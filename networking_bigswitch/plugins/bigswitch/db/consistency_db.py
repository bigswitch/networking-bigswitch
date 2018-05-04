# Copyright 2014, Big Switch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import datetime
import eventlet
import random
import re
import time

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_db.sqlalchemy import session
from oslo_log import log as logging
import sqlalchemy as sa

from neutron.db import model_base

from networking_bigswitch.plugins.bigswitch.i18n import _LI
from networking_bigswitch.plugins.bigswitch.i18n import _LW

LOG = logging.getLogger(__name__)
# Maximum time in seconds to wait for a single record lock to be released
# NOTE: The total time waiting may exceed this if there are multiple servers
# waiting for the same lock
MAX_LOCK_WAIT_TIME = 15  # seconds
MAX_LOCK_TOPOSYNC_WAIT_TIME = 300  # seconds
MIN_LOCK_RETRY_SLEEP_TIME = 100  # milliseconds
MAX_LOCK_RETRY_SLEEP_TIME = 250  # milliseconds
TOPO_SYNC_EXPIRED_SECS = 1800
DBLOCK_ID_LEN = 12
DBLOCK_PREFIX_TOPO = "TOPO"
DBLOCK_PREFIX_AUTOGEN = "A"


class ConsistencyHash(model_base.BASEV2):
    '''
    A simple table to store the latest consistency hash
    received from a server.
    For now we only support one global state so the
    hash_id will always be '1'
    '''
    __tablename__ = 'consistencyhashes'
    hash_id = sa.Column(sa.String(255),
                        primary_key=True)
    hash = sa.Column(sa.String(255), nullable=False)


def setup_db():
    '''Helper to register models for unit tests'''
    if HashHandler._FACADE is None:
        HashHandler._FACADE = session.EngineFacade.from_config(
            cfg.CONF, sqlite_fk=True)
    ConsistencyHash.metadata.create_all(
        HashHandler._FACADE.get_engine())


def clear_db():
    '''Helper to unregister models and clear engine in unit tests'''
    if not HashHandler._FACADE:
        return
    ConsistencyHash.metadata.drop_all(HashHandler._FACADE.get_engine())
    HashHandler._FACADE = None


def convert_ts_to_datetime(timestamp_ms):
    dt_string = datetime.datetime.fromtimestamp(float(timestamp_ms)).strftime(
        '%Y-%m-%d %H:%M:%S.%f')
    return dt_string


class HashHandler(object):
    '''
    A wrapper object to keep track of the session between the read
    and the update operations.

    This class needs an SQL engine completely independent of the main
    neutron connection so rollbacks from consistency hash operations don't
    affect the parent sessions.
    '''
    _FACADE = None

    def __init__(self, hash_id='1', timestamp_ms=None):
        if HashHandler._FACADE is None:
            HashHandler._FACADE = session.EngineFacade.from_config(
                cfg.CONF, sqlite_fk=True)

        self.hash_id = hash_id
        self.session = HashHandler._FACADE.get_session(autocommit=True,
                                                       expire_on_commit=False)
        self.lock_ts = str(timestamp_ms) if timestamp_ms else str(time.time())
        self.lock_marker = 'LOCKED_BY[%s]' % self.lock_ts

    def _get_current_record(self):
        with self.session.begin(subtransactions=True):
            res = (self.session.query(ConsistencyHash).
                   filter_by(hash_id=self.hash_id).first())
            if res:
                self.session.refresh(res)  # make sure latest is loaded from db
            return res

    def _insert_empty_hash_with_lock(self):
        # try to insert a new hash, return False on conflict
        try:
            with self.session.begin(subtransactions=True):
                res = ConsistencyHash(hash_id=self.hash_id,
                                      hash=self.lock_marker)
                self.session.add(res)
                return True
        except db_exc.DBDuplicateEntry:
            # another server created a new record at the same time
            return False

    def _optimistic_update_hash_record(self, old_record, new_hash):
        # Optimistic update strategy. Returns True if successful, else False.
        query = sa.update(ConsistencyHash.__table__).values(hash=new_hash)
        query = query.where(ConsistencyHash.hash_id == old_record.hash_id)
        query = query.where(ConsistencyHash.hash == old_record.hash)
        try:
            with self._FACADE.get_engine().begin() as conn:
                result = conn.execute(query)
        except db_exc.DBDeadlock:
            # mysql can encounter internal deadlocks servicing a query with
            # multiple where criteria. treat it the same as not being able
            # to update the record so it will be tried again
            return False
        # We need to check update row count in case another server is
        # doing this at the same time. Only one will succeed, the other will
        # not update any rows.
        return result.rowcount != 0

    def _get_lock_owner(self, record):
        matches = re.findall(r"^LOCKED_BY\[(\d+\.\d+)\]", record)
        if not matches:
            return None
        return matches[0]

    def _try_force_acquire_db_lock(self, res):
        """Try to acquire DB lock as current Lock has been held for too long
        @return: DB_HASH, on success
                 None, otherwise
        """
        lock_id = self.lock_ts
        current_lock_owner = self._get_lock_owner(res.hash)
        LOG.warning(_LW("Gave up waiting for consistency DB lock, trying to "
                        "take it. Current hash is: %s"), res.hash)
        new_db_value = res.hash.replace(current_lock_owner, lock_id)
        if self._optimistic_update_hash_record(res, new_db_value):
            return res.hash.replace(new_db_value, '')

        LOG.info(_LI("LockID %(this)s - Failed to take lock as another thread "
                     "has grabbed it"),
                 {'this': lock_id})
        return None

    def _is_topo_sync_required(self, check_ts=True):
        """Check consistencyhashes table if topo_sync is already in progress.

        If topo_sync is in progress and timestamp of topo_sync is less than
        TOPO_SYNC_EXPIRED_SECS, topo_sync is ACTIVE

        Else topo_sync is INACTIVE

        :return: (bool, timestamp_ms)
                 boolean specifying if topo_sync is ACTIVE or not
                 timestamp in milliseconds if available in database, else 0
        """
        res = self._get_current_record()
        if res:
            # record found, check other details
            prev_ts = (self._get_lock_owner(res.hash)
                       if 'LOCKED_BY' in res.hash
                       else res.hash)

            timestamp_expired, prev_ts = self._is_timestamp_expired(prev_ts)

            if timestamp_expired:
                LOG.debug("TOPO_SYNC: _is_topo_sync_required: True. "
                          "timestamp_expired.")
                return True, prev_ts
            elif not check_ts:
                # even if check_ts is False, we retrieve the prev_ts and return
                LOG.debug("TOPO_SYNC: _is_topo_sync_required: True. "
                          "check_ts is False.")
                return True, prev_ts
            else:
                LOG.debug("TOPO_SYNC: _is_topo_sync_required: False. "
                          "timestamp_expired is False, check_ts is True.")
                return False, prev_ts
        else:
            # no record found, sync required
            LOG.debug("TOPO_SYNC: _is_topo_sync_required: True. "
                      "no record found.")
            return True, '0'

    def _is_timestamp_expired(self, prev_ts='0'):
        """Check if prev_ts is older than TOPO_SYNC_EXPIRED_SECS

        :param prev_ts: previous timestamp value from hash record or 0
        :return: (bool, prev_ts)
                 boolean True if prev_ts is < TOPO_SYNC_EXPIRED_SECS else False
                 prev_ts value as normalized and used in the function
        """
        curr_ts_float = float(self.lock_ts)
        try:
            prev_ts_float = float(prev_ts)
        except Exception:
            # prev_ts value was garbage, set it to 0
            prev_ts = '0'
            prev_ts_float = float(0)

        time_diff = curr_ts_float - prev_ts_float
        if time_diff < TOPO_SYNC_EXPIRED_SECS:
            # diff is under the limit, NOT EXPIRED
            LOG.debug("TOPO_SYNC: _is_timestamp_expired: NOT EXPIRED. Current "
                      "timestamp is %(curr)s, previous timestamp is %(prev)s, "
                      "diff between the two is %(diff)s. "
                      "Diff < %(expired_secs)s secs.",
                      {'curr': convert_ts_to_datetime(curr_ts_float),
                       'prev': convert_ts_to_datetime(prev_ts_float),
                       'diff': time_diff,
                       'expired_secs': TOPO_SYNC_EXPIRED_SECS})
            return False, prev_ts
        else:
            # diff is over the time range, EXPIRED
            LOG.debug("TOPO_SYNC: _is_timestamp_expired: EXPIRED. Current "
                      "timestamp is %(curr)s, previous timestamp is %(prev)s, "
                      "diff between the two is %(diff)s. "
                      "Diff > %(expired_secs)s secs.",
                      {'curr': convert_ts_to_datetime(curr_ts_float),
                       'prev': convert_ts_to_datetime(prev_ts_float),
                       'diff': time_diff,
                       'expired_secs': TOPO_SYNC_EXPIRED_SECS})
            return True, prev_ts

    def lock(self, check_ts=True):
        """

        :param check_ts:
        :return: boolean sync_required
                            True if all conditions met and lock acquired
                            False if locking not required
        """
        # An optimistic locking strategy with a timeout to avoid using a
        # consistency hash while another server is using it. This will
        # not return until a lock is acquired either normally or by stealing
        # it after an individual ID holds it for greater than
        # MAX_LOCK_WAIT_TIME.
        lock_wait_start = None
        last_lock_owner = None
        lock_ts = self.lock_ts
        retry_sleep_time = random.randint(MIN_LOCK_RETRY_SLEEP_TIME,
                                          MAX_LOCK_RETRY_SLEEP_TIME) / 1000.0

        # pre-check: is_topo_sync_active? if yes, don't contend for the lock
        topo_sync_required, prev_ts = self._is_topo_sync_required(check_ts)

        if not topo_sync_required:
            return False

        LOG.debug("TOPO_SYNC: current lock_ts timestamp is %s",
                  convert_ts_to_datetime(lock_ts))
        LOG.debug("TOPO_SYNC: previously executed at %s",
                  convert_ts_to_datetime(prev_ts))
        # if check_ts=True, execute only if diff > 1 hour
        time_diff = float(lock_ts) - float(prev_ts)
        if check_ts is True and time_diff < TOPO_SYNC_EXPIRED_SECS:
            LOG.info(_LI("TOPO_SYNC: Last topo_sync executed at %(prev_ts)s, "
                         "which is less than %(expired_sec)s seconds ago. "
                         "Skipping current topo_sync."),
                     {'prev_ts': convert_ts_to_datetime(prev_ts),
                      'expired_sec': str(TOPO_SYNC_EXPIRED_SECS)})
            return False

        LOG.debug("This request's LockTS is %s",
                  convert_ts_to_datetime(lock_ts))
        while True:
            res = self._get_current_record()
            if not res:
                # no current entry. try to insert to grab lock
                if not self._insert_empty_hash_with_lock():
                    # A failed insert after missing current record means
                    # a concurrent insert occured. Start process over to
                    # find the new record.
                    LOG.debug("Concurrent record inserted. Retrying.")
                    eventlet.sleep(retry_sleep_time)
                    continue
                # The empty hash was successfully inserted with our lock
                LOG.debug("LockTS %s has grabbed the lock",
                          convert_ts_to_datetime(lock_ts))
                return True

            current_lock_owner = self._get_lock_owner(res.hash)
            if not current_lock_owner:
                # no current lock. attempt to lock
                new = self.lock_marker
                if not self._optimistic_update_hash_record(res, new):
                    # someone else beat us to it. restart process to wait
                    # for new lock ID to be removed
                    LOG.debug(
                        "Failed to acquire lock. Restarting lock wait. "
                        "Previous lock_ts: %(prev)s. Attempted update: "
                        "%(new)s",
                        {'prev': convert_ts_to_datetime(res.hash), 'new': new})
                    eventlet.sleep(retry_sleep_time)
                    continue
                # successfully got the lock
                LOG.debug("LockTS %s has grabbed the lock",
                          convert_ts_to_datetime(lock_ts))
                # now check timestamp if requested
                timestamp_expired, prev_ts = self._is_timestamp_expired(
                    res.hash)
                if timestamp_expired or check_ts is False:
                    LOG.debug("TOPO_SYNC: grabbed the lock and timestamp "
                              "expired (or forced sync via check_ts False), "
                              "sync required.")
                    return True
                elif check_ts is True and not timestamp_expired:
                    # put the old timestamp back in the DB
                    LOG.debug("TOPO_SYNC: check_ts is True and timestamp has "
                              "not expired. Reverting the timstamp in DB and "
                              "returning.")
                    self.put_hash(res.hash)
                    return False

            if current_lock_owner == lock_ts:
                # no change needed, we already have the table lock due to
                # previous lock call.
                # return hash with lock tag stripped off for use in a header
                LOG.debug("LockTS %s has grabbed the lock",
                          convert_ts_to_datetime(lock_ts))
                LOG.debug("TOPO_SYNC: prev_ts unavailable, sync required.")
                return True

            cur_time = time.time()
            if current_lock_owner != last_lock_owner:
                # The owner changed since the last iteration, but it
                # wasn't to us. Reset the counter. Log if not
                # first iteration.
                if lock_wait_start:
                    LOG.debug("LockTS %(this)s - Lock owner changed from "
                              "%(old)s to %(new)s while waiting to acquire it",
                              {'this': convert_ts_to_datetime(lock_ts),
                               'old': last_lock_owner,
                               'new': current_lock_owner})
                    timestamp_expired, prev_ts = self._is_timestamp_expired(
                        prev_ts=current_lock_owner)
                    if check_ts is True and not timestamp_expired:
                        LOG.debug("TOPO_SYNC: check_ts is True and another "
                                  "thread with recent timestamp gained lock. "
                                  "Giving up attempt to topo_sync.")
                        return False
                lock_wait_start = cur_time
                last_lock_owner = current_lock_owner

            db_lock_hash = None
            time_waited = cur_time - lock_wait_start
            if time_waited > MAX_LOCK_WAIT_TIME:
                db_lock_hash = self._try_force_acquire_db_lock(res)

            if db_lock_hash:
                LOG.debug("LockTS %s has grabbed the lock",
                          convert_ts_to_datetime(lock_ts))
                LOG.debug("TOPO_SYNC: force grabbed the lock after waiting "
                          "for MAX_LOCK_WAIT_TIME.")
                return True

            eventlet.sleep(retry_sleep_time)

    def put_hash(self, hash):
        with self.session.begin(subtransactions=True):
            res = (self.session.query(ConsistencyHash).
                   filter_by(hash_id=self.hash_id).first())
            if res:
                res.hash = hash
            else:
                conhash = ConsistencyHash(hash_id=self.hash_id, hash=hash)
                self.session.merge(conhash)
        LOG.debug("Consistency hash for group %(hash_id)s updated "
                  "to %(hash_ts)s by LockID %(this)s",
                  {'hash_id': self.hash_id, 'hash': hash,
                   'this': self.lock_ts})

    def unlock(self):
        LOG.debug("Unlocking and setting timestamp_ms to LockTS  %s",
                  self.lock_ts)
        with self.session.begin(subtransactions=True):
            res = (self.session.query(ConsistencyHash).
                   filter_by(hash_id=self.hash_id).first())
            if not res:
                LOG.warning(_LW("Hash record already gone, no lock to clear."))
                return
            else:
                self.session.refresh(res)  # get the latest res from db
            if not res.hash.startswith(self.lock_marker):
                # if these are frequent the server is too slow
                LOG.warning(_LW("Another server already removed the lock. %s"),
                            res.hash)
                return
            res.hash = res.hash.replace(self.lock_marker, self.lock_ts)
