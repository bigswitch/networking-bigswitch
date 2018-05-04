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

from networking_bigswitch.plugins.bigswitch.i18n import _LW

LOG = logging.getLogger(__name__)

MIN_LOCK_RETRY_SLEEP_TIME_SECS = 10
MAX_LOCK_RETRY_SLEEP_TIME_SECS = 2
TOPO_SYNC_EXPIRED_SECS = 1800


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


def log_lock_acquisition_failure(prev_ts, curr_ts):
    LOG.debug(
        "TOPO_SYNC: Failed to acquire lock. Restarting lock wait. "
        "Previous timestamp %(prev_ts)s in datetime format "
        "%(prev_dt_string)s. Attempted update: %(curr_ts)s in datetime "
        "format: %(curr_dt_string)s.",
        {'prev_ts': prev_ts, 'prev_dt_string': convert_ts_to_datetime(prev_ts),
         'curr_ts': curr_ts, 'curr_dt_string': convert_ts_to_datetime(curr_ts)
         })


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
        self.lock_marker = 'TOPO_SYNC[%s]' % self.lock_ts

    def _get_current_record(self):
        with self.session.begin(subtransactions=True):
            res = (self.session.query(ConsistencyHash).
                   filter_by(hash_id=self.hash_id).first())
            if res:
                self.session.refresh(res)  # make sure latest is loaded from db
            return res

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
        matches = re.findall(r"^TOPO_SYNC\[(\d+\.\d+)\]", record)
        if not matches:
            return None
        return matches[0]

    def _is_timestamp_expired(self, prev_ts='0'):
        """Check if prev_ts is older than TOPO_SYNC_EXPIRED_SECS

        :param prev_ts: previous timestamp value from hash record or 0
        :return: (bool, prev_ts)
                 boolean True if prev_ts is < TOPO_SYNC_EXPIRED_SECS else False
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
            return False
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
            return True

    def lock(self, check_ts=True):
        """Lock based on the below condition:

        while -
            if no hash present
              insert lock and move on

            if hash present

              - check if TOPO_SYNC is present i.e. TopoSync ongoing or expired
                 - (y) check if the Previous TopoSync has expired
                    - (y) evict it, put self ts and move on
                  - if locked by self, return

              - if no TOPO_SYNC
                - grab lock, check if TS has expired
                  - if expired, return true
                  - if not, put back old TS and return false

        :param check_ts:
        :return: boolean sync_required
                            True if all conditions met and lock acquired
                            False if locking not required
        """
        retry_sleep_time = random.randint(MIN_LOCK_RETRY_SLEEP_TIME_SECS,
                                          MAX_LOCK_RETRY_SLEEP_TIME_SECS)
        new_hash = self.lock_marker
        while True:
            res = self._get_current_record()
            if not res:
                # no hash present, try optimistically locking it
                if not self._optimistic_update_hash_record(res, new_hash):
                    # someone else beat us to it, sleep and retry
                    log_lock_acquisition_failure('0', self.lock_ts)
                    eventlet.sleep(retry_sleep_time)
                    continue
                # got the lock, execute update since nothing existed earlier
                LOG.debug("TOPO_SYNC: LockTS %(lockts)s has grabbed the "
                          "lock. Datetime format %(dt_string)s",
                          {'lockts': self.lock_ts,
                           'dt_string': convert_ts_to_datetime(self.lock_ts)})
                return True

            if 'TOPO_SYNC' in res.hash:
                # TOPO_SYNC already in progress. Check if timestamp is over
                # the limit
                prev_ts = self._get_lock_owner(res.hash)
                if self._is_timestamp_expired(prev_ts):
                    # optimistically update timestamp
                    if not self._optimistic_update_hash_record(res, new_hash):
                        # someone else update it before us, return
                        log_lock_acquisition_failure(prev_ts, self.lock_ts)
                        eventlet.sleep(retry_sleep_time)
                        continue
                    # grabbed the lock
                    LOG.debug(
                        "TOPO_SYNC: LockTS %(lock_ts)s, datetime format "
                        "%(lock_dt_string)s has forcefully grabbed the lock. "
                        "Previous timestamp %(prev_ts)s, datetime format "
                        "%(prev_dt_string)s was over %(expired_secs)s old.",
                        {'lock_ts': self.lock_ts,
                         'lock_dt_string': convert_ts_to_datetime(
                             self.lock_ts),
                         'prev_ts': prev_ts,
                         'prev_dt_string': convert_ts_to_datetime(prev_ts)})
                    return True
                else:
                    if prev_ts == self.lock_ts:
                        LOG.debug(
                            "TOPO_SYNC: LockTS %(lockts)s has grabbed the "
                            "lock. Datetime format %(dt_string)s",
                            {'lockts': self.lock_ts,
                             'dt_string': convert_ts_to_datetime(
                                 self.lock_ts)})
                        return True

                    if check_ts:
                        LOG.debug(
                            "TOPO_SYNC: LockTS %(lock_ts)s, datetime format "
                            "%(lock_dt_string)s giving up since previous lock "
                            "not expired.",
                            {'lock_ts': self.lock_ts, 'lock_dt_string':
                                convert_ts_to_datetime(self.lock_ts)})
                        return False
                    LOG.debug(
                        "TOPO_SYNC: LockTS %(lock_ts)s, datetime format "
                        "%(lock_dt_string)s waiting for in progress topo_sync "
                        "to complete.",
                        {'lock_ts': self.lock_ts, 'lock_dt_string':
                            convert_ts_to_datetime(self.lock_ts)})
                    eventlet.sleep(retry_sleep_time)
            else:
                # nobody has the lock, grab it
                # check the timestamp and return if its under limit
                if check_ts and not self._is_timestamp_expired(res.hash):
                    return False

                # nobody has lock, check_ts is false or expired, grab it!
                if not self._optimistic_update_hash_record(res, new_hash):
                    # someone else updated it before us, sleep and retry
                    log_lock_acquisition_failure(res.hash, self.lock_ts)
                    eventlet.sleep(retry_sleep_time)
                    continue

                # finally grabbed the lock
                LOG.debug("TOPO_SYNC: LockTS %(lockts)s has grabbed the "
                          "lock. Datetime format %(dt_string)s",
                          {'lockts': self.lock_ts,
                           'dt_string': convert_ts_to_datetime(self.lock_ts)})
                if check_ts and not self._is_timestamp_expired(res.hash):
                    # replace with old hash, since we already grabbed the lock
                    LOG.debug(
                        "TOPO_SYNC: Replacing the hash with previous "
                        "timestamp, since check_ts is True and prev_ts has "
                        "not expired. Previous timestamp %(prev_ts)s, "
                        "datetime format %(prev_dt_format)s. This lock "
                        "timestamp %(lock_ts)s, datetime format "
                        "%(lock_dt_string)s.",
                        {'prev_ts': res.hash,
                         'prev_dt_string': convert_ts_to_datetime(res.hash),
                         'lock_ts': self.lock_ts,
                         'lock_dt_string': convert_ts_to_datetime(
                             self.lock_ts)})
                    self.put_hash(res.hash)
                    return False
                return True

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
