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
import eventlet
import random
import re
import string
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


class HashHandler(object):
    '''
    A wrapper object to keep track of the session between the read
    and the update operations.

    This class needs an SQL engine completely independent of the main
    neutron connection so rollbacks from consistency hash operations don't
    affect the parent sessions.
    '''
    _FACADE = None

    def __init__(self, hash_id='1', prefix=None):
        if HashHandler._FACADE is None:
            HashHandler._FACADE = session.EngineFacade.from_config(
                cfg.CONF, sqlite_fk=True)

        if not prefix:
            prefix = DBLOCK_PREFIX_AUTOGEN
        length = max((DBLOCK_ID_LEN - len(prefix)), 0)

        self.hash_id = hash_id
        self.session = HashHandler._FACADE.get_session(autocommit=True,
                                                       expire_on_commit=False)
        self.random_lock_id = ''.join(random.choice(string.ascii_uppercase
                                                    + string.digits)
                                      for _ in range(length))
        self.random_lock_id = prefix + self.random_lock_id
        self.lock_marker = 'LOCKED_BY[%s]' % self.random_lock_id

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
        matches = re.findall(r"^LOCKED_BY\[(\w+)\]", record)
        if not matches:
            return None
        return matches[0]

    def _try_force_acquire_db_lock(self, res):
        """Try to acquire DB lock as current Lock has been held for too long
        @return: DB_HASH, on success
                 None, otherwise
        """
        lock_id = self.random_lock_id
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

    def read_for_update(self):
        # An optimistic locking strategy with a timeout to avoid using a
        # consistency hash while another server is using it. This will
        # not return until a lock is acquired either normally or by stealing
        # it after an individual ID holds it for greater than
        # MAX_LOCK_WAIT_TIME.
        lock_wait_start = None
        last_lock_owner = None
        lock_id = self.random_lock_id
        retry_sleep_time = random.randint(MIN_LOCK_RETRY_SLEEP_TIME,
                                          MAX_LOCK_RETRY_SLEEP_TIME) / 1000.0
        LOG.debug("This request's LockID is %s", lock_id)
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
                LOG.debug("LockID %s has grabbed the lock", lock_id)
                return ''

            current_lock_owner = self._get_lock_owner(res.hash)
            if not current_lock_owner:
                # no current lock. attempt to lock
                new = self.lock_marker + res.hash
                if not self._optimistic_update_hash_record(res, new):
                    # someone else beat us to it. restart process to wait
                    # for new lock ID to be removed
                    LOG.debug(
                        "Failed to acquire lock. Restarting lock wait. "
                        "Previous hash: %(prev)s. Attempted update: %(new)s",
                        {'prev': res.hash, 'new': new})
                    eventlet.sleep(retry_sleep_time)
                    continue
                # successfully got the lock
                LOG.debug("LockID %s has grabbed the lock", lock_id)
                return res.hash

            if current_lock_owner == lock_id:
                # no change needed, we already have the table lock due to
                # previous read_for_update call.
                # return hash with lock tag stripped off for use in a header
                LOG.debug("LockID %s has grabbed the lock", lock_id)
                return res.hash.replace(self.lock_marker, '')

            cur_time = time.time()
            if current_lock_owner != last_lock_owner:
                # The owner changed since the last iteration, but it
                # wasn't to us. Reset the counter. Log if not
                # first iteration.
                if lock_wait_start:
                    LOG.debug("LockID %(this)s - Lock owner changed from "
                              "%(old)s to %(new)s while waiting to acquire it",
                              {'this': lock_id, 'old': last_lock_owner,
                               'new': current_lock_owner})
                lock_wait_start = cur_time
                last_lock_owner = current_lock_owner

            db_lock_hash = None
            time_waited = cur_time - lock_wait_start
            if current_lock_owner.startswith(DBLOCK_PREFIX_TOPO):
                # Extended timeout for TopoSync as it could take more time
                if time_waited > MAX_LOCK_TOPOSYNC_WAIT_TIME:
                    db_lock_hash = self._try_force_acquire_db_lock(res)
            elif time_waited > MAX_LOCK_WAIT_TIME:
                db_lock_hash = self._try_force_acquire_db_lock(res)

            if db_lock_hash:
                LOG.debug("LockID %s has grabbed the lock", lock_id)
                return db_lock_hash

            eventlet.sleep(retry_sleep_time)

    def clear_lock(self):
        LOG.debug("Clearing hash record of LockID  %s", self.random_lock_id)
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
            res.hash = res.hash.replace(self.lock_marker, '')

    def put_hash(self, hash):
        hash = hash or ''
        with self.session.begin(subtransactions=True):
            res = (self.session.query(ConsistencyHash).
                   filter_by(hash_id=self.hash_id).first())
            if res:
                res.hash = hash
            else:
                conhash = ConsistencyHash(hash_id=self.hash_id, hash=hash)
                self.session.merge(conhash)
        LOG.debug("Consistency hash for group %(hash_id)s updated "
                  "to %(hash)s by LockID %(this)s",
                  {'hash_id': self.hash_id, 'hash': hash,
                   'this': self.random_lock_id})

    def put_hash_if_owner(self, new_hash):
        """Update the DB Hash if the current thread is the DB lock owner
        @:return: True, if DB hash was successfully updated
                  False, otherwise
        """
        new_hash = new_hash or ''
        lock_marker = self.lock_marker + '%'
        query = sa.update(ConsistencyHash.__table__).values(hash=new_hash)
        query = query.where(ConsistencyHash.hash_id == self.hash_id)
        query = query.where(ConsistencyHash.hash.like(lock_marker))

        success = True
        try:
            with self._FACADE.get_engine().begin() as conn:
                result = conn.execute(query)
        except db_exc.DBDeadlock:
            success = False

        # We need to check update row count for successful update
        if success and (result.rowcount != 0):
            # DB Hash update was successful
            LOG.debug("Consistency hash for group %(hash_id)s updated "
                      "to %(hash)s by LockID %(this)s",
                      {'hash_id': self.hash_id, 'hash': new_hash,
                       'this': self.random_lock_id})
            return True

        LOG.debug("LockID %s is no longer DB lock owner. Consistency "
                  "hash not updated", self.random_lock_id)
        return False

    def is_db_lock_owner(self):
        """Check if the current thread is the DB lock owner
        @:return True, if thread is the DB lock owner
                 False, otherwise
        """
        res = self._get_current_record()
        if not res:
            return False

        lock_owner = self._get_lock_owner(res.hash)
        if not lock_owner:
            return False

        if lock_owner == self.random_lock_id:
            return True
        return False

    def is_db_hash_empty(self):
        """Check if DB hash record exists
        :return: True, if there is no hash entry
                 False, otherwise
        """
        if not self._get_current_record():
            return True
        return False
