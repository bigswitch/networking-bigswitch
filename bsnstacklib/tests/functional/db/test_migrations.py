# Copyright 2011 OpenStack Foundation.
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
from oslo_config import cfg

from bsnstacklib.plugins.bigswitch.db.migration import alembic_migrations
from bsnstacklib.plugins.bigswitch.db.models import head

from neutron.db.migration.alembic_migrations import external
from neutron.db.migration import cli as migration
from neutron.tests.common import base
from neutron.tests.functional.db import test_migrations


# EXTERNAL_TABLES should contain all names of tables that are not related to
# current repo.
# in our case, its all tables
EXTERNAL_TABLES = set(external.TABLES)


class _TestModelsMigrationsBsn(test_migrations._TestModelsMigrations):

    def db_sync(self, engine):
        cfg.CONF.set_override('connection', engine.url, group='database')
        for conf in migration.get_alembic_configs():
            self.alembic_config = conf
            self.alembic_config.neutron_config = cfg.CONF
            migration.do_alembic_command(conf, 'upgrade', 'heads')

    def get_metadata(self):
        return head.get_metadata()

    def include_object(self, object_, name, type_, reflected, compare_to):
        if type_ == 'table' and \
                (name == 'alembic' or
                 name == alembic_migrations.BSN_VERSION_TABLE or
                 name in EXTERNAL_TABLES):
            return False
        else:
            return True


class TestModelsMigrationsMysql(_TestModelsMigrationsBsn,
                                base.MySQLTestCase):

    pass


class TestModelsMigrationsPsql(_TestModelsMigrationsBsn,
                               base.PostgreSQLTestCase):
    pass
