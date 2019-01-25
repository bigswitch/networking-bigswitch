# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

import mock
import neutron.common.test_lib as test_lib
from oslo_config import cfg

from networking_bigswitch.plugins.bigswitch import config
from networking_bigswitch.plugins.bigswitch.db import consistency_db
from networking_bigswitch.plugins.bigswitch.db import network_template_db  # noqa
from networking_bigswitch.plugins.bigswitch.db import reachability_test_db  # noqa
from networking_bigswitch.plugins.bigswitch.db import tenant_policy_db  # noqa
from networking_bigswitch.plugins.bigswitch.servermanager\
    import TOPO_RESPONSE_OK
from networking_bigswitch.tests.unit.bigswitch import fake_server

from networking_bigswitch.tests.unit.bigswitch.mock_paths import BACKGROUND
from networking_bigswitch.tests.unit.bigswitch.mock_paths import \
    BSN_SERVICE_PLUGIN_PATH
from networking_bigswitch.tests.unit.bigswitch.mock_paths import HTTPCON
from networking_bigswitch.tests.unit.bigswitch.mock_paths import \
    IS_UNICODE_ENABLED
from networking_bigswitch.tests.unit.bigswitch.mock_paths import \
    KEYSTONE_CLIENT
from networking_bigswitch.tests.unit.bigswitch.mock_paths import L3_PLUGIN_PATH
from networking_bigswitch.tests.unit.bigswitch.mock_paths import \
    LIB_RPC_TRANSPORT
from networking_bigswitch.tests.unit.bigswitch.mock_paths import \
    MAP_DISPLAY_NAME_OR_TENANT
from networking_bigswitch.tests.unit.bigswitch.mock_paths import PLUGIN_PATH
from networking_bigswitch.tests.unit.bigswitch.mock_paths import \
    POOL_TOPO_SYNC
from networking_bigswitch.tests.unit.bigswitch.mock_paths import \
    RPC_SERVER_START
from networking_bigswitch.tests.unit.bigswitch.mock_paths import SERVER_MANAGER
from networking_bigswitch.tests.unit.bigswitch.mock_paths import SPAWN


class BigSwitchTestBase(object):

    _plugin_name = ('%s.NeutronRestProxyV2' % PLUGIN_PATH)
    _l3_plugin_name = ('%s.L3RestProxy' % L3_PLUGIN_PATH)
    _bsn_service_plugin_name = ('%s.BSNServicePlugin'
                                % BSN_SERVICE_PLUGIN_PATH)

    def setup_config_files(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                'restproxy.ini.test')]
        self.addCleanup(cfg.CONF.reset)
        self.addCleanup(consistency_db.clear_db)
        config.register_config()
        # Only try SSL on SSL tests
        cfg.CONF.set_override('server_ssl', False, 'RESTPROXY')
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        cfg.CONF.set_override('ssl_cert_directory',
                              os.path.join(etc_path, 'ssl'), 'RESTPROXY')
        # The mock interferes with HTTP(S) connection caching
        cfg.CONF.set_override('cache_connections', False, 'RESTPROXY')
        cfg.CONF.set_override('service_plugins', ['bigswitch_l3'])
        cfg.CONF.set_override('add_meta_server_route', False, 'RESTPROXY')
        cfg.CONF.set_override('api_extensions_path', False)

    def map_tenant_name_side_effect(self, value):
        # for old tests, always map tenant name
        value['tenant_name'] = 'tenant_name'
        return value

    def is_unicode_enabled_side_effect(self):
        # for old tests, always return False
        return False

    def setup_patches(self):
        self.lib_rpc_transport_p = mock.patch(LIB_RPC_TRANSPORT)
        self.rpc_server_start_p = mock.patch(RPC_SERVER_START)
        # prevent any greenthreads from spawning
        self.spawn_p = mock.patch(SPAWN, new=lambda *args, **kwargs: None)
        # prevent the consistency watchdog and keystone sync from starting
        self.watch_p = mock.patch(BACKGROUND, new=lambda *args, **kwargs: None)
        # disable exception log to prevent json parse error from showing
        self.log_exc_p = mock.patch(SERVER_MANAGER + ".LOG.exception",
                                    new=lambda *args, **kwargs: None)

        self.ksclient_p = mock.patch(KEYSTONE_CLIENT)

        self.map_display_name_or_tenant_p = mock.patch(
            MAP_DISPLAY_NAME_OR_TENANT,
            side_effect=self.map_tenant_name_side_effect)
        self.is_unicode_enabled_p = mock.patch(
            IS_UNICODE_ENABLED,
            side_effect=self.is_unicode_enabled_side_effect)

        # start all mock patches
        self.log_exc_p.start()
        self.lib_rpc_transport_p.start()
        self.rpc_server_start_p.start()
        self.spawn_p.start()
        self.watch_p.start()
        self.ksclient_p.start()
        self.map_display_name_or_tenant_p.start()
        self.is_unicode_enabled_p.start()

    def startHttpPatch(self):
        self.httpPatch = mock.patch(HTTPCON,
                                    new=fake_server.HTTPConnectionMock)
        self.httpPatch.start()

    def startTopoSyncPatch(self):
        self.topo_sync_p = \
            mock.patch(POOL_TOPO_SYNC, return_value=(True, TOPO_RESPONSE_OK))
        self.topo_sync_p.start()

    def setup_db(self):
        # setup the db engine and models for the consistency db
        consistency_db.setup_db()
