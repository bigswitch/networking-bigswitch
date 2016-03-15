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
from oslo_config import cfg

import neutron.common.test_lib as test_lib

from bsnstacklib.plugins.bigswitch import config
from bsnstacklib.plugins.bigswitch.db import consistency_db
from bsnstacklib.plugins.bigswitch.db import routerrule_db
from bsnstacklib.tests.unit.bigswitch import fake_server


RESTPROXY_PKG_PATH = 'bsnstacklib.plugins.bigswitch.plugin'
L3_RESTPROXY_PKG_PATH = 'bsnstacklib.plugins.bigswitch.l3_router_plugin'
NOTIFIER = 'bsnstacklib.plugins.bigswitch.plugin.AgentNotifierApi'
DHCP_NOTIFIER = ('neutron.api.rpc.agentnotifiers.dhcp_rpc_agent_api.'
                 'DhcpAgentNotifyAPI.notify')
CERTFETCH = 'bsnstacklib.plugins.bigswitch.servermanager.ServerPool._fetch_cert'  # noqa
SERVER_MANAGER = 'bsnstacklib.plugins.bigswitch.servermanager'
HTTPCON = 'bsnstacklib.plugins.bigswitch.servermanager.httplib.HTTPConnection'
SPAWN = 'bsnstacklib.plugins.bigswitch.plugin.eventlet.GreenPool.spawn_n'
KSCLIENT = 'keystoneclient.v2_0.client.Client'
BACKGROUND = SERVER_MANAGER + '.ServerPool.start_background_tasks'
MAP_TENANT_NAME = ('bsnstacklib.plugins.bigswitch.plugin.'
                   'NeutronRestProxyV2Base._map_tenant_name')


class BigSwitchTestBase(object):

    _plugin_name = ('%s.NeutronRestProxyV2' % RESTPROXY_PKG_PATH)
    _l3_plugin_name = ('%s.L3RestProxy' % L3_RESTPROXY_PKG_PATH)

    def setup_config_files(self):
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                'restproxy.ini.test')]
        self.addCleanup(cfg.CONF.reset)
        self.addCleanup(consistency_db.clear_db)
        self.addCleanup(routerrule_db.clear_db)
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

    def map_tenant_name_side_effect(self, value):
        value['tenant_name'] = 'tenant_name'
        return value

    def setup_patches(self):
        self.plugin_notifier_p = mock.patch(NOTIFIER)
        self.dhcp_notifier_p = mock.patch(DHCP_NOTIFIER)
        # prevent any greenthreads from spawning
        self.spawn_p = mock.patch(SPAWN, new=lambda *args, **kwargs: None)
        # prevent the consistency watchdog and keystone sync from starting
        self.watch_p = mock.patch(BACKGROUND, new=lambda *args, **kwargs: None)
        # disable exception log to prevent json parse error from showing
        self.log_exc_p = mock.patch(SERVER_MANAGER + ".LOG.exception",
                                    new=lambda *args, **kwargs: None)
        self.ksclient_p = mock.patch(KSCLIENT)
        self.map_tenant_name_p = mock.patch(
            MAP_TENANT_NAME, side_effect=self.map_tenant_name_side_effect)
        self.log_exc_p.start()
        self.plugin_notifier_p.start()
        self.spawn_p.start()
        self.watch_p.start()
        self.dhcp_notifier_p.start()
        self.ksclient_p.start()
        self.map_tenant_name_p.start()

    def startHttpPatch(self):
        self.httpPatch = mock.patch(HTTPCON,
                                    new=fake_server.HTTPConnectionMock)
        self.httpPatch.start()

    def setup_db(self):
        # setup the db engine and models for the consistency db
        consistency_db.setup_db()
        routerrule_db.setup_db()
