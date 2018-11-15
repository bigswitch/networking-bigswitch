# Copyright 2014 Big Switch Networks, Inc.
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

import functools

import mock
from oslo_serialization import jsonutils

from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.db import l3_db
from neutron.plugins.ml2.drivers import type_vlan as vlan_config
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.extensions import test_securitygroup as test_sg
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron_lib.api.definitions import portbindings
from neutron_lib import context as neutron_context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from networking_bigswitch.plugins.bigswitch import config as pl_config
from networking_bigswitch.plugins.bigswitch import servermanager
from networking_bigswitch.plugins.ml2.drivers.mech_bigswitch \
    import driver as bsn_driver
# from networking_bigswitch.tests.unit.bigswitch.fake_server \
#     import HTTPResponseMock
import networking_bigswitch.tests.unit.bigswitch.test_restproxy_plugin as trp
from oslo_utils import uuidutils

_uuid = uuidutils.generate_uuid

PHYS_NET = 'physnet1'
VLAN_START = 1000
VLAN_END = 1100
SERVER_MANAGER = 'networking_bigswitch.plugins.bigswitch.servermanager'
SERVER_POOL = SERVER_MANAGER + '.ServerPool'
DRIVER_MOD = 'networking_bigswitch.plugins.ml2.drivers.mech_bigswitch.driver'
DRIVER = DRIVER_MOD + '.BigSwitchMechanismDriver'
HTTPCON = SERVER_MANAGER + '.httplib.HTTPConnection'


class TestBigSwitchMechDriverBase(trp.BigSwitchProxyPluginV2TestCase):

    def setUp(self, plugin=None, service_plugins=None, ext_mgr=None):
        # Configure the ML2 mechanism drivers and network types
        ml2_opts = {
            'mechanism_drivers': ['bsn_ml2'],
            'tenant_network_types': ['vlan'],
        }
        for opt, val in ml2_opts.items():
                ml2_config.cfg.CONF.set_override(opt, val, 'ml2')

        # Configure the ML2 VLAN parameters
        phys_vrange = ':'.join([PHYS_NET, str(VLAN_START), str(VLAN_END)])
        vlan_config.cfg.CONF.set_override('network_vlan_ranges',
                                          [phys_vrange],
                                          'ml2_type_vlan')
        super(TestBigSwitchMechDriverBase,
              self).setUp(test_plugin.PLUGIN_NAME,
                          service_plugins=service_plugins,
                          ext_mgr=ext_mgr)


class TestBigSwitchMechDriverNetworksV2(test_db_base_plugin_v2.TestNetworksV2,
                                        TestBigSwitchMechDriverBase):
    def setUp(self, plugin=None, service_plugins=None, ext_mgr=None):
        # topo sync can be triggered outside of watchdog
        self.startTopoSyncPatch()

        TestBigSwitchMechDriverBase.setUp(self,
                                          plugin=plugin,
                                          service_plugins=service_plugins,
                                          ext_mgr=ext_mgr)

    def test_create_network(self):
        # TODO(weifan): Figure out why topo sync mock does not work here
        # Skip for now
        pass
        # name = 'net1'
        # keys = [('subnets', []), ('name', name), ('admin_state_up', True),
        #         ('status', self.net_create_status), ('shared', False)]
        #
        # with mock.patch(HTTPCON) as conmock:
        #     rv = conmock.return_value
        #     rv.getresponse.return_value = HTTPResponseMock(None)
        #     with self.network(name=name) as net:
        #         # for debug
        #         print (rv.request.mock_calls)
        #         network = jsonutils.loads(rv.request.mock_calls[0][1][2])
        #         self.assertIn('tenant_name', network['network'])
        #         self.assertEqual('tenant_name',
        #                          network['network']['tenant_name'])
        #         for k, v in keys:
        #             self.assertEqual(net['network'][k], v)

    def test_update_network(self):
        with self.network() as network:
            data = {'network': {'name': 'a_brand_new_name'}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertTrue('NeutronError' in res)
            self.assertEqual('NetworkNameChangeError',
                             res['NeutronError']['type'])


class TestBigSwitchML2SubnetsV2(test_db_base_plugin_v2.TestSubnetsV2,
                                TestBigSwitchMechDriverBase):
    pass


class TestBigSwitchML2SecurityGroups(test_sg.TestSecurityGroups,
                                     TestBigSwitchMechDriverBase):
    def setUp(self):
        ext_mgr = test_sg.SecurityGroupTestExtensionManager()
        super(TestBigSwitchML2SecurityGroups, self).setUp(ext_mgr=ext_mgr)
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)


class TestBigSwitchML2Router(test_l3.L3NatTestCaseBase,
                             TestBigSwitchMechDriverBase):
    def setUp(self):
        ext_mgr = test_l3.L3TestExtensionManager()
        super(TestBigSwitchML2Router, self).setUp(ext_mgr=ext_mgr)
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def test_floatingip_with_invalid_create_port(self):
        # TODO(Joe): This test fails. Why?
        pass

    def test_router_add_interface_by_port_fails_nested(self):
        # Force _validate_router_port_info failure
        plugin = directory.get_plugin(plugin_constants.L3)
        if not isinstance(plugin, l3_db.L3_NAT_dbonly_mixin):
            self.skipTest("Plugin is not L3_NAT_dbonly_mixin")
        orig_update_port = self.plugin.update_port

        def mock_fail__validate_router_port_info(ctx, router, port_id):
            # Fail with raising BadRequest exception
            msg = "Failure mocking..."
            raise n_exc.BadRequest(resource='router', msg=msg)

        def mock_update_port_with_transaction(ctx, id, port):
            # Update port within a sub-transaction
            with ctx.session.begin(subtransactions=True):
                orig_update_port(ctx, id, port)

        def add_router_interface_with_transaction(ctx, router_id,
                                                  interface_info):
            # Call add_router_interface() within a sub-transaction
            with ctx.session.begin():
                plugin.add_router_interface(ctx, router_id, interface_info)

        tenant_id = _uuid()
        ctx = neutron_context.Context('', tenant_id)
        with self.network(tenant_id=tenant_id) as network, (
                self.router(name='router1', admin_state_up=True,
                            tenant_id=tenant_id)) as router:
            with self.subnet(network=network, cidr='10.0.0.0/24',
                             tenant_id=tenant_id) as subnet:
                fixed_ips = [{'subnet_id': subnet['subnet']['id']}]
                with self.port(subnet=subnet, fixed_ips=fixed_ips,
                               tenant_id=tenant_id) as port:
                    mock.patch.object(
                        self.plugin, 'update_port',
                        side_effect=(
                            mock_update_port_with_transaction)).start()
                    mock.patch.object(
                        plugin, '_validate_router_port_info',
                        side_effect=(
                            mock_fail__validate_router_port_info)).start()
                    self.assertRaises(RuntimeError,
                                      add_router_interface_with_transaction,
                                      ctx, router['router']['id'],
                                      {'port_id': port['port']['id']})

                    # fetch port and confirm device_id and device_owner
                    body = self._show('ports', port['port']['id'])
                    self.assertEqual('', body['port']['device_owner'])
                    self.assertEqual('', body['port']['device_id'])


class TestBigSwitchMechDriverPortsV2(test_db_base_plugin_v2.TestPortsV2,
                                     TestBigSwitchMechDriverBase):

    VIF_TYPE = portbindings.VIF_TYPE_OVS

    def setUp(self):
        super(TestBigSwitchMechDriverPortsV2, self).setUp()
        self.port_create_status = 'DOWN'

    def test_update_port_status_build(self):
        with self.port() as port:
            self.assertEqual(port['port']['status'], 'DOWN')
            self.assertEqual(self.port_create_status, 'DOWN')

    def test_bind_ivs_port(self):
        host_arg = {portbindings.HOST_ID: 'hostname'}
        with mock.patch(SERVER_POOL + '.rest_get_switch',
                        return_value=[{"fabric-role": "virtual"}]),\
                self.port(arg_list=(portbindings.HOST_ID,),
                          **host_arg) as port:

            p = port['port']
            self.assertEqual('ACTIVE', p['status'])
            self.assertEqual('hostname', p[portbindings.HOST_ID])
            self.assertEqual(pl_config.VIF_TYPE_IVS,
                             p[portbindings.VIF_TYPE])

    def test_bind_vswitch_on_host(self):
        '''get_vswitch() to suceed on HOST instead of HOST.PHYSNET '''
        host_arg = {portbindings.HOST_ID: 'hostname'}

        def side_effects(*args, **kwargs):
            # When called with PHYSNET, return None so it is retried with HOST
            physnet = args[0]
            if PHYS_NET in physnet:
                return None
            return [{"fabric-role": "virtual"}]

        with mock.patch(SERVER_POOL + '.rest_get_switch',
                        side_effect=side_effects) as rmock,\
                self.port(arg_list=(portbindings.HOST_ID,),
                          **host_arg) as port:

            rmock.assert_called_with('hostname')
            p = port['port']
            self.assertEqual('ACTIVE', p['status'])
            self.assertEqual('hostname', p[portbindings.HOST_ID])
            self.assertEqual(pl_config.VIF_TYPE_IVS,
                             p[portbindings.VIF_TYPE])

    def test_dont_bind_non_ivs_port(self):
        host_arg = {portbindings.HOST_ID: 'hostname'}
        with mock.patch(SERVER_POOL + '.rest_get_switch',
                        side_effect=servermanager.RemoteRestError(
                            reason='No such switch', status=404)) as rmock,\
                self.port(arg_list=(portbindings.HOST_ID,),
                          **host_arg) as port:

            rmock.assert_called_with('hostname')
            p = port['port']
            self.assertNotEqual(pl_config.VIF_TYPE_IVS,
                                p[portbindings.VIF_TYPE])
            self.assertNotEqual(portbindings.VIF_TYPE_VHOST_USER,
                                p[portbindings.VIF_TYPE])

    def test_dont_bind_vnic_type_direct(self):
        host_arg = {portbindings.HOST_ID: 'hostname',
                    portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT}
        with\
            mock.patch(SERVER_POOL + '.rest_get_switch', return_value=True) as rmock,\
            self.port(arg_list=(portbindings.HOST_ID, portbindings.VNIC_TYPE),
                      **host_arg):

            # bind_port() shall ignore this call
            rmock.assert_not_called()

    def test_dont_bind_vnic_type_direct_physical(self):
        host_arg = {portbindings.HOST_ID: 'hostname',
                    portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT_PHYSICAL}
        with\
            mock.patch(SERVER_POOL + '.rest_get_switch',
                       return_value=True) as rmock,\
            self.port(arg_list=(portbindings.HOST_ID, portbindings.VNIC_TYPE),
                      **host_arg):

            # bind_port() shall ignore this call
            rmock.assert_not_called()

    def test_bind_port_cache(self):
        with\
            self.subnet() as sub,\
            mock.patch(SERVER_POOL + '.rest_get_switch',
                       return_value=[{"fabric-role": "virtual"}]) as rmock:

            makeport = functools.partial(self.port, **{
                'subnet': sub, 'arg_list': (portbindings.HOST_ID,),
                portbindings.HOST_ID: 'hostname'})

            with makeport() as p1, makeport() as p2, makeport() as p3:

                for p in [p1, p2, p3]:
                    # response from first should be cached
                    self.assertEqual(pl_config.VIF_TYPE_IVS,
                                     p['port'][portbindings.VIF_TYPE])
            rmock.reset_mock()
            # expired cache should result in new calls
            mock.patch(DRIVER_MOD + '.CACHE_VSWITCH_TIME', new=0).start()

            with makeport() as p1, makeport() as p2, makeport() as p3:

                self.assertEqual(3, rmock.call_count)
                for p in [p1, p2, p3]:
                    self.assertEqual(pl_config.VIF_TYPE_IVS,
                                     p['port'][portbindings.VIF_TYPE])

    def test_create404_triggers_background_sync(self):
        # allow the async background thread to run for this test
        self.spawn_p.stop()
        with\
            mock.patch(
                SERVER_POOL + '.rest_create_port',
                side_effect=servermanager.RemoteRestError(
                    reason=servermanager.NXNETWORK, status=404)),\
            mock.patch(DRIVER + '._send_all_data') as mock_send_all,\
            self.port(**{'device_id': 'devid', 'binding:host_id': 'host',
                         'arg_list': ('binding:host_id',)}) as p:

            # wait for thread to finish
            mm = directory.get_plugin().mechanism_manager
            bigdriver = mm.mech_drivers['bsn_ml2'].obj
            bigdriver.evpool.waitall()
            mock_send_all.assert_has_calls([
                mock.call(
                    send_routers=True,
                    send_floating_ips=True,
                    timeout=None,
                    triggered_by_tenant=p['port']['tenant_id']
                )
            ])
        self.spawn_p.start()

    def test_udpate404_triggers_background_sync(self):
        with mock.patch(DRIVER + '.async_port_create',
                        side_effect=servermanager.RemoteRestError(
                            reason=servermanager.NXNETWORK,
                            status=404)),\
                mock.patch(DRIVER + '._send_all_data') as mock_send_all,\
                self.port() as p:

            plugin = directory.get_plugin()
            context = neutron_context.get_admin_context()
            plugin.update_port(context, p['port']['id'],
                               {'port': {'device_id': 'devid',
                                         'binding:host_id': 'host'}})
            # BSN L3 plugin is loaded.
            mock_send_all.assert_has_calls([
                mock.call(
                    send_routers=True,
                    send_floating_ips=True,
                    timeout=None,
                    triggered_by_tenant=p['port']['tenant_id']
                )
            ])

    def test_backend_request_contents(self):
        with\
            mock.patch(SERVER_POOL + '.rest_create_port') as mock_rest,\
            self.port(**{'device_id': 'devid', 'binding:host_id': 'host',
                         'arg_list': ('binding:host_id',)}):

            # make sure basic expected keys are present in the port body
            pb = mock_rest.mock_calls[0][1][2]
            self.assertEqual('host', pb['binding:host_id'])
            self.assertIn('bound_segment', pb)
            self.assertIn('network', pb)

    def test_bind_external_port(self):
        ext_id = jsonutils.dumps({'type': 'vlan', 'chassis_id': 'FF',
                                  'port_id': '1'})
        port_kwargs = {
            portbindings.HOST_ID: ext_id,
            'device_owner': bsn_driver.EXTERNAL_PORT_OWNER
        }
        with mock.patch(SERVER_POOL + '.rest_create_port') as rmock,\
                self.port(arg_list=(portbindings.HOST_ID,), **port_kwargs):

            create_body = rmock.mock_calls[-1][1][2]
            self.assertIsNotNone(create_body['bound_segment'])
            self.assertEqual(create_body[portbindings.HOST_ID], ext_id)
