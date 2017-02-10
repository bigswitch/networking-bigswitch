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

import contextlib
import functools

import mock
from oslo_serialization import jsonutils

from neutron import context as neutron_context
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import config as ml2_config
from neutron.plugins.ml2.drivers import type_vlan as vlan_config
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.plugins.ml2 import test_plugin

from networking_bigswitch.plugins.bigswitch import config as pl_config
from networking_bigswitch.plugins.bigswitch import servermanager
from networking_bigswitch.plugins.ml2.drivers.mech_bigswitch \
    import driver as bsn_driver
import networking_bigswitch.tests.unit.bigswitch.test_restproxy_plugin as trp

PHYS_NET = 'physnet1'
VLAN_START = 1000
VLAN_END = 1100
SERVER_MANAGER = 'networking_bigswitch.plugins.bigswitch.servermanager'
SERVER_POOL = SERVER_MANAGER + '.ServerPool'
DRIVER_MOD = 'networking_bigswitch.plugins.ml2.drivers.mech_bigswitch.driver'
DRIVER = DRIVER_MOD + '.BigSwitchMechanismDriver'
HTTPCON = SERVER_MANAGER + '.httplib.HTTPConnection'


class TestBigSwitchMechDriverBase(trp.BigSwitchProxyPluginV2TestCase):

    def setUp(self):
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
              self).setUp(test_plugin.PLUGIN_NAME)


class TestBigSwitchMechDriverNetworksV2(test_db_base_plugin_v2.TestNetworksV2,
                                        TestBigSwitchMechDriverBase):
    def test_create_network(self):
        name = 'net1'
        keys = [('subnets', []), ('name', name), ('admin_state_up', True),
                ('status', self.net_create_status), ('shared', False)]

        with mock.patch(HTTPCON) as conmock:
            with self.network(name=name) as net:
                rv = conmock.return_value
                rv.getresponse.return_value.status = 200
                network = jsonutils.loads(rv.request.mock_calls[0][1][2])
                self.assertIn('tenant_name', network['network'])
                self.assertEqual('tenant_name',
                                 network['network']['tenant_name'])
                for k, v in keys:
                    self.assertEqual(net['network'][k], v)

    def test_update_network(self):
        with self.network() as network:
            data = {'network': {'name': 'a_brand_new_name'}}
            req = self.new_update_request('networks',
                                          data,
                                          network['network']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertTrue('NeutronError' in res)
            self.assertEqual('MechanismDriverError',
                             res['NeutronError']['type'])


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
        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_get_switch',
                       return_value=[{"fabric-role": "virtual"}]),
            self.port(arg_list=(portbindings.HOST_ID,), **host_arg)
        ) as (rmock, port):
            rmock.assert_called_once_with('hostname.' + PHYS_NET)
            p = port['port']
            self.assertEqual('ACTIVE', p['status'])
            self.assertEqual('hostname', p[portbindings.HOST_ID])
            self.assertEqual(pl_config.VIF_TYPE_IVS,
                             p[portbindings.VIF_TYPE])

    def test_bind_nfvswitch_port(self):
        host_arg = {portbindings.HOST_ID: 'hostname'}
        vhost_sock = "vhost0"
        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_get_switch',
                       return_value=[{"fabric-role": "nfvswitch"}]),
            mock.patch(SERVER_POOL + '.rest_create_port', return_value=None),
            mock.patch(SERVER_POOL + '.rest_get_port',
                       return_value=[{'attachment-point':
                                      {'interface': vhost_sock}}]),
            self.port(arg_list=(portbindings.HOST_ID,), **host_arg)
        ) as (rmock1, _, _, port):
            rmock1.assert_called_with('hostname.' + PHYS_NET)
            p = port['port']
            self.assertEqual('ACTIVE', p['status'])
            self.assertEqual('hostname', p[portbindings.HOST_ID])
            self.assertEqual(portbindings.VIF_TYPE_VHOST_USER,
                             p[portbindings.VIF_TYPE])

            vif_details = p['binding:vif_details']
            self.assertEqual(vif_details[portbindings.VHOST_USER_SOCKET],
                             "/run/vhost/" + vhost_sock)
            self.assertEqual(vif_details[portbindings.VHOST_USER_MODE],
                             portbindings.VHOST_USER_MODE_SERVER)
            self.assertEqual(vif_details[portbindings.CAP_PORT_FILTER], False)
            self.assertEqual(vif_details[portbindings.VHOST_USER_OVS_PLUG],
                             False)

    def test_bind_nfvswitch_port_nosock_fail(self):
        host_arg = {portbindings.HOST_ID: 'hostname'}
        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_get_switch',
                       return_value=[{"fabric-role": "nfvswitch"}]),
            mock.patch(SERVER_POOL + '.rest_create_port', return_value=None),
            mock.patch(SERVER_POOL + '.rest_get_port', return_value=None),
            self.port(arg_list=(portbindings.HOST_ID,), **host_arg)
        ) as (rmock1, _, _, port):
            rmock1.assert_called_with('hostname.' + PHYS_NET)
            p = port['port']
            self.assertEqual('hostname', p[portbindings.HOST_ID])
            self.assertEqual(portbindings.VIF_TYPE_BINDING_FAILED,
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

        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_get_switch',
                       side_effect=side_effects),
            self.port(arg_list=(portbindings.HOST_ID,), **host_arg)
        ) as (rmock, port):
            rmock.assert_called_with('hostname')
            p = port['port']
            self.assertEqual('ACTIVE', p['status'])
            self.assertEqual('hostname', p[portbindings.HOST_ID])
            self.assertEqual(pl_config.VIF_TYPE_IVS,
                             p[portbindings.VIF_TYPE])

    def test_dont_bind_non_ivs_port(self):
        host_arg = {portbindings.HOST_ID: 'hostname'}
        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_get_switch',
                       side_effect=servermanager.RemoteRestError(
                           reason='No such switch', status=404)),
            self.port(arg_list=(portbindings.HOST_ID,), **host_arg)
        ) as (rmock, port):
            rmock.assert_called_with('hostname')
            p = port['port']
            self.assertNotEqual(pl_config.VIF_TYPE_IVS,
                                p[portbindings.VIF_TYPE])
            self.assertNotEqual(portbindings.VIF_TYPE_VHOST_USER,
                                p[portbindings.VIF_TYPE])

    def test_dont_bind_vnic_type_direct(self):
        host_arg = {portbindings.HOST_ID: 'hostname',
                    portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT}
        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_get_switch', return_value=True),
            self.port(arg_list=(portbindings.HOST_ID, portbindings.VNIC_TYPE),
                      **host_arg)
        ) as (rmock, _):
            # bind_port() shall ignore this call
            rmock.assert_not_called()

    def test_dont_bind_vnic_type_direct_physical(self):
        host_arg = {portbindings.HOST_ID: 'hostname',
                    portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT_PHYSICAL}
        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_get_switch', return_value=True),
            self.port(arg_list=(portbindings.HOST_ID, portbindings.VNIC_TYPE),
                      **host_arg)
        ) as (rmock, _):
            # bind_port() shall ignore this call
            rmock.assert_not_called()

    def test_bind_port_cache(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch(SERVER_POOL + '.rest_get_switch',
                       return_value=[{"fabric-role": "virtual"}])
        ) as (sub, rmock):
            makeport = functools.partial(self.port, **{
                'subnet': sub, 'arg_list': (portbindings.HOST_ID,),
                portbindings.HOST_ID: 'hostname'})

            with contextlib.nested(makeport(), makeport(),
                                   makeport()) as ports:
                # response from first should be cached
                rmock.assert_called_once_with('hostname.' + PHYS_NET)
                for port in ports:
                    self.assertEqual(pl_config.VIF_TYPE_IVS,
                                     port['port'][portbindings.VIF_TYPE])
            rmock.reset_mock()
            # expired cache should result in new calls
            mock.patch(DRIVER_MOD + '.CACHE_VSWITCH_TIME', new=0).start()
            with contextlib.nested(makeport(), makeport(),
                                   makeport()) as ports:
                self.assertEqual(3, rmock.call_count)
                for port in ports:
                    self.assertEqual(pl_config.VIF_TYPE_IVS,
                                     port['port'][portbindings.VIF_TYPE])

    def test_create404_triggers_background_sync(self):
        # allow the async background thread to run for this test
        self.spawn_p.stop()
        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_create_port',
                       side_effect=servermanager.RemoteRestError(
                           reason=servermanager.NXNETWORK, status=404)),
            mock.patch(DRIVER + '._send_all_data'),
            self.port(**{'device_id': 'devid', 'binding:host_id': 'host',
                         'arg_list': ('binding:host_id',)})
        ) as (mock_http, mock_send_all, p):
            # wait for thread to finish
            mm = manager.NeutronManager.get_plugin().mechanism_manager
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
        with contextlib.nested(
            mock.patch(DRIVER + '.async_port_create',
                       side_effect=servermanager.RemoteRestError(
                           reason=servermanager.NXNETWORK, status=404)),
            mock.patch(DRIVER + '._send_all_data'),
            self.port()
        ) as (mock_update, mock_send_all, p):
            plugin = manager.NeutronManager.get_plugin()
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
        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_create_port'),
            self.port(**{'device_id': 'devid', 'binding:host_id': 'host',
                         'arg_list': ('binding:host_id',)})
        ) as (mock_rest, p):
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
        with contextlib.nested(
            mock.patch(SERVER_POOL + '.rest_create_port'),
            self.port(arg_list=(portbindings.HOST_ID,), **port_kwargs)
        ) as (rmock, port):
            create_body = rmock.mock_calls[-1][1][2]
            self.assertIsNotNone(create_body['bound_segment'])
            self.assertEqual(create_body[portbindings.HOST_ID], ext_id)

    def test_req_context_header_present(self):
        with contextlib.nested(
            mock.patch(SERVER_MANAGER + '.ServerProxy.rest_call'),
            self.port(**{'device_id': 'devid', 'binding:host_id': 'host'})
        ) as (mock_rest, p):
            headers = mock_rest.mock_calls[0][1][3]
            self.assertIn('X-REQ-CONTEXT', headers)
