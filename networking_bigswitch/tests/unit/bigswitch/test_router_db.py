# Copyright 2013 Big Switch Networks, Inc.  All rights reserved.
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
#
# Adapted from neutron.tests.unit.extensions,test_l3

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from webob import exc

from networking_bigswitch.plugins.bigswitch.db import tenant_policy_db  # noqa
from networking_bigswitch.tests.unit.bigswitch import fake_server
from networking_bigswitch.tests.unit.bigswitch \
    import test_base as bsn_test_base
from neutron.extensions import l3
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
from neutron.tests.unit.extensions import test_l3 as test_l3
from neutron_lib import context
from neutron_lib.plugins import directory


HTTPCON = ('networking_bigswitch.plugins.bigswitch.servermanager.httplib'
           '.HTTPConnection')
_uuid = uuidutils.generate_uuid


class RouterRulesTestExtensionManager(object):

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class DHCPOptsTestCase(bsn_test_base.BigSwitchTestBase,
                       test_dhcpopts.TestExtraDhcpOpt):

    def setUp(self, plugin=None):
        self.setup_patches()
        self.setup_config_files()
        super(test_dhcpopts.ExtraDhcpOptDBTestCase,
              self).setUp(plugin=self._plugin_name)
        self.setup_db()
        self.startHttpPatch()


class RouterDBTestBase(bsn_test_base.BigSwitchTestBase,
                       test_l3.L3BaseForIntTests,
                       test_l3.L3NatTestCaseMixin):

    mock_rescheduling = False

    def setUp(self):
        self.setup_patches()
        self.setup_config_files()
        ext_mgr = RouterRulesTestExtensionManager()
        service_plugins = {'L3_ROUTER_NAT': self._l3_plugin_name}
        super(RouterDBTestBase, self).setUp(plugin=self._plugin_name,
                                            ext_mgr=ext_mgr,
                                            service_plugins=service_plugins)
        self.setup_db()
        cfg.CONF.set_default('allow_overlapping_ips', False)
        self.plugin_obj = directory.get_plugin('L3_ROUTER_NAT')
        self.startHttpPatch()


class RouterDBTestCase(RouterDBTestBase,
                       test_l3.L3NatDBIntTestCase):

    def test_router_create(self):
        name = 'router1'
        tenant_id = _uuid()
        expected_value = [('name', name), ('tenant_id', tenant_id),
                          ('admin_state_up', True), ('status', 'ACTIVE'),
                          ('external_gateway_info', None)]
        with mock.patch(HTTPCON) as conmock:
            with self.router(name='router1', admin_state_up=True,
                             tenant_id=tenant_id) as router:
                rv = conmock.return_value
                rv.getresponse.return_value.status = 200
                http_router = jsonutils.loads(rv.request.mock_calls[0][1][2])
                self.assertEqual('tenant_name',
                                 http_router['router'].get('tenant_name'))
                for k, v in expected_value:
                    self.assertEqual(router['router'][k], v)

    def test_router_create_with_external_net_no_tenant_id(self):
        with self.subnet() as s:
            self._set_net_external(s['subnet']['network_id'])
            data = {'router': {'tenant_id': _uuid()}}
            data['router']['name'] = 'router1'
            data['router']['external_gateway_info'] = {
                'network_id': s['subnet']['network_id']}
            self.assertIsNone(
                data['router']['external_gateway_info'].get('tenant_id'))
            router_req = self.new_create_request('routers', data, self.fmt)
            res = router_req.get_response(self.ext_api)
            router = self.deserialize(self.fmt, res)
            # external tenant_id should be patched
            self.assertTrue(
                'tenant_id' in router['router']['external_gateway_info'])

    def test_router_add_interface_port(self):
        orig_update_port = self.plugin.update_port
        with self.router() as r, (
            self.port()) as p, (
                mock.patch.object(self.plugin, 'update_port')) as update_port:
            update_port.side_effect = orig_update_port
            body = self._router_interface_action('add',
                                                 r['router']['id'],
                                                 None,
                                                 p['port']['id'])
            self.assertIn('port_id', body)
            self.assertEqual(p['port']['id'], body['port_id'])
            expected_port_update = {'status': 'ACTIVE'}
            update_port.assert_called_with(
                mock.ANY, p['port']['id'], {'port': expected_port_update})
            # fetch port and confirm device_id
            body = self._show('ports', p['port']['id'])
            self.assertEqual(r['router']['id'], body['port']['device_id'])

            # clean-up
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          None,
                                          p['port']['id'])

    def test_router_create_with_gwinfo_ext_ip_non_admin(self):
        # TODO(kevinbenton): figure out why UTs aren't getting the default
        # policy.json files
        self.skipTest("Policy processing is broken in the separate repo UTs")

    def test_create_floatingip_with_specific_ip_non_admin(self):
        self.skipTest("Policy processing is broken in the separate repo UTs")

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        # TODO(wolverineav): OSP-156 tracks this. need to fix.
        self.skipTest("broken until fixed")

    def test_router_remove_router_interface_wrong_subnet_returns_400(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.subnet(cidr='10.0.10.0/24') as s1:
                    with self.port(subnet=s1) as p:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      None,
                                                      p['port']['id'])
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      s['subnet']['id'],
                                                      p['port']['id'],
                                                      exc.HTTPBadRequest.code)
                        # remove properly to clean-up
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      None,
                                                      p['port']['id'])

    def test_router_remove_router_interface_wrong_port_returns_404(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # create another port for testing failure case
                    res = self._create_port('json', p['port']['network_id'])
                    p2 = self.deserialize('json', res)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p2['port']['id'],
                                                  exc.HTTPNotFound.code)
                    # remove correct interface to cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # remove extra port created
                    self._delete('ports', p2['port']['id'])

    def test_add_network_to_ext_gw_backend_body(self):
        plugin_obj = directory.get_plugin()
        with self.network() as n1, self.router() as r1:
            with self.subnet(network=n1, cidr='10.10.10.10/24') as s1:
                self._set_net_external(s1['subnet']['network_id'])
                with mock.patch.object(plugin_obj.servers,
                                       'rest_update_router') as upmock:
                    self._add_external_gateway_to_router(r1['router']['id'],
                                                         n1['network']['id'])
        router_body = upmock.mock_calls[0][1][1]
        self.assertEqual(
            plugin_obj.get_network(context.get_admin_context(),
                                   n1['network']['id']),
            router_body['external_gateway_info']['network'])

    def test_multi_tenant_flip_alllocation(self):
        tenant1_id = _uuid()
        tenant2_id = _uuid()
        with\
            self.network(tenant_id=tenant1_id) as n1,\
                self.network(tenant_id=tenant2_id) as n2:
            with\
                self.subnet(network=n1, cidr='11.0.0.0/24') as s1,\
                self.subnet(network=n2, cidr='12.0.0.0/24') as s2,\
                    self.subnet(cidr='13.0.0.0/24') as psub:
                with\
                    self.router(tenant_id=tenant1_id) as r1,\
                    self.router(tenant_id=tenant2_id) as r2,\
                    self.port(subnet=s1, tenant_id=tenant1_id) as p1,\
                        self.port(subnet=s2, tenant_id=tenant2_id) as p2:
                    self._set_net_external(psub['subnet']['network_id'])
                    s1id = p1['port']['fixed_ips'][0]['subnet_id']
                    s2id = p2['port']['fixed_ips'][0]['subnet_id']
                    s1 = {'subnet': {'id': s1id}}
                    s2 = {'subnet': {'id': s2id}}
                    self._add_external_gateway_to_router(
                        r1['router']['id'],
                        psub['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r2['router']['id'],
                        psub['subnet']['network_id'])
                    self._router_interface_action(
                        'add', r1['router']['id'],
                        s1['subnet']['id'], None)
                    self._router_interface_action(
                        'add', r2['router']['id'],
                        s2['subnet']['id'], None)
                    fl1 = self._make_floatingip_for_tenant_port(
                        net_id=psub['subnet']['network_id'],
                        port_id=p1['port']['id'],
                        tenant_id=tenant1_id)
                    self.httpPatch.stop()
                    multiFloatPatch = mock.patch(
                        HTTPCON,
                        new=fake_server.VerifyMultiTenantFloatingIP)
                    multiFloatPatch.start()
                    fl2 = self._make_floatingip_for_tenant_port(
                        net_id=psub['subnet']['network_id'],
                        port_id=p2['port']['id'],
                        tenant_id=tenant2_id)
                    multiFloatPatch.stop()
                    self.httpPatch.start()
                    self._delete('floatingips', fl1['floatingip']['id'])
                    self._delete('floatingips', fl2['floatingip']['id'])
                    self._router_interface_action(
                        'remove', r1['router']['id'],
                        s1['subnet']['id'], None)
                    self._router_interface_action(
                        'remove', r2['router']['id'],
                        s2['subnet']['id'], None)

    def _make_floatingip_for_tenant_port(self, net_id, port_id, tenant_id):
        data = {'floatingip': {'floating_network_id': net_id,
                               'tenant_id': tenant_id,
                               'port_id': port_id}}
        floatingip_req = self.new_create_request('floatingips', data, self.fmt)
        res = floatingip_req.get_response(self.ext_api)
        return self.deserialize(self.fmt, res)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(
            'networking_bigswitch.plugins.bigswitch.plugin.NeutronRestProxyV2')

    def test_create_floatingip_no_ext_gateway_return_404(self):
        with self.subnet(cidr='10.0.10.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router():
                    res = self._create_floatingip(
                        'json',
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int, exc.HTTPNotFound.code)

    def test_router_update_gateway(self):
        with self.router() as r:
            with self.subnet() as s1:
                with self.subnet(cidr='10.0.10.0/24') as s2:
                    self._set_net_external(s1['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s1['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEqual(net_id, s1['subnet']['network_id'])
                    self._set_net_external(s2['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEqual(net_id, s2['subnet']['network_id'])
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])

    def test_router_add_interface_overlapped_cidr(self):
        self.skipTest("Plugin does not support")

    def test_router_add_interface_overlapped_cidr_returns_400(self):
        self.skipTest("Plugin does not support")

    def test_list_nets_external(self):
        self.skipTest("Plugin does not support")

    def test_router_update_gateway_with_existed_floatingip(self):
        with self.subnet(cidr='10.0.10.0/24') as subnet:
            self._set_net_external(subnet['subnet']['network_id'])
            with self.floatingip_with_assoc() as fip:
                self._add_external_gateway_to_router(
                    fip['floatingip']['router_id'],
                    subnet['subnet']['network_id'],
                    expected_code=exc.HTTPConflict.code)

    def test_router_remove_interface_wrong_subnet_returns_400(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.10.0/24') as s:
                with self.port() as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  p['port']['id'],
                                                  exc.HTTPBadRequest.code)
                    # remove properly to clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_remove_interface_wrong_port_returns_404(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.10.0/24'):
                with self.port() as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # create another port for testing failure case
                    res = self._create_port('json', p['port']['network_id'])
                    p2 = self.deserialize('json', res)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p2['port']['id'],
                                                  exc.HTTPNotFound.code)
                    # remove correct interface to cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # remove extra port created
                    self._delete('ports', p2['port']['id'])

    def test_send_data(self):
        fmt = 'json'
        plugin_obj = directory.get_plugin()

        with self.router() as r:
            r_id = r['router']['id']

            with self.subnet(cidr='10.0.10.0/24') as s:
                s_id = s['subnet']['id']

                with self.router() as r1:
                    r1_id = r1['router']['id']
                    body = self._router_interface_action('add', r_id, s_id,
                                                         None)
                    self.assertIn('port_id', body)
                    r_port_id = body['port_id']
                    body = self._show('ports', r_port_id)
                    self.assertEqual(body['port']['device_id'], r_id)

                    with self.subnet(cidr='10.0.20.0/24') as s1:
                        s1_id = s1['subnet']['id']
                        body = self._router_interface_action('add', r1_id,
                                                             s1_id, None)
                        self.assertIn('port_id', body)
                        r1_port_id = body['port_id']
                        body = self._show('ports', r1_port_id)
                        self.assertEqual(body['port']['device_id'], r1_id)

                        with self.subnet(cidr='11.0.0.0/24') as public_sub:
                            public_net_id = public_sub['subnet']['network_id']
                            self._set_net_external(public_net_id)

                            with self.port() as prv_port:
                                prv_fixed_ip = prv_port['port']['fixed_ips'][0]
                                priv_sub_id = prv_fixed_ip['subnet_id']
                                self._add_external_gateway_to_router(
                                    r_id, public_net_id)
                                self._router_interface_action('add', r_id,
                                                              priv_sub_id,
                                                              None)

                                priv_port_id = prv_port['port']['id']
                                res = self._create_floatingip(
                                    fmt, public_net_id,
                                    port_id=priv_port_id)
                                self.assertEqual(res.status_int,
                                                 exc.HTTPCreated.code)
                                floatingip = self.deserialize(fmt, res)

                                result = plugin_obj._send_all_data()
                                self.assertEqual(result[0], 200)

                                self._delete('floatingips',
                                             floatingip['floatingip']['id'])
                                self._remove_external_gateway_from_router(
                                    r_id, public_net_id)
                                self._router_interface_action('remove', r_id,
                                                              priv_sub_id,
                                                              None)
                        self._router_interface_action('remove', r_id, s_id,
                                                      None)
                        self._show('ports', r_port_id,
                                   expected_code=exc.HTTPNotFound.code)
                        self._router_interface_action('remove', r1_id, s1_id,
                                                      None)
                        self._show('ports', r1_port_id,
                                   expected_code=exc.HTTPNotFound.code)

    def test_rollback_on_router_create(self):
        tid = test_base._uuid()
        self.httpPatch.stop()
        with mock.patch(HTTPCON, new=fake_server.HTTPConnectionMock500):
            self._create_router('json', tid)
        self.assertTrue(len(self._get_routers(tid)) == 0)

    def test_rollback_on_router_update(self):
        with self.router() as r:
            data = {'router': {'name': 'aNewName'}}
            self.httpPatch.stop()
            with mock.patch(HTTPCON, new=fake_server.HTTPConnectionMock500):
                self.new_update_request(
                    'routers', data, r['router']['id']).get_response(self.api)
            self.httpPatch.start()
            updatedr = self._get_routers(r['router']['tenant_id'])[0]
            # name should have stayed the same due to failure
            self.assertEqual(r['router']['name'], updatedr['name'])

    def test_rollback_on_router_delete(self):
        with self.router() as r:
            self.httpPatch.stop()
            with mock.patch(HTTPCON, new=fake_server.HTTPConnectionMock500):
                self._delete('routers', r['router']['id'],
                             expected_code=exc.HTTPInternalServerError.code)
            self.httpPatch.start()
            self.assertEqual(r['router']['id'],
                             self._get_routers(r['router']['tenant_id']
                                               )[0]['id'])

    def _get_routers(self, tenant_id):
        ctx = context.Context('', tenant_id)
        return self.plugin_obj.get_routers(ctx)


def _strip_rule_ids(rules):
    cleaned = []
    for rule in rules:
        del rule['id']
        cleaned.append(rule)
    return cleaned
