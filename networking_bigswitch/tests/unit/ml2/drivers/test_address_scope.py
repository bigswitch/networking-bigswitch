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

import mock
import netaddr

from networking_bigswitch.tests.unit.ml2.drivers \
    import test_bigswitch_mech as test_bsml2
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_address_scope as test_as

from neutron_lib import constants

PHYS_NET = 'physnet1'
VLAN_START = 1000
VLAN_END = 1100
SERVER_MANAGER = 'networking_bigswitch.plugins.bigswitch.servermanager'
SERVER_POOL = SERVER_MANAGER + '.ServerPool'
CREATE_NET = SERVER_POOL + '.rest_create_network'
UPDATE_NET = SERVER_POOL + '.rest_update_network'
DRIVER_MOD = 'networking_bigswitch.plugins.ml2.drivers.mech_bigswitch.driver'
DRIVER = DRIVER_MOD + '.BigSwitchMechanismDriver'
HTTPCON = SERVER_MANAGER + '.httplib.HTTPConnection'


class TestBigSwitchAddressScope(test_as.AddressScopeTestCase,
                                test_bsml2.TestBigSwitchMechDriverBase):
    """Tests the Address Scope feature for the big switch plugin.

    The feature itself is already tested upstream, so basic address scope
    database manipulation is not tested here. These tests are just to verify
    that the data sent to the controller is correct based on the topology
    that we create.
    """

    def setUp(self):
        ext_mgr = test_as.AddressScopeTestExtensionManager()
        super(TestBigSwitchAddressScope, self).setUp(ext_mgr=ext_mgr)
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def _make_subnet(self, net_id, subpool_id, prefix_len, ip_version,
                     tenant_id):
        data = {'subnet': {
                'network_id': net_id,
                'subnetpool_id': subpool_id,
                'prefixlen': prefix_len,
                'ip_version': ip_version,
                'tenant_id': tenant_id}}
        req = self.new_create_request('subnets', data)
        return self.deserialize(self.fmt, req.get_response(self.api))

    def test_address_scope_basic(self):
        addr_scope_name = 'FOO'
        subnet = netaddr.IPNetwork('10.10.10.0/24')

        with self.address_scope(name=addr_scope_name) as addr_scope, \
            self.subnetpool(
                prefixes=[subnet.cidr],
                admin=False,
                address_scope_id=addr_scope['address_scope']['id'],
                name=addr_scope_name + 'subpool',
                min_prefixlen='21',
                tenant_id=self._tenant_id) as subpool, \
            mock.patch(CREATE_NET, return_value=None), \
            mock.patch(UPDATE_NET, return_value=None) as net_update_mock, \
                self.network() as net:
                subnet = self._make_subnet(
                    net['network']['id'], subpool['subnetpool']['id'],
                    '24', 4, self._tenant_id)
                net_data = net_update_mock.mock_calls[0][1][2]
                scopes = net_data['address_scopes']['data']
                self.assertFalse(net_data['address_scopes']['overlapping'])
                self.assertEqual(len(scopes), 1)
                self.assertEqual(scopes[0]['name'], addr_scope_name)

    def test_address_scope_ipv4_and_v6(self):
        addr_scope_name = 'FOO'
        subnet4 = netaddr.IPNetwork('10.10.10.0/24')
        subnet6 = netaddr.IPNetwork('2001:db8:1234:0000::/64')

        with self.address_scope(name=addr_scope_name + '4') as addr_scope4, \
            self.address_scope(constants.IP_VERSION_6,
                               name=addr_scope_name + '6') as addr_scope6, \
            self.subnetpool(
                prefixes=[subnet4.cidr],
                admin=False,
                address_scope_id=addr_scope4['address_scope']['id'],
                name=addr_scope_name + 'subpool4',
                min_prefixlen='25',
                tenant_id=self._tenant_id) as subpool4, \
            self.subnetpool(
                prefixes=[subnet6.cidr],
                admin=False,
                address_scope_id=addr_scope6['address_scope']['id'],
                name=addr_scope_name + 'subpool6',
                min_prefixlen='65',
                tenant_id=self._tenant_id) as subpool6, \
            mock.patch(CREATE_NET, return_value=None), \
            mock.patch(UPDATE_NET, return_value=None) as net_update_mock, \
                self.network() as net:
                subnet4 = self._make_subnet(
                    net['network']['id'], subpool4['subnetpool']['id'],
                    '26', 4, self._tenant_id)
                subnet6 = self._make_subnet(
                    net['network']['id'], subpool6['subnetpool']['id'],
                    '65', 6, self._tenant_id)
                net_data = net_update_mock.mock_calls[0][1][2]
                scopes = net_data['address_scopes']['data']
                self.assertFalse(net_data['address_scopes']['overlapping'])
                self.assertEqual(len(scopes), 2)
                self.assertEqual(scopes[0]['name'], addr_scope_name + '4')
                self.assertEqual(scopes[1]['name'], addr_scope_name + '6')

    def test_address_scope_multiple_subs(self):
        addr_scope_name1 = 'FOO1'
        addr_scope_name2 = 'FOO2'
        subnet1 = netaddr.IPNetwork('10.10.10.0/24')
        subnet2 = netaddr.IPNetwork('10.10.20.0/24')

        with self.address_scope(name=addr_scope_name1) as addr_scope1, \
            self.address_scope(name=addr_scope_name2) as addr_scope2, \
            self.subnetpool(
                prefixes=[subnet1.cidr],
                admin=False,
                address_scope_id=addr_scope1['address_scope']['id'],
                name=addr_scope_name1 + 'subpool',
                min_prefixlen='25',
                tenant_id=self._tenant_id) as subpool1, \
            self.subnetpool(
                prefixes=[subnet2.cidr],
                admin=False,
                address_scope_id=addr_scope2['address_scope']['id'],
                name=addr_scope_name2 + 'subpool',
                min_prefixlen='25',
                tenant_id=self._tenant_id) as subpool2, \
            mock.patch(CREATE_NET, return_value=None), \
            mock.patch(UPDATE_NET, return_value=None) as net_update_mock, \
            self.network() as net1, \
                self.network() as net2:
                subnet1 = self._make_subnet(
                    net1['network']['id'], subpool1['subnetpool']['id'],
                    '26', 4, self._tenant_id)
                net_data = net_update_mock.mock_calls[0][1][2]
                scopes = net_data['address_scopes']['data']
                self.assertFalse(net_data['address_scopes']['overlapping'])
                self.assertEqual(len(scopes), 2)
                self.assertEqual(scopes[0]['name'], addr_scope_name1)

                subnet2 = self._make_subnet(
                    net2['network']['id'], subpool2['subnetpool']['id'],
                    '26', 4, self._tenant_id)
                net_data = net_update_mock.mock_calls[0][1][2]
                scopes = net_data['address_scopes']['data']
                self.assertFalse(net_data['address_scopes']['overlapping'])
                self.assertEqual(len(scopes), 2)
                self.assertEqual(scopes[1]['name'], addr_scope_name2)

    def test_address_scope_overlap(self):
        addr_scope_name1 = 'FOO1'
        addr_scope_name2 = 'FOO2'
        subnet1 = netaddr.IPNetwork('10.10.10.0/24')
        subnet2 = netaddr.IPNetwork('10.10.10.0/28')

        with self.address_scope(name=addr_scope_name1) as addr_scope1, \
            self.address_scope(name=addr_scope_name2) as addr_scope2, \
            self.subnetpool(
                prefixes=[subnet1.cidr],
                admin=False,
                address_scope_id=addr_scope1['address_scope']['id'],
                name=addr_scope_name1 + 'subpool',
                min_prefixlen='25',
                tenant_id=self._tenant_id) as subpool1, \
            self.subnetpool(
                prefixes=[subnet2.cidr],
                admin=False,
                address_scope_id=addr_scope2['address_scope']['id'],
                name=addr_scope_name2 + 'subpool',
                min_prefixlen='25',
                tenant_id=self._tenant_id) as subpool2, \
            mock.patch(CREATE_NET, return_value=None), \
            mock.patch(UPDATE_NET, return_value=None) as net_update_mock, \
            self.network() as net1, \
                self.network() as net2:
                subnet1 = self._make_subnet(
                    net1['network']['id'], subpool1['subnetpool']['id'],
                    '26', 4, self._tenant_id)
                net_data = net_update_mock.mock_calls[0][1][2]
                scopes = net_data['address_scopes']['data']
                self.assertTrue(net_data['address_scopes']['overlapping'])
                self.assertEqual(len(scopes), 2)
                self.assertEqual(scopes[0]['name'], addr_scope_name1)

                subnet2 = self._make_subnet(
                    net2['network']['id'], subpool2['subnetpool']['id'],
                    '26', 4, self._tenant_id)
                net_data = net_update_mock.mock_calls[0][1][2]
                scopes = net_data['address_scopes']['data']
                self.assertTrue(net_data['address_scopes']['overlapping'])
                self.assertEqual(len(scopes), 2)
                self.assertEqual(scopes[1]['name'], addr_scope_name2)
