# Copyright 2014 Big Switch Networks, Inc.
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

import mock
from oslo_utils import importutils

from neutron.tests import base

from networking_bigswitch.plugins.bigswitch import config as pl_config

OVSBRIDGE = 'neutron.agent.common.ovs_lib.OVSBridge'
PLUGINAPI = 'neutron.agent.rpc.PluginApi'
CONTEXT = 'neutron_lib.context'
CONSUMERCREATE = 'neutron.agent.rpc.create_consumers'
SGRPC = 'neutron.agent.securitygroups_rpc'
AGENTMOD = 'networking_bigswitch.plugins.bigswitch.agent.restproxy_agent'
SGAGENT = AGENTMOD + '.FilterDeviceIDMixin'
IVSBRIDGE = AGENTMOD + '.IVSBridge'
NFVSWBRIDGE = AGENTMOD + '.NFVSwitchBridge'
NEUTRONCFG = 'neutron.common.config'
PLCONFIG = 'networking_bigswitch.plugins.bigswitch.config'


class BaseAgentTestCase(base.BaseTestCase):

    def setUp(self):
        pl_config.register_config()
        super(BaseAgentTestCase, self).setUp()
        self.mod_agent = importutils.import_module(AGENTMOD)


class TestRestProxyAgentOVS(BaseAgentTestCase):
    def setUp(self):
        super(TestRestProxyAgentOVS, self).setUp()
        self.plapi = mock.patch(PLUGINAPI).start()
        self.ovsbridge_p = mock.patch(OVSBRIDGE)
        self.ovsbridge = self.ovsbridge_p.start()
        self.context = mock.patch(CONTEXT).start()
        self.rpc = mock.patch(CONSUMERCREATE).start()
        self.sg_agent = mock.patch(SGAGENT).start()
        self.sg_rpc = mock.patch(SGRPC).start()

    def mock_agent(self):
        mock_context = mock.Mock(return_value='abc')
        self.context.get_admin_context_without_session = mock_context
        return self.mod_agent.RestProxyAgent('int-br', 2)

    def mock_port_update(self, **kwargs):
        agent = self.mock_agent()
        agent.port_update(mock.Mock(), **kwargs)

    def test_port_update(self):
        port = {'id': '1', 'security_groups': 'default'}

        with mock.patch.object(self.ovsbridge.return_value,
                               'get_vif_port_by_id',
                               return_value='1') as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with('1')
        self.sg_agent.assert_has_calls([
            mock.call().refresh_firewall()
        ])

    def test_port_update_not_vifport(self):
        port = {'id': '1', 'security_groups': 'default'}

        with mock.patch.object(self.ovsbridge.return_value,
                               'get_vif_port_by_id',
                               return_value=False) as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with('1')
        self.assertFalse(self.sg_agent.return_value.refresh_firewall.called)

    def test_port_update_without_secgroup(self):
        port = {'id': '1'}

        with mock.patch.object(self.ovsbridge.return_value,
                               'get_vif_port_by_id',
                               return_value='1') as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with('1')
        self.assertFalse(self.sg_agent.return_value.refresh_firewall.called)

    def mock_update_ports(self, vif_port_set=None, registered_ports=None):
        vif_port_set = vif_port_set or set()
        registered_ports = registered_ports or set()
        with mock.patch.object(self.ovsbridge.return_value,
                               'get_vif_port_set',
                               return_value=vif_port_set):
            agent = self.mock_agent()
            return agent._update_ports(registered_ports)

    def test_update_ports_unchanged(self):
        self.assertIsNone(self.mock_update_ports())

    def test_update_ports_changed(self):
        vif_port_set = set(['1', '3'])
        registered_ports = set(['1', '2'])
        expected = dict(current=vif_port_set,
                        added=set(['3']),
                        removed=set(['2']))

        actual = self.mock_update_ports(vif_port_set, registered_ports)

        self.assertEqual(expected, actual)

    def mock_process_devices_filter(self, port_info):
        agent = self.mock_agent()
        agent._process_devices_filter(port_info)

    def test_process_devices_filter_add(self):
        port_info = {'added': 1}

        self.mock_process_devices_filter(port_info)

        self.sg_agent.assert_has_calls([
            mock.call().prepare_devices_filter(1)
        ])

    def test_process_devices_filter_remove(self):
        port_info = {'removed': 2}

        self.mock_process_devices_filter(port_info)

        self.sg_agent.assert_has_calls([
            mock.call().remove_devices_filter(2)
        ])

    def test_process_devices_filter_both(self):
        port_info = {'added': 1, 'removed': 2}

        self.mock_process_devices_filter(port_info)

        self.sg_agent.assert_has_calls([
            mock.call().prepare_devices_filter(1),
            mock.call().remove_devices_filter(2)
        ])

    def test_process_devices_filter_none(self):
        port_info = {}

        self.mock_process_devices_filter(port_info)

        self.assertFalse(
            self.sg_agent.return_value.prepare_devices_filter.called)
        self.assertFalse(
            self.sg_agent.return_value.remove_devices_filter.called)


class TestRestProxyAgent(BaseAgentTestCase):
    def mock_main(self):
        cfg_attrs = {'CONF.RESTPROXYAGENT.integration_bridge': 'integ_br',
                     'CONF.RESTPROXYAGENT.polling_interval': 5,
                     'CONF.RESTPROXYAGENT.virtual_switch_type': 'ovs',
                     'CONF.AGENT.root_helper': 'helper',
                     'CONF.AGENT.report_interval': 60}
        with\
            mock.patch(AGENTMOD + '.cfg', **cfg_attrs) as mock_conf,\
            mock.patch(AGENTMOD + '.config.init'),\
            mock.patch(NEUTRONCFG) as mock_log_conf,\
                mock.patch(PLCONFIG):
            self.mod_agent.main()

        mock_log_conf.assert_has_calls([
            mock.call(mock_conf),
        ])

    def test_main(self):
        agent_attrs = {'daemon_loop.side_effect': SystemExit(0)}
        with mock.patch(AGENTMOD + '.RestProxyAgent',
                        **agent_attrs) as mock_agent:
            self.assertRaises(SystemExit, self.mock_main)

        mock_agent.assert_has_calls([
            mock.call('integ_br', 5, 'ovs'),
            mock.call().daemon_loop()
        ])


class TestRestProxyAgentIVS(TestRestProxyAgentOVS):

    def setUp(self):
        super(TestRestProxyAgentIVS, self).setUp()
        # we don't want to mock out the whole class, just the part that
        # tries to run commands on the system
        self.ovsbridge_p.stop()
        self.runvsctl = mock.patch(IVSBRIDGE + '.run_vsctl').start()

    def mock_agent(self):
        mock_context = mock.Mock(return_value='abc')
        self.context.get_admin_context_without_session = mock_context
        # same as OVS case except passing 'ivs' for vswitch type
        return self.mod_agent.RestProxyAgent('int-br', 2, vs='ivs')

    def mock_update_ports(self, vif_port_set=None, registered_ports=None):
        vif_port_set = vif_port_set or set()
        registered_ports = registered_ports or set()
        agent = self.mock_agent()
        with mock.patch.object(agent.int_br,
                               'get_vif_port_set',
                               return_value=vif_port_set):
            return agent._update_ports(registered_ports)

    def test_port_update_not_vifport(self):
        port = {'id': '1', 'security_groups': 'default'}

        with mock.patch(IVSBRIDGE + '.get_vif_port_by_id',
                        return_value=False) as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with('1')
        self.assertFalse(self.sg_agent.return_value.refresh_firewall.called)

    def test_port_update_without_secgroup(self):
        port = {'id': '1'}

        with mock.patch(IVSBRIDGE + '.get_vif_port_by_id',
                        return_value='1') as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with('1')
        self.assertFalse(self.sg_agent.return_value.refresh_firewall.called)

    def test_port_update(self):
        port = {'id': '1', 'security_groups': 'default'}

        with mock.patch(IVSBRIDGE + '.get_vif_port_by_id',
                        return_value='1') as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with('1')
        self.sg_agent.assert_has_calls([
            mock.call().refresh_firewall()
        ])

    def test_port_list_with_new_method(self):
        agent = self.mock_agent()
        self.runvsctl.return_value = "port1\nport2\nport3\n"
        self.assertEqual(['port1', 'port2', 'port3'],
                         agent.int_br.get_port_name_list())
        expected_calls = [mock.call(['list-ports'], True,
                                    log_fail_as_error=False)]
        self.assertEqual(expected_calls, self.runvsctl.mock_calls)

    def test_port_list_fallback_to_show(self):
        agent = self.mock_agent()
        # fail the first call to 'list-ports' so it falls back to 'show'
        self.runvsctl.side_effect = [RuntimeError(), IVS_SHOW_OUTPUT]
        self.assertEqual(['ivs', 'p1p1', 'p1p2', 'os-mgmt',
                          'tapa40e6816-82', 'inband'],
                         agent.int_br.get_port_name_list())
        expected_calls = [mock.call(['list-ports'], True,
                                    log_fail_as_error=False),
                          mock.call(['show'], True)]
        self.assertEqual(expected_calls, self.runvsctl.mock_calls)


# some test 'ivs-ctl show' data
IVS_SHOW_OUTPUT = '''
ovs-system:
  kernel lookups: hit=7 missed=11 lost=0
  kernel flows=0
  ports:
    0 ovs-system (internal)
      rx: packets=0 bytes=0 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    1 bond0
      rx: packets=0 bytes=0 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    2 br-int (internal)
      rx: packets=0 bytes=0 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    3 vxlan_sys_4789 (unknown vport type)
      rx: packets=0 bytes=0 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    4 br-tun (internal)
      rx: packets=0 bytes=0 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    5 br-eth0 (internal)
      rx: packets=0 bytes=0 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    6 br-ex (internal)
      rx: packets=8 bytes=648 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
ivs:
  kernel lookups: hit=19446 missed=2998 lost=1
  kernel flows=1
  ports:
    0 ivs (internal)
      rx: packets=0 bytes=0 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    1 p1p1
      rx: packets=1863 bytes=232066 errors=0 dropped=0
      tx: packets=1210 bytes=100440 errors=0 dropped=0
    2 p1p2
      rx: packets=0 bytes=0 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    3 os-mgmt (internal)
      rx: packets=8 bytes=648 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    4 tapa40e6816-82
      rx: packets=8 bytes=648 errors=0 dropped=0
      tx: packets=0 bytes=0 errors=0 dropped=0
    1000 inband (internal)
      rx: packets=20565 bytes=1768550 errors=0 dropped=0
      tx: packets=586 bytes=50368 errors=0 dropped=0'''


class TestRestProxyAgentNFVSwitch(TestRestProxyAgentOVS):

    def setUp(self):
        super(TestRestProxyAgentNFVSwitch, self).setUp()
        # we don't want to mock out the whole class, just the part that
        # tries to run commands on the system
        self.ovsbridge_p.stop()

    def mock_agent(self):
        mock_context = mock.Mock(return_value='abc')
        self.context.get_admin_context_without_session = mock_context
        # same as OVS case except passing 'nfvswitch' for vswitch type
        return self.mod_agent.RestProxyAgent('int-br', 2, vs='nfvswitch')

    def mock_update_ports(self, vif_port_set=None, registered_ports=None):
        vif_port_set = vif_port_set or set()
        registered_ports = registered_ports or set()
        agent = self.mock_agent()
        with mock.patch.object(agent.int_br,
                               'get_vif_port_set',
                               return_value=vif_port_set):
            return agent._update_ports(registered_ports)

    def test_port_update_not_vifport(self):
        port = {'id': '1', 'security_groups': 'default'}

        with mock.patch(NFVSWBRIDGE + '.get_vif_port_by_id',
                        return_value=False) as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with('1')
        self.assertFalse(self.sg_agent.return_value.refresh_firewall.called)

    def test_port_update_without_secgroup(self):
        port = {'id': '1'}

        with mock.patch(NFVSWBRIDGE + '.get_vif_port_by_id',
                        return_value=False) as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with('1')
        self.assertFalse(self.sg_agent.return_value.refresh_firewall.called)

    def test_port_update(self):
        port = {'id': '1', 'security_groups': 'default'}

        with mock.patch(NFVSWBRIDGE + '.get_vif_port_by_id',
                        return_value=False) as get_vif:
            self.mock_port_update(port=port)

        get_vif.assert_called_once_with('1')
        self.assertFalse(self.sg_agent.return_value.refresh_firewall.called)
