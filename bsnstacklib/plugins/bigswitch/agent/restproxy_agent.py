# Copyright 2014 Big Switch Networks, Inc.
# All Rights Reserved.
#
# Copyright 2011 VMware, Inc.
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

import sys
import time

import eventlet
eventlet.monkey_patch()

from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from oslo_utils import excutils

from neutron.agent.common import ovs_lib
from neutron.agent.linux import utils
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config
from neutron.common import constants as q_const
from neutron.common import topics
from neutron import context as q_context
from neutron.extensions import securitygroup as ext_sg
from neutron.i18n import _LE, _LI
from neutron.openstack.common import loopingcall

from bsnstacklib.plugins.bigswitch import config as pl_config

LOG = log.getLogger(__name__)


class IVSBridge(ovs_lib.OVSBridge):
    '''
    This class does not provide parity with OVS using IVS.
    It's only the bare minimum necessary to use IVS with this agent.
    '''
    def run_vsctl(self, args, check_error=False, log_fail_as_error=True):
        full_args = ["ivs-ctl"] + args
        try:
            resp = utils.execute(full_args, run_as_root=True,
                                 return_stderr=True,
                                 log_fail_as_error=log_fail_as_error)
            return resp[0] or resp[1]
        except Exception as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if log_fail_as_error:
                    logfunc = LOG.error
                else:
                    logfunc = LOG.debug
                logfunc(_LE("Unable to execute %(cmd)s. "
                            "Exception: %(exception)s"),
                        {'cmd': full_args, 'exception': e})
                if not check_error:
                    ctxt.reraise = False

    def get_vif_port_set(self):
        port_names = self.get_port_name_list()
        edge_ports = set(port_names)
        return edge_ports

    def get_vif_port_by_id(self, port_id):
        # IVS in nova uses hybrid method with last 14 chars of UUID
        name = 'qvo%s' % port_id[:14]
        if name in self.get_vif_port_set():
            return name
        return False

    def get_port_name_list(self):
        # Try native list-ports command first and then fallback to show
        # command.
        try:
            resp = self.run_vsctl(['list-ports'], True,
                                  log_fail_as_error=False).strip().splitlines()
            port_names = map(lambda x: x.strip(), resp)
        except RuntimeError:
            resp = self.run_vsctl(['show'], True)
            # get rid of stats and blank lines
            ports = filter(
                lambda x: 'packets=' not in x and x.strip(),
                resp.split('ivs:')[1].split('ports:')[1].splitlines())
            port_names = map(lambda x: x.strip().split(' ')[1], ports)
        LOG.debug("Ports on IVS: %s", port_names)
        return port_names


class FilterDeviceIDMixin(sg_rpc.SecurityGroupAgentRpc):

    def prepare_devices_filter(self, device_ids):
        if not device_ids:
            return
        # use tap as a prefix because ml2 is hard-coded to expect that
        device_ids = [d.replace('qvo', 'tap') for d in device_ids]
        LOG.info(_LI("Preparing filters for devices %s"), device_ids)
        if self.use_enhanced_rpc:
            devices_info = self.plugin_rpc.security_group_info_for_devices(
                self.context, list(device_ids))
            devices = devices_info['devices']
            security_groups = devices_info['security_groups']
            security_group_member_ips = devices_info['sg_member_ips']
        else:
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, list(device_ids))

        with self.firewall.defer_apply():
            for device in devices.values():
                # strip tap back off since prepare_port_filter will apply it
                device['device'] = device['device'].replace('tap', '')
                self.firewall.prepare_port_filter(device)
            if self.use_enhanced_rpc:
                LOG.debug("Update security group information for ports %s",
                          devices.keys())
                self._update_security_group_info(
                    security_groups, security_group_member_ips)


class RestProxyAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    target = oslo_messaging.Target(version='1.1')

    def __init__(self, integ_br, polling_interval, vs='ovs'):
        super(RestProxyAgent, self).__init__()
        self.polling_interval = polling_interval
        self._setup_rpc()
        self.sg_agent = FilterDeviceIDMixin(self.context, self.sg_plugin_rpc)
        if vs == 'ivs':
            self.int_br = IVSBridge(integ_br)
        else:
            self.int_br = ovs_lib.OVSBridge(integ_br)
        self.use_call = True
        self.agent_state = {
            'binary': 'neutron-bsn-agent',
            'host': cfg.CONF.host,
            'topic': q_const.L2_AGENT_TOPIC,
            'configurations': {},
            'agent_type': "BSN IVS Agent",
            'start_flag': True}

    def _report_state(self):
        # How many devices are likely used by a VM
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state,
                                        self.use_call)
            self.use_call = False
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def _setup_rpc(self):
        self.topic = topics.AGENT
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.context = q_context.get_admin_context_without_session()
        self.endpoints = [self]
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def port_update(self, context, **kwargs):
        LOG.debug("Port update received")
        port = kwargs.get('port')
        vif_port = self.int_br.get_vif_port_by_id(port['id'])
        if not vif_port:
            LOG.debug("Port %s is not present on this host.", port['id'])
            return

        LOG.debug("Port %s found. Refreshing firewall.", port['id'])
        if ext_sg.SECURITYGROUPS in port:
            self.sg_agent.refresh_firewall()

    def _update_ports(self, registered_ports):
        ports = self.int_br.get_vif_port_set()
        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}

    def _process_devices_filter(self, port_info):
        if 'added' in port_info:
            self.sg_agent.prepare_devices_filter(port_info['added'])
        if 'removed' in port_info:
            self.sg_agent.remove_devices_filter(port_info['removed'])

    def daemon_loop(self):
        ports = set()

        while True:
            start = time.time()
            try:
                port_info = self._update_ports(ports)
                if port_info:
                    LOG.debug("Agent loop has new device")
                    self._process_devices_filter(port_info)
                    ports = port_info['current']
            except Exception:
                LOG.exception(_LE("Error in agent event loop"))

            elapsed = max(time.time() - start, 0)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval "
                          "(%(polling_interval)s vs. %(elapsed)s)!",
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})


def main():
    config.init(sys.argv[1:])
    config.setup_logging()
    pl_config.register_config()

    integ_br = cfg.CONF.RESTPROXYAGENT.integration_bridge
    polling_interval = cfg.CONF.RESTPROXYAGENT.polling_interval
    bsnagent = RestProxyAgent(integ_br, polling_interval,
                              cfg.CONF.RESTPROXYAGENT.virtual_switch_type)
    bsnagent.daemon_loop()
    sys.exit(0)

if __name__ == "__main__":
    main()
