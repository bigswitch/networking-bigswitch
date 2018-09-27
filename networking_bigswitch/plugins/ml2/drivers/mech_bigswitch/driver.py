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
import copy
import datetime
import httplib
import os

import eventlet
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from oslo_utils import excutils
from oslo_utils import timeutils

from neutron.common import rpc as n_rpc
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import context as ctx
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api

from networking_bigswitch.plugins.bigswitch import config as pl_config
from networking_bigswitch.plugins.bigswitch.i18n import _
from networking_bigswitch.plugins.bigswitch.i18n import _LE
from networking_bigswitch.plugins.bigswitch.i18n import _LI
from networking_bigswitch.plugins.bigswitch.i18n import _LW
from networking_bigswitch.plugins.bigswitch import plugin
from networking_bigswitch.plugins.bigswitch import servermanager

EXTERNAL_PORT_OWNER = 'neutron:external_port'
ROUTER_GATEWAY_PORT_OWNER = 'network:router_gateway'
OVS_AGENT_INI_FILEPATH = '/etc/neutron/plugins/ml2/openvswitch_agent.ini'
RH_NET_CONF_PATH = "/etc/os-net-config/config.json"
LOG = log.getLogger(__name__)
add_debug_log = plugin.add_debug_log

# time in seconds to maintain existence of vswitch response
CACHE_VSWITCH_TIME = 60


def _read_ovs_bridge_mappings():
    """Read the 'bridge_mappings' property from openvswitch_agent.ini

    This is done for Redhat environments, to allow an improved
    learning/programming of interface groups based on ports and the network
    to which the ports belong to.

    :return: bridge_mappings dictionary {'physnet_name': 'bridge_name', ...}
                {} empty dictionary when not found
    """
    mapping = {}
    mapping_str = None
    # read openvswitch_agent.ini for bridge_mapping info
    if not os.path.isfile(OVS_AGENT_INI_FILEPATH):
        # if ovs_agent.ini doesn't exists, return empty mapping
        LOG.warning(_LW("Unable to read OVS bridge_mappings, "
                        "openvswitch_agent.ini file not present."))
        return mapping

    with open(OVS_AGENT_INI_FILEPATH) as f:
        for line in f:
            if ('#' not in line and
                    ('=' in line and 'bridge_mappings' in line)):
                # typical config line looks like the following:
                # bridge_mappings = datacentre:br-ex,dpdk:br-link
                key, value = line.split('=', 1)
                mapping_str = value.strip()

    # parse comma separated physnet list into individual mappings
    if not mapping_str:
        # if file did not have bridge_mappings, return empty mapping
        LOG.warning(_LW(
            "Unable to read OVS bridge_mappings, either the line is commented "
            "or not present in openvswitch_agent.ini."))
        return mapping

    phy_map_list = mapping_str.split(',')
    for phy_map in phy_map_list:
        phy, bridge = phy_map.split(':')
        mapping[phy.strip()] = bridge.strip()

    LOG.info(_LI("OVS bridge_mappings are: %(br_map)s"), {'br_map': mapping})
    return mapping


class BigSwitchMechanismDriver(plugin.NeutronRestProxyV2Base,
                               api.MechanismDriver):

    """Mechanism Driver for Big Switch Networks Controller.

    This driver relays the network create, update, delete
    operations to the Big Switch Controller.
    """
    target = oslo_messaging.Target(version='1.1')

    def initialize(self):
        LOG.debug('Initializing driver')

        # register plugin config opts
        pl_config.register_config()
        self.evpool = eventlet.GreenPool(cfg.CONF.RESTPROXY.thread_pool_size)

        # init network ctrl connections
        self.servers = servermanager.ServerPool()
        self.servers.get_topo_function = self._get_all_data
        self.servers.get_topo_function_args = {'get_ports': True,
                                               'get_floating_ips': True,
                                               'get_routers': True,
                                               'get_sgs': True}
        # perform one forced topo_sync after 60secs. delayed to let plugin
        # initialization complete
        eventlet.spawn_after(60, self.servers.force_topo_sync,
                             **{'check_ts': True})

        self.segmentation_types = ', '.join(cfg.CONF.ml2.type_drivers)
        # if os-net-config is present, attempt to read physnet bridge_mappings
        # from openvswitch_agent.ini
        self.bridge_mappings = {}
        if os.path.isfile(RH_NET_CONF_PATH):
            self.bridge_mappings = _read_ovs_bridge_mappings()
        # Track hosts running IVS to avoid excessive calls to the backend
        self.ivs_host_cache = {}
        self.setup_rpc_callbacks()

        LOG.debug("Initialization done")

    def setup_rpc_callbacks(self):
        # Security group operations are split between callback and RPC
        # notifications mechanism.
        # Callbacks are 'only once' and RPC notifications are 'at least once'.
        # In a HA setup, RPC notifications can be called once per overcloud
        # controller.
        # Callback: SG add, SG delete, SG update, SG rule add
        # RPC notifications: SG add, SG delete, SG rule delete
        # In addition, RPC notifications also used for: tenant add,
        # tenant delete, log all other events as FYI.

        # Register callbacks ONLY IF sync_security_groups is True
        if cfg.CONF.RESTPROXY.sync_security_groups:
            # following way to register call back functions start in kilo
            self._create_sg_f = self.bsn_create_sg_callback
            self._delete_sg_f = self.bsn_delete_sg_callback
            self._update_sg_f = self.bsn_update_sg_callback
            self._create_sg_rule_f = self.bsn_create_sg_rule_callback
            registry.subscribe(self._create_sg_f,
                               resources.SECURITY_GROUP, events.AFTER_CREATE)
            registry.subscribe(self._delete_sg_f,
                               resources.SECURITY_GROUP, events.AFTER_DELETE)
            registry.subscribe(self._update_sg_f,
                               resources.SECURITY_GROUP, events.AFTER_UPDATE)
            registry.subscribe(self._create_sg_rule_f,
                               resources.SECURITY_GROUP_RULE,
                               events.AFTER_CREATE)

        # the above does not cover the cases where security groups are
        # initially created or when they are deleted since those actions
        # aren't needed by the L2 agent. In order to receive those, we
        # subscribe to the notifications topic that receives all of the
        # API create/update/delete events.
        # Notifications are published at the 'info' level so they will result
        # in a call to the 'info' function below. From there we can check
        # the event type and determine what to do from there.
        target = oslo_messaging.Target(topic='#',
                                       server=cfg.CONF.host)
        keystone_target = oslo_messaging.Target(
            topic='#', exchange='keystone', server=cfg.CONF.host)
        self.listener = oslo_messaging.get_notification_listener(
            n_rpc.TRANSPORT, [target, keystone_target], [self],
            executor='eventlet', allow_requeue=False)
        self.listener.start()

    def bsn_create_sg_callback(self, resource, event, trigger, **kwargs):
        security_group = kwargs.get('security_group')
        context = kwargs.get('context')
        if security_group and context:
            sg_id = security_group.get('id')
            LOG.debug("Callback create sg_id: %s", sg_id)
            self.bsn_create_security_group(sg_id=sg_id, context=context)

    def bsn_delete_sg_callback(self, resource, event, trigger, **kwargs):
        sg_id = kwargs.get('security_group_id')
        context = kwargs.get('context')
        if sg_id and context:
            LOG.debug("Callback delete sg_id: %s", sg_id)
            self.bsn_delete_security_group(sg_id=sg_id, context=context)

    def bsn_update_sg_callback(self, resource, event, trigger, **kwargs):
        security_group = kwargs.get('security_group')
        context = kwargs.get('context')
        if security_group and context:
            sg_id = security_group.get('id')
            LOG.debug("Callback update sg_id: %s", sg_id)
            self.bsn_create_security_group(sg_id=sg_id, context=context)

    def bsn_create_sg_rule_callback(self, resource, event, trigger, **kwargs):
        rule = kwargs.get('security_group_rule')
        context = kwargs.get('context')
        if rule and context:
            sg_id = rule.get('security_group_id')
            LOG.debug("Callback create rule in sg_id: %s", sg_id)
            self.bsn_create_security_group(sg_id=sg_id, context=context)

    def bsn_delete_sg_rule(self, sg_rule, context):
        LOG.debug("Deleting security group rule from BCF: %s", sg_rule)
        if not context:
            LOG.error(_LE(
                "Context missing when trying to delete security group rule. "
                "Please force-bcf-sync to ensure consistency with BCF."))
        sg_id = sg_rule['security_group_id']
        # we over write the sg on bcf controller instead of deleting
        try:
            self.bsn_create_security_group(sg_id,
                                           context=context)
        except ext_sg.SecurityGroupNotFound:
            # DB query will throw exception when security group is
            # being deleted. delete_security_group_rule callback would
            # try to update BCF with new set of rules.
            LOG.warning(
                _LW("Security group with ID %(sg_id)s not found "
                    "when trying to update."), {'sg_id': sg_id})

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        """This is called on each notification to the neutron topic """
        # we retain this section for security groups, because it handles
        # other events as well. Ignore security group events if disabled in
        # config
        if event_type == 'security_group.create.end':
            LOG.debug("Security group created: %s", payload)
            if cfg.CONF.RESTPROXY.sync_security_groups:
                self.bsn_create_security_group(sg=payload['security_group'])
        elif event_type == 'security_group.delete.end':
            LOG.debug("Security group deleted: %s", payload)
            if cfg.CONF.RESTPROXY.sync_security_groups:
                self.bsn_delete_security_group(payload['security_group_id'])
        elif event_type == 'security_group_rule.delete.end':
            LOG.debug("Security group rule deleted: %s", payload)
            if cfg.CONF.RESTPROXY.sync_security_groups:
                self.bsn_delete_sg_rule(payload['security_group_rule'], ctxt)
        elif event_type == 'identity.project.deleted':
            LOG.debug("Project deleted: %s", payload)
            self.bsn_delete_tenant(payload['resource_info'])
        elif event_type == 'identity.project.created':
            LOG.debug("Project created: %s", payload)
            self.bsn_create_tenant(payload['resource_info'])
        elif event_type == 'identity.project.updated':
            LOG.debug("Project updated: %s", payload)
            # update is the same as create, nsapi will handle it
            self.bsn_create_tenant(payload['resource_info'])
        else:
            LOG.debug("Else events: %s payload: %s", (event_type, payload))

    @add_debug_log
    def security_groups_rule_updated(self, context, **kwargs):
        # this will get called whenever a security group rule updated message
        # goes onto the RPC bus
        LOG.debug("security_groups_rule_updated: %s", kwargs)
        if kwargs.get('security_groups'):
            for sg_id in kwargs.get('security_groups'):
                self.bsn_create_security_group(sg_id, context=context)

    @add_debug_log
    def security_groups_member_updated(self, context, **kwargs):
        pass

    @add_debug_log
    def security_groups_provider_updated(self, context, **kwargs):
        pass

    @add_debug_log
    def create_network_postcommit(self, context):
        # create network on the network controller
        self._send_create_network(context.current)

    @add_debug_log
    def update_network_precommit(self, context):
        self._verify_network_precommit(context)

    @add_debug_log
    def update_network_postcommit(self, context):
        # update network on the network controller
        self._send_update_network(context.current)

    @add_debug_log
    def update_subnet_postcommit(self, context):
        self._trigger_network_update_from_subnet_transaction(context)

    @add_debug_log
    def create_subnet_postcommit(self, context):
        self._trigger_network_update_from_subnet_transaction(context)

    @add_debug_log
    def delete_subnet_postcommit(self, context):
        self._trigger_network_update_from_subnet_transaction(context)

    def _trigger_network_update_from_subnet_transaction(self, context):
        net = directory.get_plugin().get_network(
            ctx.get_admin_context(), context.current['network_id'])
        self._send_update_network(net)

    @add_debug_log
    def delete_network_postcommit(self, context):
        # delete network on the network controller
        self._send_delete_network(context.current)

    @add_debug_log
    def create_port_postcommit(self, context):
        if not self._is_port_supported(context.current):
            LOG.debug("Ignoring unsupported vnic type")
            return

        if self._is_port_sriov(context.current):
            LOG.debug("SR-IOV port, nothing to do")
            return

        # If bsn_l3 plugin and it is a gateway port, bind to ivs.
        if (self.l3_bsn_plugin and
                context.current['device_owner'] == ROUTER_GATEWAY_PORT_OWNER):
            directory.get_plugin().update_port_status(
                context._plugin_context, context.current['id'],
                const.PORT_STATUS_ACTIVE)

        try:
            # create port on the network controller
            port = self._prepare_port_for_controller(context)
        except servermanager.TenantIDNotFound as e:
            LOG.warning("Skipping create port %(port)s as %(exp)s",
                        {'port': context.current.get('id'), 'exp': e})
            return

        if port:
            # For vhostuser type ports, membership rule and endpoint was
            # created during bind_port, so skip this
            if port[portbindings.VIF_TYPE] == portbindings.VIF_TYPE_VHOST_USER:
                return

            self.async_port_create(port["network"]["tenant_id"],
                                   port["network"]["id"], port)

    @add_debug_log
    def update_port_postcommit(self, context):
        if not self._is_port_supported(context.current):
            LOG.debug("Ignoring unsupported vnic type")
            return

        # OSP-68: check if port is SRIOV and VM detach case, then skip host_id
        # check and delete port on controller side
        # read-only for shared context okay. deepcopy before modifying
        port = context.current
        network = context.network.current
        if self._is_port_sriov_vm_detach(port, network):
            LOG.debug("update_port_postcommmit called for SRIOV port VM "
                      "detach case.")
            # remove port from BCF and return
            self.servers.rest_delete_port(network["tenant_id"],
                                          network["id"],
                                          port["id"])
            return

        # Else: regular port update,
        # update port on the network controller
        try:
            port = self._prepare_port_for_controller(context)
        except servermanager.TenantIDNotFound as e:
            LOG.warning("Skipping update port %(port)s as %(exp)s",
                        {'port': context.current.get('id'), 'exp': e})
            return

        if port:
            try:
                # For SR-IOV ports, we shouldn't update the port status
                update_status = not self._is_port_sriov(port)
                self.async_port_create(port["network"]["tenant_id"],
                                       port["network"]["id"], port,
                                       update_status)
            except servermanager.RemoteRestError as e:
                with excutils.save_and_reraise_exception() as ctxt:
                    if (cfg.CONF.RESTPROXY.auto_sync_on_failure and
                            e.status == httplib.NOT_FOUND and
                            servermanager.NXNETWORK in e.reason):
                        ctxt.reraise = False
                        LOG.error("Inconsistency with backend controller "
                                  "triggering full synchronization.")
                        self._send_all_data_auto(
                            triggered_by_tenant=port["network"]["tenant_id"]
                        )

    @add_debug_log
    def delete_port_postcommit(self, context):
        if not self._is_port_supported(context.current):
            LOG.debug("Ignoring unsupported vnic type")
            return

        # delete port on the network controller
        port = context.current
        net = context.network.current
        tenant_id = net['tenant_id']
        if not tenant_id:
            tenant_id = servermanager.SERVICE_TENANT
        self.servers.rest_delete_port(tenant_id, net["id"], port['id'])

    def _prepare_port_for_controller(self, context):
        """Make a copy so the context isn't changed for other drivers

        :exception can throw servermanager.TenantIDNotFound
        """
        port = copy.deepcopy(context.current)
        net = context.network.current
        port['network'] = net
        port['bound_segment'] = context.top_bound_segment
        prepped_port = self._map_display_name_or_tenant(port)
        if prepped_port.get('description'):
            del (prepped_port['description'])
        if self.servers.is_unicode_enabled():
            prepped_port['name'] = None
        prepped_port = self._map_state_and_status(prepped_port)
        prepped_port = self._map_port_hostid(prepped_port, net)
        return prepped_port

    def _bind_port_ivswitch(self, context, segment):
        """Perform bind_port for Indigo virtual switch.

        @param context: PortContext object
        """
        vif_type = pl_config.VIF_TYPE_IVS
        vif_details = {portbindings.CAP_PORT_FILTER: True,
                       portbindings.OVS_HYBRID_PLUG: True}
        context.set_binding(segment[api.ID], vif_type, vif_details)

    @add_debug_log
    def bind_port(self, context):
        """Marks ports as bound.

        Binds external ports and IVS ports.
        Fabric configuration will occur on the subsequent port update.
        Currently only vlan segments are supported.
        """
        if context.current['device_owner'] == EXTERNAL_PORT_OWNER:
            # TODO(kevinbenton): check controller to see if the port exists
            # so this driver can be run in parallel with others that add
            # support for external port bindings
            for segment in context.segments_to_bind:
                if segment[api.NETWORK_TYPE] == const.TYPE_VLAN:
                    context.set_binding(
                        segment[api.ID], portbindings.VIF_TYPE_BRIDGE,
                        {portbindings.CAP_PORT_FILTER: False,
                         portbindings.OVS_HYBRID_PLUG: False})
                    return

        if not self._is_port_supported(context.current):
            LOG.debug("Ignoring unsupported vnic type")
            return

        if self._is_port_sriov(context.current):
            LOG.debug("SR-IOV port, nothing to do")
            return

        # IVS hosts will have a vswitch with the same name as the hostname
        if self.does_vswitch_exist(context.host):
            for segment in context.segments_to_bind:
                if segment[api.NETWORK_TYPE] == const.TYPE_VLAN:
                    self._bind_port_ivswitch(context, segment)

    def does_vswitch_exist(self, host):
        """Check if Indigo vswitch exists with the given hostname.

        Returns True if switch exists on backend.
        Returns False if switch does not exist.
        Returns None if backend could not be reached.
        Caches response from backend.
        """
        try:
            return self._get_cached_vswitch_existence(host)
        except ValueError:
            # cache was empty for that switch or expired
            pass

        try:
            exists = bool(self.servers.rest_get_switch(host))
        except servermanager.RemoteRestError:
            # Connectivity or internal server error. Skip cache to try again on
            # next binding attempt
            return
        self.ivs_host_cache[host] = {
            'timestamp': datetime.datetime.now(),
            'exists': exists
        }
        return exists

    def _get_cached_vswitch_existence(self, host):
        """Returns cached existence.

        Expired and non-cached raise ValueError.
        """
        entry = self.ivs_host_cache.get(host)
        if not entry:
            raise ValueError(_('No cache entry for host %s') % host)

        diff = timeutils.delta_seconds(entry['timestamp'],
                                       datetime.datetime.now())
        if diff > CACHE_VSWITCH_TIME:
            self.ivs_host_cache.pop(host)
            raise ValueError(_('Expired cache entry for host %s') % host)
        return entry['exists']
