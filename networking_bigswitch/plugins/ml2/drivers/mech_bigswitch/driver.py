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

import eventlet
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from oslo_utils import excutils
from oslo_utils import timeutils

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as const
from neutron.common import rpc as n_rpc
from neutron import context as ctx
from neutron.extensions import portbindings
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.plugins.common import constants as pconst
from neutron.plugins.ml2 import driver_api as api

from networking_bigswitch.plugins.bigswitch import config as pl_config
from networking_bigswitch.plugins.bigswitch.i18n import _
from networking_bigswitch.plugins.bigswitch.i18n import _LE
from networking_bigswitch.plugins.bigswitch.i18n import _LI
from networking_bigswitch.plugins.bigswitch.i18n import _LW
from networking_bigswitch.plugins.bigswitch import plugin
from networking_bigswitch.plugins.bigswitch import servermanager

from networking_bigswitch.plugins.bigswitch.config import VHOST_USER_SOCKET_DIR
from networking_bigswitch.plugins.bigswitch.config \
    import VIF_DET_BSN_VSWITCH_HOST_ID
from networking_bigswitch.plugins.bigswitch.config import VSwitchType

EXTERNAL_PORT_OWNER = 'neutron:external_port'
ROUTER_GATEWAY_PORT_OWNER = 'network:router_gateway'
LOG = log.getLogger(__name__)
put_context_in_serverpool = plugin.put_context_in_serverpool

# time in seconds to maintain existence of vswitch response
CACHE_VSWITCH_TIME = 60


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
        # Track hosts running IVS to avoid excessive calls to the backend
        self.vswitch_host_cache = {}
        self.setup_sg_rpc_callbacks()

        LOG.debug("Initialization done")

    def setup_sg_rpc_callbacks(self):
        # following way to register call back functions start in kilo
        self._create_sg_f = self.bsn_create_sg_callback
        self._delete_sg_f = self.bsn_delete_sg_callback
        self._update_sg_f = self.bsn_update_sg_callback
        self._create_sg_rule_f = self.bsn_create_sg_rule_callback
        self._delete_sg_rule_f = self.bsn_delete_sg_rule_callback
        registry.subscribe(self._create_sg_f,
                           resources.SECURITY_GROUP, events.AFTER_CREATE)
        registry.subscribe(self._delete_sg_f,
                           resources.SECURITY_GROUP, events.AFTER_DELETE)
        registry.subscribe(self._update_sg_f,
                           resources.SECURITY_GROUP, events.AFTER_UPDATE)
        registry.subscribe(self._create_sg_rule_f,
                           resources.SECURITY_GROUP_RULE, events.AFTER_CREATE)
        registry.subscribe(self._delete_sg_rule_f,
                           resources.SECURITY_GROUP_RULE, events.AFTER_DELETE)

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
            LOG.debug("Callback create sg_id: %s" % sg_id)
            self.bsn_create_security_group(sg_id=sg_id, context=context)

    def bsn_delete_sg_callback(self, resource, event, trigger, **kwargs):
        sg_id = kwargs.get('security_group_id')
        context = kwargs.get('context')
        if sg_id and context:
            LOG.debug("Callback delete sg_id: %s" % sg_id)
            self.bsn_delete_security_group(sg_id=sg_id, context=context)

    def bsn_update_sg_callback(self, resource, event, trigger, **kwargs):
        security_group = kwargs.get('security_group')
        context = kwargs.get('context')
        if security_group and context:
            sg_id = security_group.get('id')
            LOG.debug("Callback update sg_id: %s" % sg_id)
            self.bsn_create_security_group(sg_id=sg_id, context=context)

    def bsn_create_sg_rule_callback(self, resource, event, trigger, **kwargs):
        rule = kwargs.get('security_group_rule')
        context = kwargs.get('context')
        if rule and context:
            sg_id = rule.get('security_group_id')
            LOG.debug("Callback create rule in sg_id: %s" % sg_id)
            self.bsn_create_security_group(sg_id=sg_id, context=context)

    def bsn_delete_sg_rule_callback(self, resource, event, trigger, **kwargs):
        context = kwargs.get('context')
        if context:
            LOG.debug("Callback delete sg_rule belongs to tenant: %s"
                      % context.tenant_id)
            sgs = self.get_security_groups(context, filters={}) or []
            for sg in sgs:
                if sg.get('tenant_id') != context.tenant_id:
                    continue
                sg_id = sg.get('id')
                LOG.debug("Callback delete rule in sg_id: %s" % sg_id)
                # we over write the sg on bcf controller instead of deleting
                try:
                    self.bsn_create_security_group(sg_id=sg_id,
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
        if event_type == 'security_group.create.end':
            LOG.debug("Security group created: %s" % payload)
            self.bsn_create_security_group(sg=payload['security_group'])
        elif event_type == 'security_group.delete.end':
            LOG.debug("Security group deleted: %s" % payload)
            self.bsn_delete_security_group(payload['security_group_id'])
        elif event_type == 'identity.project.deleted':
            LOG.debug("Project deleted: %s" % payload)
            self.bsn_delete_tenant(payload['resource_info'])
        elif event_type == 'identity.project.created':
            LOG.debug("Project created: %s" % payload)
            self.bsn_create_tenant(payload['resource_info'])
        else:
            LOG.debug("Else events: %s payload: %s" % (event_type, payload))

    @put_context_in_serverpool
    def security_groups_rule_updated(self, context, **kwargs):
        # this will get called whenever a security group rule updated message
        # goes onto the RPC bus
        LOG.debug("security_groups_rule_updated: %s" % kwargs)
        if kwargs.get('security_groups'):
            for sg_id in kwargs.get('security_groups'):
                self.bsn_create_security_group(sg_id, context=context)

    @put_context_in_serverpool
    def security_groups_member_updated(self, context, **kwargs):
        pass

    @put_context_in_serverpool
    def security_groups_provider_updated(self, context, **kwargs):
        pass

    @put_context_in_serverpool
    def create_network_postcommit(self, context):
        # create network on the network controller
        self._send_create_network(context.current)

    @put_context_in_serverpool
    def update_network_precommit(self, context):
        self._verify_network_precommit(context)

    @put_context_in_serverpool
    def update_network_postcommit(self, context):
        # update network on the network controller
        self._send_update_network(context.current)

    @put_context_in_serverpool
    def update_subnet_postcommit(self, context):
        self._trigger_network_update_from_subnet_transaction(context)

    @put_context_in_serverpool
    def create_subnet_postcommit(self, context):
        self._trigger_network_update_from_subnet_transaction(context)

    @put_context_in_serverpool
    def delete_subnet_postcommit(self, context):
        self._trigger_network_update_from_subnet_transaction(context)

    def _trigger_network_update_from_subnet_transaction(self, context):
        net = manager.NeutronManager.get_plugin().get_network(
            ctx.get_admin_context(), context.current['network_id'])
        self._send_update_network(net)

    @put_context_in_serverpool
    def delete_network_postcommit(self, context):
        # delete network on the network controller
        self._send_delete_network(context.current)

    @put_context_in_serverpool
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
            manager.NeutronManager.get_plugin().update_port_status(
                context._plugin_context, context.current['id'],
                const.PORT_STATUS_ACTIVE)

        try:
            # create port on the network controller
            port = self._prepare_port_for_controller(context)
        except servermanager.TenantIDNotFound as e:
            LOG.warning(_LW("Skipping create port %(port)s as %(exp)s"),
                        {'port': context.current.get('id'), 'exp': e})
            return

        if port:
            # For vhostuser type ports, membership rule and endpoint was
            # created during bind_port, so skip this
            if port[portbindings.VIF_TYPE] == portbindings.VIF_TYPE_VHOST_USER:
                return

            self.async_port_create(port["network"]["tenant_id"],
                                   port["network"]["id"], port)

    @put_context_in_serverpool
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
            LOG.warning(_LW("Skipping update port %(port)s as %(exp)s"),
                        {'port': context.current.get('id'), 'exp': e})
            return

        if port:
            # For vhostuser type ports, membership rule and endpoint was
            # created during bind_port, so skip this
            if port[portbindings.VIF_TYPE] == portbindings.VIF_TYPE_VHOST_USER:
                return

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
                        LOG.error(_LE("Inconsistency with backend controller "
                                      "triggering full synchronization."))
                        self._send_all_data_auto(
                            triggered_by_tenant=port["network"]["tenant_id"]
                        )

    @put_context_in_serverpool
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
        """
        Make a copy so the context isn't changed for other drivers
        :exception can throw servermanager.TenantIDNotFound
        """
        port = copy.deepcopy(context.current)
        net = context.network.current
        port['network'] = net
        port['bound_segment'] = context.top_bound_segment
        prepped_port = self._map_tenant_name(port)
        prepped_port = self._map_state_and_status(prepped_port)
        prepped_port = self._map_port_hostid(prepped_port, net)
        return prepped_port

    def _bind_port_nfvswitch(self, context, segment, host_id):
        """Perform bind_port for nfvswitch.

        A NFV VM needs to be attached to a nfv-switch socket. So, during
        bind_port() we create a NFV VM endpoint on BCF, thereby reserving the
        socket for it's use. Then pass the sock_path in the set_binding() for
        Nova to plug the VM to the nfv-switch.

        @param context: PortContext object
        """
        vif_type = portbindings.VIF_TYPE_VHOST_USER
        port = self._prepare_port_for_controller(context)
        if not port:
            LOG.warning(_LW("nfv-switch bind_port() skipped due to missing "
                            "Host ID."))
            return

        # Create an endpoint corresponding to the port on the Controller,
        # thereby asking the Controller to reserve a vhost_sock for it
        tenant_id = port["network"]["tenant_id"]
        network_id = port["network"]["id"]
        # Set vif_type to 'vhost_user' for the Controller to reserve vhost_sock
        port[portbindings.VIF_TYPE] = vif_type
        # Update host_id so that endpoint create will have the correct value
        port[portbindings.HOST_ID] = host_id
        try:
            self.async_port_create(tenant_id, network_id, port)
        except servermanager.RemoteRestError as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if (cfg.CONF.RESTPROXY.auto_sync_on_failure and
                        e.status == httplib.NOT_FOUND and
                        servermanager.NXNETWORK in e.reason):
                    ctxt.reraise = False
                    LOG.error(_LE("Inconsistency with backend controller "
                                  "triggering full synchronization."))
                    self._send_all_data_auto(triggered_by_tenant=tenant_id)

        # Retrieve the vhost_socket reserved for the port(endpoint) by the
        # Controller and use it in set_binding()
        resp = self.servers.rest_get_port(tenant_id, network_id, port["id"])
        if not resp or not isinstance(resp, list):
            LOG.warning(_LW("Controller failed to reserve a nfv-switch sock"))
            return

        vhost_sock = None
        attachment_point = resp[0].get('attachment-point')
        if attachment_point:
            vhost_sock = attachment_point.get('interface')

        if not vhost_sock:
            LOG.warning(_LW("Controller failed to reserve a nfv-switch sock"))
            return

        vhost_sock_path = self._get_vhost_user_sock_path(vhost_sock)
        LOG.info(_LI('nfv-switch VM %(port)s alloted sock_path %(sock)s'),
                 {'port': port['id'], 'sock': vhost_sock_path})

        # Update vif_details with host_id. This way, for all BCF
        # communications, we we shall use it as HOST_ID (i.e. interface-group
        # on BCF)
        vif_details = {
                       portbindings.CAP_PORT_FILTER: False,
                       portbindings.VHOST_USER_MODE:
                       portbindings.VHOST_USER_MODE_SERVER,
                       portbindings.VHOST_USER_OVS_PLUG: False,
                       portbindings.VHOST_USER_SOCKET: vhost_sock_path,
                       VIF_DET_BSN_VSWITCH_HOST_ID: host_id
        }
        context.set_binding(segment[api.ID], vif_type, vif_details)

    def _bind_port_ivswitch(self, context, segment, host_id):
        """Perform bind_port for Indigo virtual switch.

        @param context: PortContext object
        """
        vif_type = pl_config.VIF_TYPE_IVS
        vif_details = {
                       portbindings.CAP_PORT_FILTER: True,
                       portbindings.OVS_HYBRID_PLUG: True,
                       VIF_DET_BSN_VSWITCH_HOST_ID: host_id
        }
        context.set_binding(segment[api.ID], vif_type, vif_details)

    @put_context_in_serverpool
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
                if segment[api.NETWORK_TYPE] == pconst.TYPE_VLAN:
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

        # A compute node can have multiple vswitches. They are differentiated
        # on BCF based on the lldps sent by them.
        #   IVS shall be identified as 'HOST'
        #   Others (eg. NFVSwitch) shall be identified as 'HOST'.'PHYSNET'
        #
        # Check each segment to identify the correct vswitch, and set it in
        # vif_details
        for segment in context.segments_to_bind:
            if segment[api.NETWORK_TYPE] == pconst.TYPE_VLAN:
                (vswitch_type, host_id) = self.get_vswitch_type(context.host,
                                                                segment)
                if vswitch_type == VSwitchType.NFVSWITCH:
                    self._bind_port_nfvswitch(context, segment, host_id)
                elif vswitch_type == VSwitchType.VIRTUAL:
                    self._bind_port_ivswitch(context, segment, host_id)

    def get_vswitch_type(self, host, segment=None):
        """Get the virtual switch type on the given host for the given segment
        Check for virtual switch on host.physnet, else check on host.

        @param host: the HOST_ID.
        @param segment: the segment.
        @returns: (vswitch-type, host-id): if vswitch is found on the host.
                  (None, _): otherwise.
        """
        if segment and segment[api.PHYSICAL_NETWORK]:
            physnet = segment[api.PHYSICAL_NETWORK]
            host_physnet = host + "." + physnet
            host_physnet_vswitch_type = self._get_vswitch_type(host_physnet)
            if host_physnet_vswitch_type:
                return (host_physnet_vswitch_type, host_physnet)

        return (self._get_vswitch_type(host), host)

    def _get_vswitch_type(self, host):
        """Get virtual switch type
        Check if a virtual switch exists with the given hostname on BCF, if
        it does, return its type.

        @param host: the HOST_ID.
        @returns: switch-type, if the vswitch is known to BCF.
                  None, if vswitch is unknown to BCF or backend couldn't be
                  reached.
        Caches response from backend.
        """
        try:
            return self._get_cached_vswitch_existence(host)
        except ValueError:
            # cache was empty for that switch or expired
            pass

        switch_type = None
        try:
            resp = self.servers.rest_get_switch(host)
            exists = bool(resp)
            if exists:
                switch_type = resp[0]["fabric-role"]
        except servermanager.RemoteRestError:
            # Connectivity or internal server error. Skip cache to try again on
            # next binding attempt
            return

        self.vswitch_host_cache[host] = {
            'type': switch_type,
            'timestamp': datetime.datetime.now(),
            'exists': exists
        }
        return switch_type

    def _get_cached_vswitch_existence(self, host):
        """Returns cached existence. Expired and non-cached raise ValueError.
        """
        entry = self.vswitch_host_cache.get(host)
        if not entry:
            raise ValueError(_('No cache entry for host %s') % host)

        diff = timeutils.delta_seconds(entry['timestamp'],
                                       datetime.datetime.now())
        if diff > CACHE_VSWITCH_TIME:
            self.vswitch_host_cache.pop(host)
            raise ValueError(_('Expired cache entry for host %s') % host)

        if entry['exists']:
            return entry['type']
        return None

    def _get_vhost_user_sock_path(self, sock):
        """Get the socket path for the vhost_user socket. """
        return VHOST_USER_SOCKET_DIR + str(sock)
