# Copyright 2012 Big Switch Networks, Inc.
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

"""
Neutron REST Proxy Plug-in for Big Switch and FloodLight Controllers.

NeutronRestProxy provides a generic neutron plugin that translates all plugin
function calls to equivalent authenticated REST calls to a set of redundant
external network controllers. It also keeps persistent store for all neutron
state to allow for re-sync of the external controller(s), if required.

The local state on the plugin also allows for local response and fast-fail
semantics where it can be determined based on the local persistent store.

Network controller specific code is decoupled from this plugin and expected
to reside on the controller itself (via the REST interface).

This allows for:
 - independent authentication and redundancy schemes between neutron and the
   network controller
 - independent upgrade/development cycles between neutron and the controller
   as it limits the proxy code upgrade requirement to neutron release cycle
   and the controller specific code upgrade requirement to controller code
 - ability to sync the controller with neutron for independent recovery/reset

External REST API used by proxy is the same API as defined for neutron (JSON
subset) with some additional parameters (gateway on network-create and macaddr
on port-attach) on an additional PUT to do a bulk dump of all persistent data.
"""

import copy
import functools
import httplib
import re

import eventlet
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import importutils
from sqlalchemy.orm import exc as sqlexc

from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api import extensions as neutron_extensions
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.rpc.handlers import securitygroups_rpc
from neutron.common import rpc as n_rpc
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import l3_db
from neutron.db.models import securitygroup as sg_db
from neutron.db import models_v2
from neutron.db import securitygroups_rpc_base as sg_db_rpc

from neutron_lib.agent import topics
from neutron_lib.api.definitions import allowedaddresspairs as addr_pair
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as const
from neutron_lib import context as qcontext
from neutron_lib.db import api as lib_db_api
from neutron_lib import exceptions as lib_exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.utils import runtime

from networking_bigswitch.plugins.bigswitch import config as pl_config
from networking_bigswitch.plugins.bigswitch import constants as bsn_constants
from networking_bigswitch.plugins.bigswitch.db import porttracker_db
from networking_bigswitch.plugins.bigswitch import extensions
from networking_bigswitch.plugins.bigswitch.i18n import _
from networking_bigswitch.plugins.bigswitch.i18n import _LW
from networking_bigswitch.plugins.bigswitch import servermanager
from networking_bigswitch.plugins.bigswitch.utils import Util
from networking_bigswitch.plugins.bigswitch import version

LOG = logging.getLogger(__name__)

SYNTAX_ERROR_MESSAGE = _('Syntax error in server config file, aborting plugin')
METADATA_SERVER_IP = '169.254.169.254'


class AgentNotifierApi(securitygroups_rpc.SecurityGroupAgentRpcApiMixin):

    def __init__(self, topic):
        self.topic = topic
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def port_update(self, context, port):
        topic_port_update = topics.get_topic_name(self.client.target.topic,
                                                  topics.PORT, topics.UPDATE)
        cctxt = self.client.prepare(fanout=True, topic=topic_port_update)
        cctxt.cast(context, 'port_update', port=port)


class SecurityGroupServerRpcMixin(sg_db_rpc.SecurityGroupServerRpcMixin):

    def get_port_from_device(self, context, device):
        port_id = re.sub(r"^%s" % const.TAP_DEVICE_PREFIX, "", device)
        port = self.get_port_and_sgs(context, port_id)
        if port:
            port['device'] = device
        return port

    def get_port_and_sgs(self, context, port_id):
        """Get port from database with security group info."""

        LOG.debug("get_port_and_sgs() called for port_id %s", port_id)
        sg_binding_port = sg_db.SecurityGroupPortBinding.port_id

        with db.context_manager.reader.using(context):
            query = context.session.query(
                models_v2.Port,
                sg_db.SecurityGroupPortBinding.security_group_id
            )
            query = query.outerjoin(sg_db.SecurityGroupPortBinding,
                                    models_v2.Port.id == sg_binding_port)
            query = query.filter(models_v2.Port.id.startswith(port_id))
            port_and_sgs = query.all()
            if not port_and_sgs:
                return
            port = port_and_sgs[0][0]
            plugin = directory.get_plugin()
            port_dict = plugin._make_port_dict(port)
            port_dict['security_groups'] = [
                sg_id for port_, sg_id in port_and_sgs if sg_id]
            port_dict['security_group_rules'] = []
            port_dict['security_group_source_groups'] = []
            port_dict['fixed_ips'] = [ip['ip_address']
                                      for ip in port['fixed_ips']]
        return port_dict


class NeutronRestProxyV2Base(db_base_plugin_v2.NeutronDbPluginV2,
                             external_net_db.External_net_db_mixin,
                             SecurityGroupServerRpcMixin,
                             agentschedulers_db.DhcpAgentSchedulerDbMixin):

    supported_extension_aliases = ["binding"]
    servers = None

    def __init__(self):
        super(NeutronRestProxyV2Base, self).__init__()
        self._setup_rpc()

    def _setup_rpc(self):
        self.conn = n_rpc.Connection()
        self.topic = topics.PLUGIN
        self.notifier = AgentNotifierApi(topics.AGENT)
        # init dhcp agent support
        self._dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            self._dhcp_agent_notifier
        )
        self.endpoints = [agent_rpc.PluginApi(self.topic),
                          securitygroups_rpc.SecurityGroupServerRpcCallback(),
                          dhcp_rpc.DhcpRpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        # Consume from all consumers in threads
        self.conn.consume_in_threads()

    @property
    def l3_plugin(self):
        return directory.get_plugin(plugin_constants.L3)

    @property
    def l3_bsn_plugin(self):
        return hasattr(self.l3_plugin, "bsn")

    @property
    def bsn_service_plugin(self):
        return directory.get_plugin(bsn_constants.BSN_SERVICE_PLUGIN)

    def _validate_names(self, obj, name=None):
        """validate names

        :returns
            True, if obj name, obj's tenant name and name have supported chars
            False, otherwise
        """

        if self.servers.is_unicode_enabled():
            return True

        if name and not servermanager.is_valid_bcf_name(name):
            LOG.warning('Unsupported characters in Name: %(name)s. ',
                        {'name': name})
            return False

        if (obj and 'name' in obj and
                not servermanager.is_valid_bcf_name(obj['name'])):
            LOG.warning('Unsupported characters in Name: %(name)s. '
                        'Object details: %(obj)s',
                        {'name': obj['name'], 'obj': obj})
            return False

        if (obj and 'tenant_name' in obj and
                not servermanager.is_valid_bcf_name(obj['tenant_name'])):
            LOG.warning('Unsupported characters in TenantName: %(tname)s. '
                        'Object details: %(obj)s',
                        {'tname': obj['tenant_name'], 'obj': obj})
            return False

        return True

    def _get_all_data_auto(self):
        return self._get_all_data(
            get_floating_ips=self.l3_bsn_plugin,
            get_routers=self.l3_bsn_plugin,
            get_sgs=True)

    def _get_all_data(self, get_ports=True, get_floating_ips=True,
                      get_routers=True, get_sgs=True):
        # sync tenant cache with keystone
        if not self.servers._update_tenant_cache(reconcile=False):
            return None

        admin_context = qcontext.get_admin_context()
        networks = []
        # this method is used by the ML2 driver so it can't directly invoke
        # the self.get_(ports|networks) methods
        plugin = directory.get_plugin()
        all_networks = plugin.get_networks(admin_context) or []
        for net in all_networks:
            try:
                if self._skip_bcf_network_event(net):
                    LOG.info('Skipping segment create for Network: %(n)s',
                             {'n': net.get('name')})
                    continue

                mapped_network = self._get_mapped_network_with_subnets(net)
                if not self._validate_names(mapped_network):
                    continue
                # validate names for subnet as well
                if 'subnets' in mapped_network:
                    new_subnets = []
                    for subnet in mapped_network['subnets']:
                        if not self._validate_names(subnet):
                            continue
                        new_subnets.append(subnet)
                    mapped_network['subnets'] = new_subnets

                flips_n_ports = mapped_network
                if get_floating_ips:
                    flips_n_ports = self._get_network_with_floatingips(
                        mapped_network)

                if get_ports:
                    ports = []
                    net_filter = {'network_id': [net.get('id')]}
                    net_ports = plugin.get_ports(admin_context,
                                                 filters=net_filter) or []
                    for port in net_ports:
                        if not self._is_port_supported(port):
                            continue
                        # skip L3 router ports since the backend
                        # implements the router
                        if (self.l3_bsn_plugin and
                            port.get('device_owner') in
                            [const.DEVICE_OWNER_ROUTER_GW,
                             const.DEVICE_OWNER_ROUTER_HA_INTF]):
                            continue
                        mapped_port = self._map_display_name_or_tenant(port)
                        if self.servers.is_unicode_enabled():
                            # remove port name so that it won't be stored in
                            #  description
                            mapped_port['name'] = None
                        mapped_port = self._map_state_and_status(mapped_port)
                        mapped_port = self._map_port_hostid(mapped_port, net)
                        if not mapped_port:
                            continue

                        mapped_port['attachment'] = {
                            'id': port.get('device_id'),
                            'mac': port.get('mac_address'),
                        }
                        ports.append(mapped_port)
                    flips_n_ports['ports'] = ports

                if flips_n_ports:
                    networks.append(flips_n_ports)
            except servermanager.TenantIDNotFound:
                # if tenant name is not known to keystone, skip the network
                continue

        data = {'networks': networks}

        if get_routers and self.l3_plugin:
            routers = []
            all_routers = self.l3_plugin.get_routers(admin_context) or []
            all_policies = (self.bsn_service_plugin
                            .get_tenantpolicies(admin_context)
                            if self.bsn_service_plugin else [])
            tenant_policies = {}
            for policy in all_policies:
                if policy['tenant_id'] not in tenant_policies:
                    tenant_policies[policy['tenant_id']] = []
                policy['ipproto'] = policy['protocol']
                tenant_policies[policy['tenant_id']].append(policy)
            for router in all_routers:
                try:
                    # Add tenant_id of the external gateway network
                    if router.get(l3_apidef.EXTERNAL_GW_INFO):
                        ext_net_id = router[l3_apidef.EXTERNAL_GW_INFO].get(
                            'network_id')
                        ext_net = self.get_network(admin_context, ext_net_id)
                        ext_tenant_id = ext_net.get('tenant_id')
                        if ext_tenant_id:
                            router[l3_apidef.EXTERNAL_GW_INFO]['tenant_id'] = (
                                ext_tenant_id)

                    interfaces = []
                    mapped_router = self._map_display_name_or_tenant(router)
                    mapped_router = self._map_state_and_status(mapped_router)
                    if not self._validate_names(mapped_router):
                        continue

                    router_filter = {
                        'device_owner': [const.DEVICE_OWNER_ROUTER_INTF],
                        'device_id': [router.get('id')]
                    }
                    router_ports = self.get_ports(admin_context,
                                                  filters=router_filter) or []
                    for port in router_ports:
                        subnet_id = port['fixed_ips'][0]['subnet_id']
                        intf_details = self._get_router_intf_details(
                            admin_context, port, subnet_id)

                        interfaces.append(intf_details)

                    mapped_router['interfaces'] = interfaces

                    routers.append(mapped_router)
                except servermanager.TenantIDNotFound:
                    # if tenant name is not known to keystone, skip the network
                    continue

            # append router_tenant_rules to each router
            for router in routers:
                if router['tenant_id'] in tenant_policies:
                    router['policies'] = tenant_policies[router['tenant_id']]

            data.update({'routers': routers})

            # L3 plugin also includes tenant policies
            # data.update({'policies': tenant_policies})

        if (get_sgs and self.l3_plugin
                and cfg.CONF.RESTPROXY.sync_security_groups):
            sgs = plugin.get_security_groups(admin_context) or []
            new_sgs = []
            for sg in sgs:
                try:
                    mapped_sg = self._map_display_name_or_tenant(sg)
                    if not self._validate_names(mapped_sg):
                        continue
                    if 'description' in mapped_sg:
                        mapped_sg['description'] = ''
                    if self.servers.is_unicode_enabled():
                        mapped_sg['name'] = None
                    else:
                        mapped_sg['name'] = Util.format_resource_name(
                            mapped_sg['name'])
                    new_sgs.append(mapped_sg)
                except servermanager.TenantIDNotFound:
                    # if tenant name is not known to keystone, skip the sg
                    continue

            data.update({'security-groups': new_sgs})

        all_tenants_map = self.servers.keystone_tenants

        if self.servers.is_unicode_enabled():
            # display-name is only supported as list for topology in NSAPI
            tenants = []
            for tenant_id, tenant_name in all_tenants_map.items():
                tenants.append({
                    'name': tenant_id,
                    'id': tenant_id,
                    'display-name': tenant_name
                })
        else:
            # dict for tenant works in topology sync only if display-name is
            # not enabled
            tenants = {}
            for tenant in all_tenants_map:
                if not self._validate_names(None,
                                            name=all_tenants_map[tenant]):
                    continue
                tenants[tenant] = all_tenants_map[tenant]

        data['tenants'] = tenants
        return data

    def _send_all_data_auto(self, timeout=None, triggered_by_tenant=None):
        return self._send_all_data(
            send_floating_ips=self.l3_bsn_plugin,
            send_routers=self.l3_bsn_plugin,
            timeout=timeout,
            triggered_by_tenant=triggered_by_tenant)

    def _send_all_data(self, send_ports=True, send_floating_ips=True,
                       send_routers=True, send_sgs=True, timeout=None,
                       triggered_by_tenant=None):
        """Pushes all data to network ctrl (networks/ports, ports/attachments).

        This gives the controller an option to re-sync it's persistent store
        with neutron's current view of that data.

        All args are ignored. The `_get_all_data` method dynamically pulls the
        relevant information i.e. if its L2 only or L2+L3.
        """
        sync_executed, topo_resp = self.servers.force_topo_sync()
        return topo_resp

    def _assign_resource_to_service_tenant(self, resource):
        resource['tenant_id'] = (resource['tenant_id'] or
                                 servermanager.SERVICE_TENANT)

        if not self.servers.is_unicode_enabled():
            if resource.get('name'):
                # resource name may contain space. Replace space with -
                resource['name'] = Util.format_resource_name(resource['name'])

    def _get_network_with_floatingips(self, network, context=None):
        if context is None:
            context = qcontext.get_admin_context()

        net_id = network['id']
        net_filter = {'floating_network_id': [net_id]}
        if self.l3_plugin:
            fl_ips = self.l3_plugin.get_floatingips(context,
                                                    filters=net_filter) or []
            floating_ips = []
            for flip in fl_ips:
                try:
                    # BVS-7525: the 'tenant_id' in a floating-ip represents the
                    # tenant to which it is allocated.
                    # Validate that the tenant exists
                    # name/display-name of floating ip is not actually
                    # used on bcf
                    mapped_flip = self._map_display_name_or_tenant(flip)
                    if mapped_flip.get('floating_port_id'):
                        fport = self.get_port(context,
                                              mapped_flip['floating_port_id'])
                        mapped_flip['floating_mac_address'] = \
                            fport.get('mac_address')
                    floating_ips.append(mapped_flip)
                except servermanager.TenantIDNotFound:
                    # if tenant name is not known to keystone, skip it
                    continue

            network['floatingips'] = floating_ips

        return network

    def _get_all_subnets_json_for_network(self, net_id, context=None):
        if context is None:
            context = qcontext.get_admin_context()
        # start a sub-transaction to avoid breaking parent transactions
        with db.context_manager.writer.using(context):
            subnets = self._get_subnets_by_network(context,
                                                   net_id)
        subnets_details = []
        if subnets:
            for subnet in subnets:
                subnet_dict = self._make_subnet_dict(subnet, context=context)
                mapped_subnet = self._map_display_name_or_tenant(subnet_dict)
                mapped_subnet = self._map_state_and_status(mapped_subnet)
                subnets_details.append(mapped_subnet)

        return subnets_details

    def _tenant_check_for_security_group(self, sg):
        """Router VRRP creates a hidden network for router heart-beats.

        This network is not associated with any tenant
        """
        sg['tenant_id'] = sg['tenant_id'] or servermanager.SERVICE_TENANT
        tenant_name = self.servers.keystone_tenants.get(sg['tenant_id'])

        if not tenant_name:
            self.servers._update_tenant_cache(reconcile=True)
            tenant_name = self.servers.keystone_tenants.get(sg['tenant_id'])

        if not self.servers.is_unicode_enabled():
            sg['tenant_name'] = tenant_name
        return tenant_name

    def bsn_create_security_group(self, sg_id=None, sg=None, context=None):
        if sg_id:
            if not hasattr(context, 'session'):
                context = qcontext.get_admin_context()
            # overwrite sg if both sg and sg_id are given
            sg = self.get_security_group(context, sg_id)

        if sg:
            if self.servers.is_unicode_enabled():
                sg['display-name'] = sg['name']
                sg['name'] = None
            else:
                sg['name'] = Util.format_resource_name(sg['name'])
            # remove description as its not used
            if sg.get('description'):
                del(sg['description'])
            # check and map tenant_name for sg
            tenant_name = self._tenant_check_for_security_group(sg)
            # skip the security group if its tenant is unknown
            if tenant_name:
                if tenant_name == servermanager.SERVICE_TENANT:
                    self.bsn_create_tenant(servermanager.SERVICE_TENANT,
                                           context=context)
                self.servers.rest_create_securitygroup(sg)
        else:
            LOG.warning(_LW("No security group is provided for creation."))

    def bsn_delete_security_group(self, sg_id, context=None):
        self.servers.rest_delete_securitygroup(sg_id)

    def bsn_create_tenant(self, tenant_id, context=None):
        self.servers.rest_create_tenant(tenant_id)

    def bsn_delete_tenant(self, tenant_id, context=None):
        self.servers.rest_delete_tenant(tenant_id)

    def _verify_network_precommit(self, context):
        if not self.servers.is_unicode_enabled():
            if context.current['name'] != context.original['name']:
                raise servermanager.NetworkNameChangeError()

    def _get_mapped_network_with_subnets(self, network, context=None):
        # if context is not provided, admin context is used
        if context is None:
            context = qcontext.get_admin_context()
        network = self._map_display_name_or_tenant(network)
        network = self._map_state_and_status(network)
        subnets = self._get_all_subnets_json_for_network(network['id'],
                                                         context)
        network['subnets'] = subnets
        for subnet in (subnets or []):
            if subnet['gateway_ip']:
                # FIX: For backward compatibility with wire protocol
                network['gateway'] = subnet['gateway_ip']
                break
        else:
            network['gateway'] = ''
        network[extnet_apidef.EXTERNAL] = self._network_is_external(
            context, network['id'])
        # include ML2 segmentation types
        network['segmentation_types'] = getattr(self, "segmentation_types", "")
        # OSP-45: remove name to avoid NSAPI error in convertToAscii
        for subnet in (subnets or []):
            subnet.pop('name', None)

        return network

    def _skip_bcf_network_event(self, network):
        '''Check if the network event needs to be sent to BCF

        return true, if event should be skipped, i.e. not be sent to BCF
               false, otherwise
       '''
        pnet = network.get(pl_config.PROVIDER_PHYSNET)
        if pnet and pl_config.SRIOV_ACTIVE_ACTIVE_MODE_PHYSNET_SUBSTR in pnet:
            # Configure BCF segment only for networks on ACTIVE physnet
            if not pnet.endswith(pl_config.SRIOV_ACTIVE_PHYSNET):
                return True
        return False

    def _send_create_network(self, network, context=None):
        tenant_id = network['tenant_id']
        if self._skip_bcf_network_event(network):
            LOG.info('Skipping BCF segment create for Network: %(name)s',
                     {'name': network.get('name')})
            return

        if context is None:
            context = qcontext.get_admin_context()
        filters = {'name': ['default'], 'tenant_id': [tenant_id]}
        if cfg.CONF.RESTPROXY.sync_security_groups:
            default_group = self.get_security_groups(
                context, filters, default_sg=True)
            if default_group:
                # VRRP tenant doesn't have tenant_id
                self.bsn_create_security_group(sg=default_group[0])
        # display-name is also mapped here
        mapped_network = self._get_mapped_network_with_subnets(network,
                                                               context)

        if not tenant_id:
            tenant_id = servermanager.SERVICE_TENANT
            mapped_network['tenant_id'] = servermanager.SERVICE_TENANT
            if not self.servers.is_unicode_enabled():
                mapped_network['name'] = Util.format_resource_name(
                    mapped_network['name'])
            self.bsn_create_tenant(servermanager.SERVICE_TENANT,
                                   context=context)
        self.servers.rest_create_network(tenant_id, mapped_network)

    def _send_update_network(self, network, context=None):
        net_id = network['id']
        tenant_id = network['tenant_id']
        if self._skip_bcf_network_event(network):
            LOG.info('Skipping BCF segment update for Network: %(name)s',
                     {'name': network.get('name')})
            return

        # display-name is also mapped here
        mapped_network = self._get_mapped_network_with_subnets(network,
                                                               context)
        net_fl_ips = self._get_network_with_floatingips(mapped_network,
                                                        context)
        if not tenant_id:
            tenant_id = servermanager.SERVICE_TENANT
            net_fl_ips['tenant_id'] = servermanager.SERVICE_TENANT
            if not self.servers.is_unicode_enabled():
                net_fl_ips['name'] = Util.format_resource_name(
                    net_fl_ips['name'])
        self.servers.rest_update_network(tenant_id, net_id, net_fl_ips)

    def _send_delete_network(self, network, context=None):
        net_id = network['id']
        tenant_id = network['tenant_id'] or servermanager.SERVICE_TENANT
        self.servers.rest_delete_network(tenant_id, net_id)

    def _map_display_name_or_tenant(self, resource):
        """This maps tenant_name or display-name for an object

        None-unicode mode uses tenant_name
        Unicode mode uses tenant_id and display-name

        :param resource: object to be mapped
        :return: mapped object copy
        """
        resource = copy.deepcopy(resource)
        self._assign_resource_to_service_tenant(resource)

        tenant_name = self.servers.keystone_tenants.get(resource['tenant_id'])
        if not tenant_name:
            self.servers._update_tenant_cache()
            tenant_name = self.servers.keystone_tenants.get(
                resource['tenant_id'])
            if not tenant_name:
                raise servermanager.TenantIDNotFound(
                    tenant=resource['tenant_id'])

        if self.servers.is_unicode_enabled():
            if resource.get('name'):
                resource['display-name'] = resource['name']
            # cases like network needs the name on bcf side
            resource['name'] = resource['id']
        else:
            resource['tenant_name'] = tenant_name

        return resource

    def _map_state_and_status(self, resource):
        resource = copy.copy(resource)
        resource['state'] = ('UP' if resource.pop('admin_state_up',
                                                  True) else 'DOWN')
        resource.pop('status', None)

        return resource

    def _is_port_supported(self, port):
        """Check if the vnic-type is supported

        :return: True, if port is supported
                 False, otherwise
        """
        vnic_type = port.get(portbindings.VNIC_TYPE)
        if vnic_type and vnic_type in pl_config.UNSUPPORTED_VNIC_TYPES:
            return False
        return True

    def _is_port_sriov(self, port):
        """Check if port is an SR-IOV port

        :return: True, if port is an SR-IOV port
                 False, otherwise
        """
        vnic_type = port.get(portbindings.VNIC_TYPE)
        if vnic_type and vnic_type in pl_config.VNIC_TYPE_SRIOV:
            return True
        return False

    def _sriov_port_validation_active_active(self, port, network):
        """For SR-IOV port, we configure 'memeber interface-group $HOSTID' on BCF.

        In Active-Active mode, this is done ONLY for ports belonging to the
        ACTIVE physnet. In Active-Backup mode, this is done for all ports.

        :param port:
        :param network:
        :return: boolean value whether it passed or failed
        """
        network_type = network.get(pl_config.PROVIDER_NETWORK_TYPE)
        if not network_type or network_type != const.TYPE_VLAN:
            return False

        physnet = network.get(pl_config.PROVIDER_PHYSNET)
        if not physnet:
            return False

        if pl_config.SRIOV_ACTIVE_ACTIVE_MODE_PHYSNET_SUBSTR in physnet:
            # Active-Active mode, configure BCF only for ACTIVE physnet
            if not physnet.endswith(pl_config.SRIOV_ACTIVE_PHYSNET):
                return False

        return True

    def _is_port_sriov_vm_detach(self, port, network):
        """We allow empty host_id field during update_port_postcommit.

        This is a check to see if the port is SRIOV port and a case of VM
        detach. If yes, we send a delete_port to the BCF controller for that
        port. Otherwise return false and do nothing for the port.

        :param port:
        :param network:
        :return: boolean value specifying if port is sriov_vm_detach case
        """
        # if port is SRIOV and unbound, it is VM detach
        if self._is_port_sriov(port):
            if not self._sriov_port_validation_active_active(port, network):
                return False

            vif_type = port.get(portbindings.VIF_TYPE)
            if not vif_type:
                return False
            elif vif_type == portbindings.VIF_TYPE_UNBOUND:
                return True
        return False

    def _get_sriov_port_hostid(self, port, network):
        """Return the HostID for the given SR-IOV port

        For SR-IOV port, we configure 'memeber interface-group $HOSTID' on BCF.
        In Active-Active mode, this is done ONLY for ports belonging to the
        ACTIVE physnet. In Active-Backup mode, this is done for all ports.
        HostID = $(H)-$(PHYSNET), which corresponds to interface-groups on BCF.

        :return: HostID, if membership-rule needs to be configured on BCF
                 None, otherwise
        """
        if not self._sriov_port_validation_active_active(port, network):
            return None
        physnet = network.get(pl_config.PROVIDER_PHYSNET)
        bsn_host_id = port.get(portbindings.HOST_ID) + '-' + physnet
        return bsn_host_id

    def _get_ovs_dpdk_port_hostid(self, port, network):
        """Return HostID with bridge_name appended for OVS and DPDK ports

        VIF type for OVS and DPDK ports is OVS and VHOSTUSER respectively.

        :param port:
        :param network:
        :return: new_host_id
        """
        host_id = port.get(portbindings.HOST_ID)
        physnet = network.get(pl_config.PROVIDER_PHYSNET)
        if physnet not in self.bridge_mappings:
            LOG.warning(_LW("Physical network to bridge mapping not "
                            "found for port %s."), port)
            return host_id

        bridge_name = self.bridge_mappings.get(physnet)
        host_id_bridge_name = host_id + '_' + bridge_name
        return host_id_bridge_name

    def _map_port_hostid(self, port, network):
        """Update the HOST_ID of a given port based on it's type.

        Perform basic sanity checks and update the HOST_ID of the port
        :return: port, if port is of relevance to BCF
                 False, otherwise
        """
        prepped_port = copy.copy(port)
        if (portbindings.HOST_ID not in prepped_port or
                prepped_port[portbindings.HOST_ID] == ''):
            LOG.debug("Ignoring port notification to controller because of "
                      "missing host ID.")
            return False

        # Update HOST_ID (to be used by BCF).
        # - For SR-IOV it is a function of HostID & physnet info
        if self._is_port_sriov(prepped_port):
            vif_type = prepped_port.get(portbindings.VIF_TYPE)
            if not vif_type or vif_type == portbindings.VIF_TYPE_UNBOUND:
                # Port not bound yet, nothing to do
                return False

            hostid = self._get_sriov_port_hostid(prepped_port, network)
            if not hostid:
                return False
            prepped_port[portbindings.HOST_ID] = hostid

        # update HOST_ID to '<host-id>_<bridge-name>' for ports with
        # VIF_TYPE OVS and VHOSTUSER i.e. DHCP and DPDK ports
        # if bridge_name not available, sets it to just 'host-id'
        vif_type = prepped_port.get(portbindings.VIF_TYPE)
        if (vif_type and
                (vif_type == portbindings.VIF_TYPE_OVS
                 or vif_type == portbindings.VIF_TYPE_VHOST_USER)):
            prepped_port[portbindings.HOST_ID] = (
                self._get_ovs_dpdk_port_hostid(prepped_port, network))

        return prepped_port

    def _warn_on_state_status(self, resource):
        if resource.get('admin_state_up', True) is False:
            LOG.warning("Setting admin_state_up=False is not supported "
                        "in this plugin version. Ignoring setting for "
                        "resource: %s", resource)

        if 'status' in resource:
            if resource['status'] != const.NET_STATUS_ACTIVE:
                LOG.warning("Operational status is internally set by the "
                            "plugin. Ignoring setting status=%s.",
                            resource['status'])

    def _get_router_intf_details(self, context, port, subnet_id):

        # we will use the network id as interface's id
        subnet = self.get_subnet(context, subnet_id)
        net_id = subnet['network_id']
        network = self.get_network(context, net_id)
        mapped_network = self._get_mapped_network_with_subnets(network)
        mapped_subnet = self._map_display_name_or_tenant(subnet)
        mapped_subnet = self._map_state_and_status(mapped_subnet)

        data = {
            'id': subnet_id,
            "network": mapped_network,
            "subnet": mapped_subnet
        }

        # get gateway_ip from port instead of gateway_ip
        if port.get("fixed_ips"):
            data['ip_address'] = port["fixed_ips"][0]['ip_address']

        return data

    def _extend_port_dict_binding(self, context, port):
        cfg_vif_type = cfg.CONF.NOVA.vif_type.lower()
        if cfg_vif_type not in (portbindings.VIF_TYPE_OVS,
                                pl_config.VIF_TYPE_IVS):
            LOG.warning("Unrecognized vif_type in configuration "
                        "[%s]. Defaulting to ovs.",
                        cfg_vif_type)
            cfg_vif_type = portbindings.VIF_TYPE_OVS
        # In ML2, the host_id is already populated
        if portbindings.HOST_ID in port:
            hostid = port[portbindings.HOST_ID]
        elif 'id' in port:
            hostid = porttracker_db.get_port_hostid(context, port['id'])
        else:
            hostid = None
        if hostid:
            port[portbindings.HOST_ID] = hostid
            override = self._check_hostvif_override(hostid)
            if override:
                cfg_vif_type = override
        port[portbindings.VIF_TYPE] = cfg_vif_type

        sg_enabled = sg_rpc.is_firewall_enabled()
        port[portbindings.VIF_DETAILS] = {
            # TODO(rkukura): Replace with new VIF security details
            portbindings.CAP_PORT_FILTER:
            'security-group' in self.supported_extension_aliases,
            portbindings.OVS_HYBRID_PLUG: sg_enabled
        }
        return port

    def _check_hostvif_override(self, hostid):
        for v in cfg.CONF.NOVA.vif_types:
            if hostid in getattr(cfg.CONF.NOVA, "node_override_vif_" + v, []):
                return v
        return False

    def _get_port_net_tenantid(self, context, port):
        net = super(NeutronRestProxyV2Base,
                    self).get_network(context, port["network_id"])
        return net['tenant_id']

    def _add_service_tenant_to_port(self, port):
        port['tenant_id'] = port['tenant_id'] or servermanager.SERVICE_TENANT

        if 'network' in port:
            port['network']['tenant_id'] = (
                port['network']['tenant_id'] or servermanager.SERVICE_TENANT)

    def async_port_create(self, tenant_id, net_id, port, update_status=True):
        try:
            tenant_id = tenant_id or servermanager.SERVICE_TENANT
            rest_port = copy.deepcopy(port)
            self._add_service_tenant_to_port(rest_port)
            self.servers.rest_create_port(tenant_id, net_id, rest_port)
        except servermanager.RemoteRestError as e:
            # 404 should never be received on a port create unless
            # there are inconsistencies between the data in neutron
            # and the data in the backend.
            # Run a sync to get it consistent.
            if (cfg.CONF.RESTPROXY.auto_sync_on_failure and
                    e.status == httplib.NOT_FOUND and
                    servermanager.NXNETWORK in e.reason):
                LOG.error("Inconsistency with backend controller "
                          "triggering full synchronization.")
                # args depend on if we are operating in ML2 driver
                # or as the full plugin
                self._send_all_data_auto(triggered_by_tenant=tenant_id)
                # If the full sync worked, the port will be created
                # on the controller so it can be safely marked as active
            else:
                # Any errors that don't result in a successful auto-sync
                # require that the port be placed into the error state.
                LOG.error(
                    "NeutronRestProxyV2: Unable to create port: %s", e)
                try:
                    self._set_port_status(port['id'], const.PORT_STATUS_ERROR)
                except lib_exceptions.PortNotFound:
                    # If port is already gone from DB and there was an error
                    # creating on the backend, everything is already consistent
                    pass
                return

        if not update_status:
            return

        new_status = (const.PORT_STATUS_ACTIVE if port['state'] == 'UP'
                      else const.PORT_STATUS_DOWN)
        try:
            self._set_port_status(port['id'], new_status)
        except lib_exceptions.PortNotFound:
            # This port was deleted before the create made it to the controller
            # so it now needs to be deleted since the normal delete request
            # would have deleted an non-existent port.
            tenant_id = tenant_id or servermanager.SERVICE_TENANT
            self.servers.rest_delete_port(tenant_id, net_id, port['id'])

    # NOTE(kevinbenton): workaround for eventlet/mysql deadlock
    @runtime.synchronized('bsn-port-barrier')
    def _set_port_status(self, port_id, status):
        session = lib_db_api.get_writer_session()
        try:
            port = session.query(models_v2.Port).filter_by(id=port_id).one()
            port['status'] = status
            session.flush()
        except sqlexc.NoResultFound:
            raise lib_exceptions.PortNotFound(port_id=port_id)


def add_debug_log(f):
    @functools.wraps(f)
    def wrapper(self, context, *args, **kwargs):
        # core plugin: context is top level object
        # Do not need context in header anymore
        LOG.debug("Function: %(fname)s called", {'fname': f.__name__})
        return f(self, context, *args, **kwargs)
    return wrapper


class NeutronRestProxyV2(NeutronRestProxyV2Base,
                         addr_pair_db.AllowedAddressPairsMixin,
                         extradhcpopt_db.ExtraDhcpOptMixin):

    _supported_extension_aliases = ["external-net", "binding",
                                    "extra_dhcp_opt", "quotas",
                                    "dhcp_agent_scheduler", "agent",
                                    "security-group", "allowed-address-pairs"]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_by_config(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self):
        super(NeutronRestProxyV2, self).__init__()
        LOG.info('NeutronRestProxy: Starting plugin. Version=%s',
                 version.version_string_with_vcs())
        pl_config.register_config()
        self.evpool = eventlet.GreenPool(cfg.CONF.RESTPROXY.thread_pool_size)

        # Include the Big Switch Extensions path in the api_extensions
        neutron_extensions.append_api_extensions_path(extensions.__path__)

        self.add_meta_server_route = cfg.CONF.RESTPROXY.add_meta_server_route

        # init network ctrl connections
        self.servers = servermanager.ServerPool()
        self.servers.get_topo_function = self._get_all_data
        self.servers.get_topo_function_args = {'get_ports': True,
                                               'get_floating_ips': True,
                                               'get_routers': True,
                                               'get_sgs': True}

        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )

        # setup rpc for security and DHCP agents
        self._setup_rpc()

        if cfg.CONF.RESTPROXY.sync_data:
            self._send_all_data_auto()

        self.add_periodic_dhcp_agent_status_check()
        LOG.debug("NeutronRestProxyV2: initialization done")

    @db.context_manager.writer
    @add_debug_log
    def create_network(self, context, network):
        """Create a network.

        Network represents an L2 network segment which can have a set of
        subnets and ports associated with it.

        :param context: neutron api request context
        :param network: dictionary describing the network

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can specify
                         a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: RemoteRestError
        """
        self._warn_on_state_status(network['network'])

        self._ensure_default_security_group(
            context,
            network['network']["tenant_id"]
        )
        # create network in DB
        new_net = super(NeutronRestProxyV2, self).create_network(context,
                                                                 network)
        self._process_l3_create(context, new_net, network['network'])
        # create network on the network controller
        self._send_create_network(new_net, context)

        # return created network
        return new_net

    @db.context_manager.writer
    @add_debug_log
    def update_network(self, context, net_id, network):
        """Updates the properties of a particular Virtual Network.

        :param context: neutron api request context
        :param net_id: uuid of the network to update
        :param network: dictionary describing the updates

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can
                         specify a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        self._warn_on_state_status(network['network'])

        new_net = super(NeutronRestProxyV2, self).update_network(
            context, net_id, network)
        self._process_l3_update(context, new_net, network['network'])

        # update network on network controller
        self._send_update_network(new_net, context)
        return new_net

    @db.context_manager.writer
    @add_debug_log
    def delete_network(self, context, net_id):
        """Delete a network.

        :param context: neutron api request context
        :param id: UUID representing the network to delete.

        :returns: None

        :raises: exceptions.NetworkInUse
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        # Validate args
        orig_net = super(NeutronRestProxyV2, self).get_network(context, net_id)

        self._process_l3_delete(context, net_id)
        ret_val = super(NeutronRestProxyV2, self).delete_network(context,
                                                                 net_id)
        self._send_delete_network(orig_net, context)
        return ret_val

    @add_debug_log
    def create_port(self, context, port):
        """Create a port.

        create a port, which is a connection point of a device
        (e.g., a VM NIC) to attach an L2 Neutron network.
        :param context: neutron api request context
        :param port: dictionary describing the port

        :returns:
        {
            "id": uuid representing the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": Sets admin state of port. if down, port
                              does not forward packets.
            "status": dicates whether port is currently operational
                      (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet IDs and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.NetworkNotFound
        :raises: exceptions.StateInvalid
        :raises: RemoteRestError
        """
        # Update DB in new session so exceptions rollback changes
        with db.context_manager.writer.using(context):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            # non-router port status is set to pending. it is then updated
            # after the async rest call completes. router ports are synchronous
            if port['port']['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_INTF:
                port['port']['status'] = const.PORT_STATUS_ACTIVE
            elif not port['port'].get('status'):
                port['port']['status'] = const.PORT_STATUS_BUILD
            dhcp_opts = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
            new_port = super(NeutronRestProxyV2, self).create_port(context,
                                                                   port)
            self._process_port_create_security_group(context, new_port, sgids)
        if (portbindings.HOST_ID in port['port']
                and 'id' in new_port):
            host_id = port['port'][portbindings.HOST_ID]
            porttracker_db.put_port_hostid(context, new_port['id'],
                                           host_id)
        new_port[addr_pair.ADDRESS_PAIRS] = (
            self._process_create_allowed_address_pairs(
                context, new_port,
                port['port'].get(addr_pair.ADDRESS_PAIRS)))
        self._process_port_create_extra_dhcp_opts(context, new_port,
                                                  dhcp_opts)
        new_port = self._extend_port_dict_binding(context, new_port)
        net = super(NeutronRestProxyV2,
                    self).get_network(context, new_port["network_id"])
        if self.add_meta_server_route:
            if new_port['device_owner'] == const.DEVICE_OWNER_DHCP:
                destination = METADATA_SERVER_IP + '/32'
                self._add_host_route(context, destination, new_port)

        # create on network ctrl
        mapped_port = self._map_display_name_or_tenant(new_port)
        if self.servers.is_unicode_enabled():
            # remove port name so that it won't be stored in description
            mapped_port['name'] = None
        mapped_port = self._map_state_and_status(mapped_port)
        # ports have to be created synchronously when creating a router
        # port since adding router interfaces is a multi-call process
        if mapped_port['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_INTF:
            self.servers.rest_create_port(net["tenant_id"],
                                          new_port["network_id"],
                                          mapped_port)
        else:
            self.evpool.spawn_n(self.async_port_create, net["tenant_id"],
                                new_port["network_id"], mapped_port)
        self.notify_security_groups_member_updated(context, new_port)
        return new_port

    def get_port(self, context, id, fields=None):
        with db.context_manager.reader.using(context):
            port = super(NeutronRestProxyV2, self).get_port(context, id,
                                                            fields)
            self._extend_port_dict_binding(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        with db.context_manager.reader.using(context):
            ports = super(NeutronRestProxyV2, self).get_ports(context, filters,
                                                              fields)
            for port in ports:
                self._extend_port_dict_binding(context, port)
        return [self._fields(port, fields) for port in ports]

    @add_debug_log
    def update_port(self, context, port_id, port):
        """Update values of a port.

        :param context: neutron api request context
        :param id: UUID representing the port to update.
        :param port: dictionary with keys indicating fields to update.

        :returns: a mapping sequence with the following signature:
        {
            "id": uuid representing the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": sets admin state of port. if down, port
                               does not forward packets.
            "status": dicates whether port is currently operational
                       (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet IDs and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.StateInvalid
        :raises: exceptions.PortNotFound
        :raises: RemoteRestError
        """
        self._warn_on_state_status(port['port'])

        # Validate Args
        orig_port = super(NeutronRestProxyV2, self).get_port(context, port_id)
        with db.context_manager.writer.using(context):
            # Update DB
            new_port = super(NeutronRestProxyV2,
                             self).update_port(context, port_id, port)
            ctrl_update_required = False
            if addr_pair.ADDRESS_PAIRS in port['port']:
                ctrl_update_required |= (
                    self.update_address_pairs_on_port(context, port_id, port,
                                                      orig_port, new_port))
            self._update_extra_dhcp_opts_on_port(context, port_id, port,
                                                 new_port)
            old_host_id = porttracker_db.get_port_hostid(context,
                                                         orig_port['id'])
            if (portbindings.HOST_ID in port['port']
                    and 'id' in new_port):
                host_id = port['port'][portbindings.HOST_ID]
                porttracker_db.put_port_hostid(context, new_port['id'],
                                               host_id)
                if old_host_id != host_id:
                    ctrl_update_required = True

            if (new_port.get("device_id") != orig_port.get("device_id") and
                    orig_port.get("device_id")):
                ctrl_update_required = True

            if ctrl_update_required:
                # tenant_id must come from network in case network is shared
                net_tenant_id = self._get_port_net_tenantid(context, new_port)
                new_port = self._extend_port_dict_binding(context, new_port)
                mapped_port = self._map_display_name_or_tenant(new_port)
                if self.servers.is_unicode_enabled():
                    # remove port name so that it won't be stored in
                    # description
                    mapped_port['name'] = None
                mapped_port = self._map_state_and_status(mapped_port)
                self.servers.rest_update_port(net_tenant_id,
                                              new_port["network_id"],
                                              mapped_port)
            need_port_update_notify = self.update_security_group_on_port(
                context, port_id, port, orig_port, new_port)
        need_port_update_notify |= self.is_security_group_member_updated(
            context, orig_port, new_port)

        if need_port_update_notify:
            self.notifier.port_update(context, new_port)

        # return new_port
        return new_port

    # NOTE(kevinbenton): workaround for eventlet/mysql deadlock
    @runtime.synchronized('bsn-port-barrier')
    @add_debug_log
    def delete_port(self, context, port_id, l3_port_check=True):
        """Delete a port.

        :param context: neutron api request context
        :param id: UUID representing the port to delete.

        :raises: exceptions.PortInUse
        :raises: exceptions.PortNotFound
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check and self.l3_plugin:
            self.l3_plugin.prevent_l3_port_deletion(context, port_id)
        with db.context_manager.writer.using(context):
            if self.l3_plugin:
                router_ids = self.l3_plugin.disassociate_floatingips(
                    context, port_id, do_notify=False)
            port = super(NeutronRestProxyV2, self).get_port(context, port_id)
            # Tenant ID must come from network in case the network is shared
            tenid = self._get_port_net_tenantid(context, port)
            self.ipam.delete_port(context, port_id)
            tenid = tenid or servermanager.SERVICE_TENANT
            self.servers.rest_delete_port(tenid, port['network_id'], port_id)

        if self.l3_plugin:
            # now that we've left db transaction, we are safe to notify
            self.l3_plugin.notify_routers_updated(context, router_ids)

    @add_debug_log
    def create_subnet(self, context, subnet):
        self._warn_on_state_status(subnet['subnet'])

        with context.session.begin(subtransactions=True):
            # create subnet in DB
            new_subnet = super(NeutronRestProxyV2,
                               self).create_subnet(context, subnet)
            net_id = new_subnet['network_id']
            orig_net = super(NeutronRestProxyV2,
                             self).get_network(context, net_id)
            # update network on network controller
            self._send_update_network(orig_net, context)
        return new_subnet

    @add_debug_log
    def update_subnet(self, context, id, subnet):
        self._warn_on_state_status(subnet['subnet'])

        with db.context_manager.writer.using(context):
            # update subnet in DB
            new_subnet = super(NeutronRestProxyV2,
                               self).update_subnet(context, id, subnet)
            net_id = new_subnet['network_id']
            orig_net = super(NeutronRestProxyV2,
                             self).get_network(context, net_id)
            # update network on network controller
            self._send_update_network(orig_net, context)
            return new_subnet

    @add_debug_log
    def delete_subnet(self, context, id):
        orig_subnet = super(NeutronRestProxyV2, self).get_subnet(context, id)
        net_id = orig_subnet['network_id']
        with db.context_manager.writer.using(context):
            # delete subnet in DB
            super(NeutronRestProxyV2, self).delete_subnet(context, id)
            orig_net = super(NeutronRestProxyV2, self).get_network(context,
                                                                   net_id)
            # update network on network controller - exception will rollback
            self._send_update_network(orig_net, context)

    def _add_host_route(self, context, destination, port):
        subnet = {}
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            nexthop = fixed_ip['ip_address']
            subnet['host_routes'] = [{'destination': destination,
                                      'nexthop': nexthop}]
            updated_subnet = self.update_subnet(context,
                                                subnet_id,
                                                {'subnet': subnet})
            payload = {'subnet': updated_subnet}
            self._dhcp_agent_notifier.notify(context, payload,
                                             'subnet.update.end')
            LOG.debug("Adding host route: ")
            LOG.debug("Destination:%(dst)s nexthop:%(next)s",
                      {'dst': destination, 'next': nexthop})
