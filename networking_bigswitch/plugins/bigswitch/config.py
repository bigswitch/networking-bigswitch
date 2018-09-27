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

"""
This module manages configuration options
"""

from oslo_config import cfg

from neutron.conf.agent import common as agconfig
from neutron_lib.api.definitions import portbindings
from neutron_lib.utils import net

restproxy_opts = [
    cfg.ListOpt('servers', default=['localhost:8800'],
                help=_("A comma separated list of Big Switch or Floodlight "
                       "servers and port numbers. The plugin proxies the "
                       "requests to the Big Switch/Floodlight server, "
                       "which performs the networking configuration. Only one"
                       "server is needed per deployment, but you may wish to"
                       "deploy multiple servers to support failover.")),
    cfg.StrOpt('server_auth', secret=True,
               help=_("The username and password for authenticating against "
                      " the Big Switch or Floodlight controller.")),
    cfg.BoolOpt('server_ssl', default=True,
                help=_("If True, Use SSL when connecting to the Big Switch or "
                       "Floodlight controller.")),
    cfg.BoolOpt('ssl_sticky', default=True,
                help=_("Trust and store the first certificate received for "
                       "each controller address and use it to validate future "
                       "connections to that address.")),
    cfg.BoolOpt('no_ssl_validation', default=False,
                help=_("Disables SSL certificate validation for controllers")),
    cfg.BoolOpt('cache_connections', default=True,
                help=_("Re-use HTTP/HTTPS connections to the controller.")),
    cfg.StrOpt('ssl_cert_directory',
               default='/etc/neutron/plugins/bigswitch/ssl',
               help=_("Directory containing ca_certs and host_certs "
                      "certificate directories.")),
    cfg.BoolOpt('sync_data', default=False,
                help=_("Sync data on connect")),
    cfg.BoolOpt('auto_sync_on_failure', default=True,
                help=_("If neutron fails to create a resource because "
                       "the backend controller doesn't know of a dependency, "
                       "the plugin automatically triggers a full data "
                       "synchronization to the controller.")),
    cfg.IntOpt('consistency_interval', default=60,
               help=_("Time between verifications that the backend controller "
                      "database is consistent with Neutron. (0 to disable)")),
    cfg.IntOpt('server_timeout', default=10,
               help=_("Maximum number of seconds to wait for proxy request "
                      "to connect and complete.")),
    cfg.IntOpt('thread_pool_size', default=4,
               help=_("Maximum number of threads to spawn to handle large "
                      "volumes of port creations.")),
    cfg.StrOpt('neutron_id', default='neutron-' + net.get_hostname(),
               deprecated_name='quantum_id',
               help=_("User defined identifier for this Neutron deployment")),
    cfg.BoolOpt('add_meta_server_route', default=True,
                help=_("Flag to decide if a route to the metadata server "
                       "should be injected into the VM")),
    cfg.StrOpt('auth_url', help=_("Authentication URL")),
    cfg.StrOpt('auth_user', help=_("Admin username")),
    cfg.StrOpt('auth_password', help=_("Admin password")),
    cfg.StrOpt('auth_tenant', help=_("Admin tenant name")),
    cfg.IntOpt('keystone_sync_interval', default=300,
               help=_("Time between that keystone queries to sync "
                      "Openstack tenants. (0 to disable)")),
    cfg.BoolOpt('sync_security_groups', default=False,
                help=_("Sync security group info to Big Cloud Fabric for "
                       "enhanced Testpath visibility.")),
    cfg.BoolOpt('naming_scheme_unicode', default=True,
                help=_("Configure whether or not to configure BCF "
                       "with unicode display-name. Applicable to BCF 5.0 "
                       "onwards."))
]
router_opts = [
    cfg.MultiStrOpt('tenant_default_router_rule', default=['*:any:any:permit'],
                    help=_("The default router rules installed in new tenant "
                           "routers. Repeat the config option for each rule. "
                           "Format is <tenant>:<source>:<destination>:<action>"
                           " Use an * to specify default for all tenants.")),
    cfg.IntOpt('max_router_rules', default=200,
               help=_("Maximum number of router rules")),
]
nova_opts = [
    cfg.StrOpt('vif_type', default='ivs',
               help=_("Virtual interface type to configure on "
                      "Nova compute nodes")),
]

VIF_TYPE_IVS = 'ivs'
VIF_TYPES = [
    portbindings.VIF_TYPE_UNBOUND,
    portbindings.VIF_TYPE_BINDING_FAILED,
    portbindings.VIF_TYPE_DISTRIBUTED,
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_BRIDGE,
    portbindings.VIF_TYPE_OTHER,
    portbindings.VIF_TYPE_VHOST_USER,
    VIF_TYPE_IVS,
    'iovisor', 'dvs', '802.1qbg', '802.1qbh', 'hyperv',
    'midonet', 'ib_hostdev', 'hw_web', 'vrouter',
]

PROVIDER_NETWORK_TYPE = 'provider:network_type'
PROVIDER_PHYSNET = 'provider:physical_network'

# SR-IOV related constants
UNSUPPORTED_VNIC_TYPES = [portbindings.VNIC_DIRECT_PHYSICAL]
VNIC_TYPE_SRIOV = [portbindings.VNIC_DIRECT]
SRIOV_ACTIVE_ACTIVE_MODE_PHYSNET_SUBSTR = 'BSN-ACTIVE-'
SRIOV_ACTIVE_PHYSNET = SRIOV_ACTIVE_ACTIVE_MODE_PHYSNET_SUBSTR + '1'

# Each VIF Type can have a list of nova host IDs that are fixed to that type
for i in VIF_TYPES:
    opt = cfg.ListOpt('node_override_vif_' + i, default=[],
                      help=_("Nova compute nodes to manually set VIF "
                             "type to %s") % i)
    nova_opts.append(opt)

# Add the vif types for reference later
nova_opts.append(cfg.ListOpt('vif_types',
                             default=VIF_TYPES,
                             help=_('List of allowed vif_type values.')))

agent_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_('Name of integration bridge on compute '
                      'nodes used for security group insertion.')),
    cfg.IntOpt('polling_interval', default=5,
               help=_('Seconds between agent checks for port changes')),
    cfg.StrOpt('virtual_switch_type', default='ivs',
               help=_('Virtual switch type.'))
]


def register_config():
    cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")
    cfg.CONF.register_opts(router_opts, "ROUTER")
    cfg.CONF.register_opts(nova_opts, "NOVA")
    cfg.CONF.register_opts(agent_opts, "RESTPROXYAGENT")
    # include for report_interval
    cfg.CONF.register_opts(agconfig.AGENT_STATE_OPTS, "AGENT")
    agconfig.register_root_helper(cfg.CONF)
