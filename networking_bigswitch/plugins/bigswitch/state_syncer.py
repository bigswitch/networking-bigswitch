# Copyright 2019 Big Switch Networks, Inc.
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
import eventlet
import os

from keystoneauth1.identity import v3
from keystoneauth1 import loading
from keystoneauth1 import session
from keystoneclient.v3 import client as ksclient
from networking_bigswitch.plugins.bigswitch import constants as bsn_consts
from networking_bigswitch.plugins.bigswitch.utils import Util
from novaclient import client as nv_client
from oslo_log import log as logging
import servermanager

LOG = logging.getLogger(__name__)


class StateSyncer(object):
    """StateSyncer

    Periodic state syncer for BCF.
    Used to provide additional orchestrator information to BCF for the
    orchestrator integration GUI.
    NOT the same as topo_sync.

    StateSyncer provides network information, along with metadata about a bunch
    of other objects - such as compute nodes available, interface groups,
    VMs running on each compute node, last X errors for the calls to BCF,
    last topo_sync status.
    """

    def __init__(self, ks_auth_dict, nova_auth_dict):
        # typically:
        # username = neutron
        # project_name = service
        # user_domain_name = Default
        # project_domain_name = Default

        # self.ks_auth_dict = ks_auth_dict

        # initialize keystone client
        auth = v3.Password(auth_url=ks_auth_dict['auth_url'],
                           username=ks_auth_dict['username'],
                           password=ks_auth_dict['password'],
                           project_name=ks_auth_dict['project_name'],
                           user_domain_name=ks_auth_dict['user_domain_name'],
                           project_domain_name=ks_auth_dict[
                               'project_domain_name'])
        sess = session.Session(auth=auth)
        self.keystone_client = ksclient.Client(session=sess)

        # initialize nova client
        loader = loading.get_plugin_loader('password')
        auth = loader.load_from_options(
            auth_url=nova_auth_dict['auth_url'],
            username=nova_auth_dict['username'],
            password=nova_auth_dict['password'],
            project_name=nova_auth_dict['project_name'],
            user_domain_name=nova_auth_dict['user_domain_name'],
            project_domain_name=nova_auth_dict['project_domain_name'])
        sess = session.Session(auth=auth)
        self.nova_client = nv_client.Client(bsn_consts.NOVA_CLIENT_VERSION,
                                            session=sess)
        # read the bridge mappings from os-net-config
        # this helps to generate interface group names in case of RH systems
        # if os-net-config is present, attempt to read physnet bridge_mappings
        # from openvswitch_agent.ini
        # this does not change at runtime. so read once at init is good.
        self.bridge_mappings = {}
        if os.path.isfile(bsn_consts.RH_NET_CONF_PATH):
            self.bridge_mappings = Util.read_ovs_bridge_mappings()

        self.bridge_name = None
        if (len(self.bridge_mappings) > 0):
            # if there are many bridge mappings, pick the first one
            # typically, generic RHOSP deployments have a single physnet:bridge
            # mappings. we can handle multiple physnet case later
            # missing info is physnet associated with an interface of a VM.
            # given that, we can utilize multiple bridge info at runtime.
            self.bridge_name = self.bridge_mappings.values()[0]

    def periodic_update(self, period=300):
        while True:
            eventlet.sleep(period)
            self.push_update()

    def push_update(self):
        """Push current state of OSP to BCF

        Collects the info about various objects from keystone, nova, neutron
        and posts an update to BCF. A typical update has the following
        structure:
        {
            'tenant' : [
                {
                    'id': '',
                    'name': '',
                },
                {},
                ...
            ],

            'network' : [
                {
                    'id': '',
                    'name': '',
                },
                {},
                ...
            ],

            'hypervisor' : [
                {
                    'hardware-model': '',
                    'state': '',
                    'vcpus': 24,
                    'vcpus_used': 2,
                    'local_gb': hdd_size,
                    'local_gb_used': hdd_used,
                    'hostname': '',
                    'memory_mb': mem_size,
                    'memory_mb_used': mem_used,
                }, {}, ...
            ],

            'vm': [
                {
                    'name': '',
                    'hypervisor_hostname': '',
                    'state': '',
                    'tenant_id': '',
                    'tenant_name': '',
                    'interface': [
                        {
                            'network_name': '',
                            'mac_address': '',
                            'ip_address': '',
                            'type': 'fixed/floating',
                            'version': '4/6'
                        }, {}, ...
                    ],
                    'network': [
                        {
                            'network_name': '',
                            'interface': [
                                {
                                    'mac_addr': '',
                                    'ip_addr': '',
                                    'type': '',
                                },
                                {}
                            ]
                        },
                        {}
                    ],
                },
                {}, ...
            ]
        }

        :return: None - it does a REST call to BCF. does not return a value
        """
        # get serverpool instance
        serverpool = servermanager.ServerPool.get_instance()
        # initialize empty dictionary post data
        post_data = {}

        # add tenant list
        keystone_tenants = copy.deepcopy(serverpool.keystone_tenants)
        tenant_list = []
        for tenant in keystone_tenants:
            tenant_list.append({
                'tenant-id': tenant,
                'tenant-name': keystone_tenants[tenant]
            })
        post_data['tenant'] = tenant_list

        # get hypervisors info from nova
        hypervisors = self.nova_client.hypervisors.list()
        hv_list = []
        for hv in hypervisors:
            intf_group_name = (
                (hv.hypervisor_hostname + '_' + self.bridge_name)
                if self.bridge_name
                else hv.hypervisor_hostname)
            hv_list.append({
                'hostname': hv.hypervisor_hostname,
                'vcpu-count': hv.vcpus,
                'vcpu-count-used': hv.vcpus_used,
                'disk-capacity-gb': hv.local_gb,
                'disk-capacity-gb-used': hv.local_gb_used,
                'memory-mb': hv.memory_mb,
                'memory-mb-used': hv.memory_mb_used,
                'power-state': hv.state,
                'status': hv.status,
                'current-workload': hv.current_workload,
                'interface-group': intf_group_name
            })
        post_data['hypervisor'] = hv_list

        # get VM info from nova
        vms = self.nova_client.servers.list()
        vm_list = []
        for vm in vms:
            # network info needs more parsing
            interfaces = []
            for addr in vm.addresses:
                for intf in vm.addresses[addr]:
                    interfaces.append({
                        'network-name': addr,
                        'mac-address': intf[bsn_consts.INTF_MAC_ADDR],
                        'ip-address': intf[bsn_consts.INTF_IP_ADDR],
                        'ip-alloc-type': intf[bsn_consts.INTF_IP_TYPE],
                        'version': intf[bsn_consts.INTF_IP_VERSION]
                    })

            vm_list.append({
                'name': vm.name,
                'id': vm.id,
                # hypervisor hostname is not straightforward object property
                'hypervisor-hostname': getattr(
                    vm, bsn_consts.HYPERVISOR_HOSTNAME),
                'state': getattr(vm, bsn_consts.VM_STATE),
                'tenant-id': vm.tenant_id,
                'tenant-name': serverpool.keystone_tenants[vm.tenant_id],
                'interface': interfaces
            })

        post_data['vm'] = vm_list

        # physnet info is not available for VMs, but we do have access to
        # bridge mappings in certain environments (RH). pass this info if
        # available
        post_data['bridge_mappings'] = self.bridge_mappings

        # post to BCF
        LOG.debug('OSP cluster info json sent to BCF is %s', post_data)
        serverpool.rest_update_osp_cluster_info(post_data)
