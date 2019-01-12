# Copyright 2017 Big Switch Networks, Inc.
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
import os

from networking_bigswitch.plugins.bigswitch import constants as bsn_consts
from networking_bigswitch.plugins.bigswitch.i18n import _LI
from networking_bigswitch.plugins.bigswitch.i18n import _LW
from neutron_lib import exceptions as n_exc
from oslo_log import log

LOG = log.getLogger(__name__)


class Util(object):
    """Util

    Placeholder for static methods that can be called from across the plugin
    and reused as required.
    """

    @staticmethod
    def format_resource_name(name):
        """format resource name

        Util method to format resource names to make them compatible with BCF.

        Replaces special characters with its corresponding BCF compatible
        encoding.

        :param name non empty string which is the name of the resource
        :rtype string name with special characters replaced
        """
        return (name
                # always replace underscores first, since other replacements
                # contain underscores as part of replacement
                .replace('_', '__')
                .replace(' ', '_s')
                .replace('\'', '_a')
                .replace('/', '_f')
                .replace('[', '_l')
                .replace(']', '_r'))

    @staticmethod
    def get_tenant_id_for_create(context, resource):
        if context.is_admin and 'tenant_id' in resource:
            tenant_id = resource['tenant_id']
        elif ('tenant_id' in resource and
              resource['tenant_id'] != context.tenant_id):
            reason = _('Cannot create resource for another tenant')
            raise n_exc.AdminRequired(reason=reason)
        else:
            tenant_id = context.tenant_id
        return tenant_id

    @staticmethod
    def read_ovs_bridge_mappings():
        """Read the 'bridge_mappings' property from openvswitch_agent.ini

        This is done for Redhat environments, to allow an improved
        learning/programming of interface groups based on ports and the network
        to which the ports belong to.

        :return: bridge_mappings dictionary {'physnet_name': 'bridge_name', ..}
                    {} empty dictionary when not found
        """
        mapping = {}
        mapping_str = None
        # read openvswitch_agent.ini for bridge_mapping info
        if not os.path.isfile(bsn_consts.OVS_AGENT_INI_FILEPATH):
            # if ovs_agent.ini doesn't exists, return empty mapping
            LOG.warning(_LW("Unable to read OVS bridge_mappings, "
                            "openvswitch_agent.ini file not present."))
            return mapping

        with open(bsn_consts.OVS_AGENT_INI_FILEPATH) as f:
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
                "Unable to read OVS bridge_mappings, either the line is "
                "commented or not present in openvswitch_agent.ini."))
            return mapping

        phy_map_list = mapping_str.split(',')
        for phy_map in phy_map_list:
            phy, bridge = phy_map.split(':')
            mapping[phy.strip()] = bridge.strip()

        LOG.info(_LI("OVS bridge_mappings are: %(br_map)s"),
                 {'br_map': mapping})
        return mapping
