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

from enum import Enum
import os
from os_net_config import utils
from oslo_serialization import jsonutils
import re
import syslog as LOG
import time

# constants for RHOSP
NET_CONF_PATH = "/etc/os-net-config/config.json"
HIERA_DIR_PATH = "/etc/puppet/hieradata"
COMPUTE_FILE_PATH = "%s/compute.json" % HIERA_DIR_PATH
SUPPORTED_BOND = ['ovs_bond', 'linux_bond']
_SYS_CLASS_NET = '/sys/class/net'


class BCFMode(Enum):
    MODE_P_ONLY = 5
    MODE_P_V = 6


# monkey patch to identify phy nics
def _is_active_nic(interface_name):
    try:
        if interface_name == 'lo':
            return False

        device_dir = _SYS_CLASS_NET + '/%s/device' % interface_name
        has_device_dir = os.path.isdir(device_dir)

        carrier = None
        with open(_SYS_CLASS_NET + '/%s/carrier' % interface_name, 'r') as f:
            carrier = int(f.read().rstrip())

        address = None
        with open(_SYS_CLASS_NET + '/%s/address' % interface_name, 'r') as f:
            address = f.read().rstrip()

        if has_device_dir and carrier == 1 and address:
            return True
        else:
            return False
    except IOError:
        return False

utils._is_active_nic = _is_active_nic


def get_bcf_mode():
    """Get bcf deployment mode.

    :returns: UNKNOWN, MODE_P_ONLY or MODE_P_V.
    """
    while True:
        if os.path.isdir(HIERA_DIR_PATH):
            break
    if not os.path.isfile(COMPUTE_FILE_PATH):
        return BCFMode.MODE_P_ONLY

    if not os.path.isfile(NET_CONF_PATH):
        return BCFMode.MODE_P_ONLY
    try:
        json_data = open(NET_CONF_PATH).read()
        data = jsonutils.loads(json_data)
    except Exception:
        return BCFMode.MODE_P_ONLY
    network_config = data.get('network_config')
    for config in network_config:
        if config.get('type') == 'ivs_bridge':
            return BCFMode.MODE_P_V

    return BCFMode.MODE_P_ONLY


def get_mac_str(network_interface):
    with open("/sys/class/net/%s/address" % network_interface) as f:
        return f.read().strip()


def add_intf_to_map(intf_map, bridge_or_bond, config_type, intf_index,
                    lacp=False):
    """Adds an interface to the interface map, after performing validation

    interface_map has a specific structure. this method checks and inserts
    keys if they're missing for the bridge or interface being added.

    :param intf_map: interface map object to which the interface is added
    :param bridge_or_bond: bridge or bond name to which the interface belongs
    :param config_type: type of object - either bridge or bond
    :param intf_index: name or index number of the interface
                       if interface is in nicX format, this will be a
                       numerical index, else name. both would be string.
    :param lacp: boolean flag, specifying whether intf is part of some form of
                 link aggregation or no.
    :return: intf_map after being updated
    """
    if bridge_or_bond not in intf_map:
        intf_map[bridge_or_bond] = {}
    if 'config_type' not in intf_map[bridge_or_bond]:
        intf_map[bridge_or_bond]['config_type'] = config_type
    if 'members' not in intf_map[bridge_or_bond]:
        intf_map[bridge_or_bond]['members'] = []
    if config_type == 'linux_bond' or lacp:
        # for linux_bond config type, always True. Otherwise, depends on
        # whether its a bond or individual interface in a bridge.
        intf_map[bridge_or_bond]['lacp'] = True
    else:
        intf_map[bridge_or_bond]['lacp'] = False
    intf_map[bridge_or_bond]['members'].append(intf_index)
    return intf_map


def _get_intf_index(nic_name):
    """os-net-config can have interface name stored nicX, where X is a number

    in this case, REAL interface name is not used. derive the index if it is in
    nicX format.
    otherwise, simply use the name.

    :param nic_name:
    :return: index or name. both in string format.
    """
    indexes = map(int, re.findall(r'\d+', nic_name))
    if len(indexes) == 1 and nic_name.startswith("nic"):
        intf_index = str(indexes[0] - 1)
    else:
        intf_index = str(nic_name)
    return intf_index


def get_network_interface_map():
    """Get interface map for bonds and bridges relevant on this RHOSP node

    :return: returns a mapping of network interfaces with its parent being a
             bridge or bond. syntax:
             {
                'bridge_or_bond_name': {
                    'type': 'bond or bridge type',
                    'lacp': False (boolean, defaults to False),
                    'members': [ list of interfaces ]
                }
             }

             sample output of a mix of bonds and bridges:

             {
                 u 'bond_api': {
                     'type': 'linux_bond',,
                     'lacp': True,
                     'members': ['p1p1']
                 }, u 'br-link': {
                     'type': 'ovs_bridge',
                     'lacp': False,
                     'members': ['p1p2']
                 }, u 'br-ex': {
                     'type': 'ovs_bridge',
                     'lacp': True,
                     'members': ['p1p1', 'p1p2']
                 }
             }
    """
    intf_map = {}
    while True:
        if not os.path.isfile(NET_CONF_PATH):
            time.sleep(1)
            continue
        try:
            json_data = open(NET_CONF_PATH).read()
            data = jsonutils.loads(json_data)
        except ValueError:
            time.sleep(1)
            continue
        network_config = data.get('network_config')
        for config in network_config:
            config_type = config.get('type')
            if config_type == 'ovs_bridge':
                bridge_name = config.get('name').encode('ascii', 'ignore')
                members = config.get('members')
                for member in members:
                    # member can be a bond or single interface in case of
                    # ovs_bridge on DPDK controller
                    member_type = member.get('type')
                    if member_type == 'interface':
                        intf_index = _get_intf_index(
                            member.get('name').encode('ascii', 'ignore'))
                        add_intf_to_map(
                            intf_map=intf_map, bridge_or_bond=bridge_name,
                            config_type='ovs_bridge', intf_index=intf_index)
                        break
                    elif member_type in SUPPORTED_BOND:
                        nics = member.get('members')
                        for nic in nics:
                            if nic.get('type') != 'interface':
                                continue
                            intf_index = _get_intf_index(
                                nic.get('name').encode('ascii', 'ignore'))
                            add_intf_to_map(
                                intf_map=intf_map, bridge_or_bond=bridge_name,
                                config_type='ovs_bridge',
                                intf_index=intf_index, lacp=True)
                        break
                    else:
                        # either a vlan type interface or unsupported type
                        continue
            elif config_type == 'linux_bond':
                bond_name = config.get('name').encode('ascii', 'ignore')
                members = config.get('members')
                for nic in members:
                    if nic.get('type') != 'interface':
                        continue
                    intf_index = _get_intf_index(
                        nic.get('name').encode('ascii', 'ignore'))
                    add_intf_to_map(
                        intf_map=intf_map, bridge_or_bond=bond_name,
                        config_type='linux_bond', intf_index=intf_index)
            elif config_type == 'ovs_user_bridge':
                bridge_name = config.get('name').encode('ascii', 'ignore')
                members = config.get('members')
                for nic in members:
                    nic_type = nic.get('type')
                    if nic_type == 'ovs_dpdk_port':
                        intf_name = nic.get('name').encode('ascii', 'ignore')
                        add_intf_to_map(
                            intf_map=intf_map, bridge_or_bond=bridge_name,
                            config_type='ovs_user_bridge',
                            intf_index=intf_name)
                        break
                    elif nic_type == 'ovs_dpdk_bond':
                        bond_interfaces = nic.get('members')
                        for bond_intf in bond_interfaces:
                            if bond_intf.get('type') != 'ovs_dpdk_port':
                                LOG.syslog("DPDK ovs_dpdk_bond has NON "
                                           "ovs_dpdk_port %s" %
                                           bond_intf.get('name'))
                                continue
                            intf_name = (bond_intf.get('name')
                                         .encode('ascii', 'ignore'))
                            add_intf_to_map(
                                intf_map=intf_map, bridge_or_bond=bridge_name,
                                config_type='ovs_user_bridge',
                                intf_index=intf_name, lacp=True)
                    else:
                        continue
        break
    # get active interfaces from os_net_config
    active_intfs = utils.ordered_active_nics()
    intf_len = len(active_intfs)
    # use the intf_map and work out the chassisid
    for br_or_bond in intf_map:
        if intf_map[br_or_bond]['config_type'] == 'ovs_user_bridge':
            # do not try to map interface name with kernel entries
            # ovs_user_bridge is used for DPDK compute nodes, interfaces are
            # owned by DPDK driver and not kernel network driver
            continue
        if 'members' in intf_map[br_or_bond]:
            intfs = []
            for index in intf_map[br_or_bond]['members']:
                try:
                    idx = int(index)
                    if idx < intf_len:
                        intfs.append(active_intfs[idx])
                except ValueError:
                    intfs.append(index)
            intf_map[br_or_bond]['members'] = intfs
    LOG.syslog("Network interface map is %s" % intf_map)
    return intf_map
