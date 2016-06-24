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
COMPUTE_FILE_PATH = "%s/compute.yaml" % HIERA_DIR_PATH
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


def get_uplinks_and_chassisid():
    """Get uplinks and chassis_id in RHOSP environment.
    :returns: a list of uplinks names and one chassis_id
        which is the first active nic's mac address.
    """
    intf_indexes = []
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
            if config.get('type') != 'ovs_bridge':
                continue
            if config.get('name') != 'br-ex':
                continue
            members = config.get('members')
            for member in members:
                if member.get('type') not in SUPPORTED_BOND:
                    continue
                nics = member.get('members')
                for nic in nics:
                    if nic.get('type') != 'interface':
                        continue
                    nic_name = nic.get('name')
                    indexes = map(int, re.findall(r'\d+', nic_name))
                    if len(indexes) == 1 and nic_name.startswith("nic"):
                        intf_indexes.append(str(indexes[0] - 1))
                    else:
                        intf_indexes.append(str(nic_name))
                break
            break
        break

    intfs = []
    chassis_id = "00:00:00:00:00:00"
    while True:
        active_intfs = utils.ordered_active_nics()
        intf_len = len(active_intfs)
        if len(active_intfs) != 0:
            chassis_id = get_mac_str(active_intfs[0])
        intfs = []
        all_nics_are_ready = True
        for index in intf_indexes:
            try:
                idx = int(index)
                if idx >= intf_len:
                    all_nics_are_ready = False
                    break
                intfs.append(active_intfs[idx])
            except ValueError:
                intfs.append(index)
        if all_nics_are_ready:
            break
        LOG.syslog("LLDP gets partial active uplinks %s" % intfs)
        time.sleep(1)
    return intfs, chassis_id
