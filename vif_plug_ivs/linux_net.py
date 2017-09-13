# Derived from nova/network/linux_net.py
#
# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Implements vlans, bridges using linux utilities."""

import os

from oslo_concurrency import processutils
from oslo_log import log as logging
from oslo_utils import excutils
from vif_plug_ivs import exception
from vif_plug_ivs.i18n import _LE
from vif_plug_ivs import privsep

LOG = logging.getLogger(__name__)


def _ivs_ctl(args):
    full_args = ['ivs-ctl']
    full_args += args
    try:
        processutils.execute(*full_args)
    except Exception as e:
        LOG.error(_LE("Unable to execute %(cmd)s. Exception: %(exception)s"),
                  {'cmd': full_args, 'exception': e})
        raise exception.AgentError(method=full_args)


@privsep.vif_plug.entrypoint
def create_ivs_vif_port(dev):
    cmd = ['add-port', dev]
    _ivs_ctl(cmd)


@privsep.vif_plug.entrypoint
def delete_ivs_vif_port(dev):
    processutils.execute('ivs-ctl', 'del-port', dev)
    processutils.execute('ip', 'link', 'delete', dev)


def device_exists(device):
    """Check if ethernet device exists."""
    return os.path.exists('/sys/class/net/%s' % device)


@privsep.vif_plug.entrypoint
def create_tap_dev(dev, mac_address=None):
    if not device_exists(dev):
        try:
            # First, try with 'ip'
            processutils.execute('ip', 'tuntap', 'add', dev, 'mode', 'tap',
                                 check_exit_code=[0, 2, 254])
        except processutils.ProcessExecutionError:
            # Second option: tunctl
            processutils.execute('tunctl', '-b', '-t', dev)
        if mac_address:
            processutils.execute('ip', 'link', 'set', dev, 'address',
                                 mac_address, check_exit_code=[0, 2, 254])
        processutils.execute('ip', 'link', 'set', dev, 'up',
                             check_exit_code=[0, 2, 254])


def _delete_net_dev(dev):
    """Delete a network device only if it exists."""
    if device_exists(dev):
        try:
            processutils.execute('ip', 'link', 'delete', dev,
                                 check_exit_code=[0, 2, 254])
            LOG.debug("Net device removed: '%s'", dev)
        except processutils.ProcessExecutionError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed removing net device: '%s'"), dev)


@privsep.vif_plug.entrypoint
def create_veth_pair(dev1_name, dev2_name):
    """Create a pair of veth devices with the specified names,

    deleting any previous devices with those names.
    """
    for dev in [dev1_name, dev2_name]:
        _delete_net_dev(dev)

    processutils.execute('ip', 'link', 'add', dev1_name,
                         'type', 'veth', 'peer', 'name', dev2_name)
    for dev in [dev1_name, dev2_name]:
        processutils.execute('ip', 'link', 'set', dev, 'up')
        processutils.execute('ip', 'link', 'set', dev, 'promisc', 'on')


@privsep.vif_plug.entrypoint
def ensure_bridge(bridge):
    if not device_exists(bridge):
        processutils.execute('brctl', 'addbr', bridge)
        processutils.execute('brctl', 'setfd', bridge, 0)
        processutils.execute('brctl', 'stp', bridge, 'off')
        syspath = '/sys/class/net/%s/bridge/multicast_snooping'
        syspath = syspath % bridge
        processutils.execute('tee', syspath, process_input='0',
                             check_exit_code=[0, 1])
        disv6 = ('/proc/sys/net/ipv6/conf/%s/disable_ipv6' %
                 bridge)
        if os.path.exists(disv6):
            processutils.execute('tee',
                                 disv6,
                                 process_input='1',
                                 check_exit_code=[0, 1])


@privsep.vif_plug.entrypoint
def delete_bridge(bridge, dev):
    if device_exists(bridge):
        processutils.execute('brctl', 'delif', bridge, dev)
        processutils.execute('ip', 'link', 'set', bridge, 'down')
        processutils.execute('brctl', 'delbr', bridge)


@privsep.vif_plug.entrypoint
def add_bridge_port(bridge, dev):
    processutils.execute('ip', 'link', 'set', bridge, 'up')
    processutils.execute('brctl', 'addif', bridge, dev)
