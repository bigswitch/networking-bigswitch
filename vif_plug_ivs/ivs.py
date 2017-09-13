# Derived from nova/virt/libvirt/vif.py
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

from vif_plug_ivs.i18n import _LE
from os_vif import objects
from os_vif import plugin
from oslo_concurrency import processutils
from oslo_log import log as logging

from vif_plug_ivs import linux_net

LOG = logging.getLogger(__name__)

class IvsPlugin(plugin.PluginBase):
    """An OVS plugin that can setup VIFs in many ways
    The OVS plugin supports several different VIF types, VIFBridge
    and VIFOpenVSwitch, and will choose the appropriate plugging
    action depending on the type of VIF config it receives.
    If given a VIFBridge, then it will create connect the VM via
    a regular Linux bridge device to allow security group rules to
    be applied to VM traffic.
    """

    NIC_NAME_LEN = 14

    @staticmethod
    def gen_port_name(prefix, id):
        return ("%s%s" % (prefix, id))[:IvsPlugin.NIC_NAME_LEN]

    @staticmethod
    def get_veth_pair_names(vif):
        return (IvsPlugin.gen_port_name("qvb", vif.id),
                IvsPlugin.gen_port_name("qvo", vif.id))

    def describe(self):
        return objects.host_info.HostPluginInfo(
            plugin_name="ivs",
            vif_info=[
                objects.host_info.HostVIFInfo(
                    vif_object_name=objects.vif.VIFBridge.__name__,
                    min_version="1.0",
                    max_version="1.0"),
                objects.host_info.HostVIFInfo(
                    vif_object_name=objects.vif.VIFGeneric.__name__,
                    min_version="1.0",
                    max_version="1.0"),
            ])

    def get_vif_devname(self, vif):
        if 'vif_name' in vif:
            return vif['vif_name']
        return ("nic" + vif.id)[:IvsPlugin.NIC_NAME_LEN]

    def _plug_ivs_ethernet(self, vif, instance):
        dev = self.get_vif_devname(vif)
        linux_net.create_tap_dev(dev)
        linux_net.create_ivs_vif_port(dev)

    def _plug_ivs_hybrid(self, vif, instance):
        """Plug using hybrid strategy (same as OVS, removes unused parts)

        Create a per-VIF linux bridge, then link that bridge to the OVS
        integration bridge via a veth device, setting up the other end
        of the veth device just like a normal OVS port. Then boot the
        VIF on the linux bridge using standard libvirt mechanisms.
        """

        v1_name, v2_name = self.get_veth_pair_names(vif)

        linux_net.ensure_bridge(vif.bridge_name)

        if not linux_net.device_exists(v2_name):
            linux_net.create_veth_pair(v1_name, v2_name)
            linux_net.add_bridge_port(vif.bridge_name, v1_name)
            linux_net.create_ivs_vif_port(v2_name)

    def plug(self, vif, instance):
        if isinstance(vif, objects.vif.VIFBridge):
            self._plug_ivs_hybrid(vif, instance)
        else:
            self._plug_ivs_ethernet(vif, instance)

    def _unplug_ivs_hybrid(self, vif, instance):
        v1_name, v2_name = self.get_veth_pair_names(vif)

        linux_net.delete_bridge(vif.bridge_name, v1_name)
        linux_net.delete_ivs_vif_port(v2_name)

    def _unplug_ivs_ethernet(self, vif, instance):
        try:
            linux_net.delete_ivs_vif_port(self.get_vif_devname(vif))
        except processutils.ProcessExecutionError:
            LOG.exception(_LE("Failed while unplugging vif"),
                          instance=instance)

    def unplug(self, vif, instance):
        if isinstance(vif, objects.vif.VIFBridge):
            self._unplug_ivs_hybrid(vif, instance)
        else:
            self._unplug_ivs_ethernet(vif, instance)
