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

import argparse
import ctypes
from ctypes import c_byte
from ctypes import c_char_p
from ctypes import c_uint
from ctypes import c_uint16
from ctypes import c_uint32
from ctypes import c_ushort
from ctypes import c_void_p
from ctypes import cast
from ctypes import get_errno
from ctypes import pointer
from ctypes import POINTER
from ctypes import Structure
from ctypes import Union
import ctypes.util
import os
import os.path
import platform
import socket
from socket import AF_INET
from socket import AF_INET6
from socket import inet_ntop
import subprocess
import syslog as LOG
import time
try:
    from rhlib import get_network_interface_map
except ImportError:
    pass

LLDP_DST_MAC = "01:80:c2:00:00:0e"
SYSTEM_DESC_LACP = "5c:16:c7:00:00:04"
SYSTEM_DESC_STATIC = "5c:16:c7:00:00:00"
LLDP_ETHERTYPE = 0x88cc
TTL = 120
INTERVAL = 10
CHASSIS_ID_LOCALLY_ASSIGNED = 7
PORT_ID_INTERFACE_ALIAS = 1
PCI_IDS_DIR = "/run/pci_ids"
LLDP_START_STR = "lldp start"
LLDP_STOP_STR = "lldp stop"
X710_INTEL_DRIVER_STR = "i40e"
X710_DEVICE_LIST = [0x1572, 0x1583]

# read and save lldp status for different interfaces
lldp_status = {}


class struct_sockaddr(Structure):
    _fields_ = [
        ('sa_family', c_ushort),
        ('sa_data', c_byte * 14)]


class struct_sockaddr_in(Structure):
    _fields_ = [
        ('sin_family', c_ushort),
        ('sin_port', c_uint16),
        ('sin_addr', c_byte * 4)]


class struct_sockaddr_in6(Structure):
    _fields_ = [
        ('sin6_family', c_ushort),
        ('sin6_port', c_uint16),
        ('sin6_flowinfo', c_uint32),
        ('sin6_addr', c_byte * 16),
        ('sin6_scope_id', c_uint32)]


class union_ifa_ifu(Union):
    _fields_ = [
        ('ifu_broadaddr', POINTER(struct_sockaddr)),
        ('ifu_dstaddr', POINTER(struct_sockaddr))]


class struct_ifaddrs(Structure):
    pass
struct_ifaddrs._fields_ = [
    ('ifa_next', POINTER(struct_ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),
    ('ifa_addr', POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    ('ifa_ifu', union_ifa_ifu),
    ('ifa_data', c_void_p)]

libc = ctypes.CDLL(ctypes.util.find_library('c'))


def ifap_iter(ifap):
    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:
            break
        ifa = ifa.ifa_next.contents


def getfamaddr(sa):
    family = sa.sa_family
    addr = None
    if family == AF_INET:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
        addr = inet_ntop(family, sa.sin_addr)
    elif family == AF_INET6:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in6)).contents
        addr = inet_ntop(family, sa.sin6_addr)
    return family, addr


class NetworkInterface(object):
    def __init__(self, name):
        self.name = name
        self.index = libc.if_nametoindex(name)
        self.addresses = {}

    def __str__(self):
        return "%s [index=%d, IPv4=%s, IPv6=%s]" % (
            self.name, self.index,
            self.addresses.get(AF_INET),
            self.addresses.get(AF_INET6))


def get_network_interfaces():
    ifap = POINTER(struct_ifaddrs)()
    result = libc.getifaddrs(pointer(ifap))
    if result != 0:
        raise OSError(get_errno())
    del result
    try:
        retval = {}
        for ifa in ifap_iter(ifap):
            name = ifa.ifa_name
            i = retval.get(name)
            if not i:
                i = retval[name] = NetworkInterface(name)
            family, addr = getfamaddr(ifa.ifa_addr.contents)
            if addr:
                i.addresses[family] = addr
        return retval.values()
    finally:
        libc.freeifaddrs(ifap)


def parse_args():
    parser = argparse.ArgumentParser()

    # LLDP packet arguments
    parser.add_argument("--network_interface")
    parser.add_argument("--system-name")
    parser.add_argument("--system-desc")

    # Other arguments
    parser.add_argument("-i", "--interval", type=int, default=0)
    parser.add_argument("-d", "--daemonize",
                        action="store_true", default=False)
    parser.add_argument("--sriov", action="store_true", default=False)

    return parser.parse_args()


def validate_num_bits_of_int(int_value, num_bits, name=None):
    mask = pow(2, num_bits) - 1
    if (int_value & mask) != int_value:
        name = name if name else "The integer value"
        msg = ("{name} must be {num_bits}-bit long. Given: {int_value} "
               "({hex_value})".format(**{'name': name, 'num_bits': num_bits,
                                         'int_value': int_value,
                                         'hex_value': hex(int_value)}))
        raise ValueError(msg)


def raw_bytes_of_hex_str(hex_str):
    return hex_str.decode("hex")


def raw_bytes_of_mac_str(mac_str):
    return raw_bytes_of_hex_str(mac_str.replace(":", ""))


def raw_bytes_of_int(int_value, num_bytes, name=None):
    validate_num_bits_of_int(int_value, num_bytes * 8, name)
    template = "%0" + "%d" % (num_bytes * 2) + "x"
    return raw_bytes_of_hex_str(template % int_value)


def get_mac_str(network_interface):
    """Attempts to get MAC addr from kernel /sys/class/net files.

    Returns None if nic is not controlled by kernel network driver file is
    missing.

    :param network_interface:
    :return:
    """
    try:
        with open("/sys/class/net/%s/address" % network_interface) as f:
            return f.read().strip()
    except Exception as e:
        LOG.syslog("Exception getting MAC address of interface %s: %s" %
                   (network_interface, e.message))
        return None


def execute_cmd(cmd):
    """Execute a command on host and return output.

    Returns None if there is an exception during execution.

    :param cmd:
    :return:
    """
    try:
        output = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, shell=True)
        return output.strip().strip("\"")
    except Exception as e:
        msg = ("Error executing command %s: %s\n" % (cmd, e))
        LOG.syslog(msg)
        return None


def get_intf_ofport_number(intf_name):
    """Return OFPort Number of an interface from ovs-db's Interface table

    :param intf_name:
    :return:
    """
    cmd = ("ovs-vsctl get Interface %(intf_name)s ofport"
           % {'intf_name': intf_name})
    return execute_cmd(cmd)


def get_dpdk_intf_mac_addr(intf_name):
    """Returns MAC addr of an interface from ovs-db's Interface table

    :param intf_name:
    :return:
    """
    cmd = ("ovs-vsctl get Interface %(intf_name)s mac_in_use"
           % {'intf_name': intf_name})
    return execute_cmd(cmd)


def get_fqdn_cli():
    """Returns output of 'hostname -f'

    In some cases, socket.getfqdn() does not return domain name. This is a more
    robust way to get hostname with domain name.

    :return:
    """
    cmd = "hostname -f"
    return execute_cmd(cmd)


def readfile(path):
    with open(path) as f:
        return f.read()


def writefile(path, data):
    with open(path, "w") as f:
        f.write(data)


def lldp_ethertype():
    return raw_bytes_of_int(LLDP_ETHERTYPE, 2, "LLDP ethertype")


def validate_tlv_type(type_):
    validate_num_bits_of_int(type_, 7, "TLV type")


def validate_tlv_length(length):
    validate_num_bits_of_int(length, 9, "TLV length")


def tlv_1st_2nd_bytes_of(type_, length):
    validate_tlv_type(type_)
    validate_tlv_length(length)
    int_value = (type_ << (8 + 1)) | length
    return raw_bytes_of_int(int_value, 2, "First 2 bytes of TLV")


def tlv_of(type_, str_value):
    return tlv_1st_2nd_bytes_of(type_, len(str_value)) + str_value


def chassis_id_tlv_of(chassis_id, subtype=CHASSIS_ID_LOCALLY_ASSIGNED):
    return tlv_of(
        1, raw_bytes_of_int(subtype, 1, "Chassis ID subtype") + chassis_id)


def port_id_tlv_of(port_id, subtype=PORT_ID_INTERFACE_ALIAS):
    return tlv_of(2, raw_bytes_of_int(subtype, 1, "Port ID subtype") + port_id)


def ttl_tlv_of(ttl_seconds):
    return tlv_of(3, raw_bytes_of_int(ttl_seconds, 2, "TTL (seconds)"))


def port_desc_tlv_of(port_desc):
    return tlv_of(4, port_desc)


def system_name_tlv_of(system_name):
    return tlv_of(5, system_name)


def system_desc_tlv_of(system_desc):
    return tlv_of(6, system_desc)


def end_tlv():
    return tlv_of(0, "")


def lldp_frame_of(chassis_id,
                  network_interface,
                  ttl,
                  system_name=None,
                  system_desc=None,
                  port_mac_str=None):
    if not port_mac_str:
        port_mac_str = get_mac_str(network_interface)
    contents = [
        # Ethernet header
        raw_bytes_of_mac_str(LLDP_DST_MAC),
        raw_bytes_of_mac_str(port_mac_str),
        lldp_ethertype(),

        # Required LLDP TLVs
        chassis_id_tlv_of(chassis_id),
        port_id_tlv_of(network_interface),
        ttl_tlv_of(ttl),
        port_desc_tlv_of(port_mac_str)]

    # Optional LLDP TLVs
    if system_name is not None:
        contents.append(system_name_tlv_of(system_name))
    if system_desc is not None:
        contents.append(system_desc_tlv_of(system_desc))

    # End TLV
    contents.append(end_tlv())
    return "".join(contents)


def daemonize():
    # Do not use this code for daemonizing elsewhere as this is
    # a very simple version that is just good enough for here.
    pid = os.fork()
    if pid != 0:
        # Exit from the parent process
        os._exit(os.EX_OK)

    os.setsid()

    pid = os.fork()
    if pid != 0:
        # Exit from the 2nd parent process
        os._exit(os.EX_OK)


def list_a_minus_list_b(list_a, list_b):
    """This method assumes input is two lists with unique elements aka sets.

    It then returns all unique elements in list_a, not present in list_b.

    :param list_a:
    :param list_b:
    :return: list of elements only in list_a OR an empty list
    """
    return list(set(list_a) - set(list_b))


def find_pci_id(uplink):
    if os.path.exists("/sys/bus/pci/devices/%s" % uplink):
        return uplink

    stash = os.path.join(PCI_IDS_DIR, uplink)
    if os.path.exists(stash):
        pci_id = readfile(stash)
        return pci_id

    if not os.path.exists("/sys/class/net/%s" % uplink):
        msg = ("No such network device %s" % uplink)
        raise RuntimeError(msg)

    pci_id = os.path.basename(os.readlink("/sys/class/net/%s/device" % uplink))

    if not os.path.exists(PCI_IDS_DIR):
        os.mkdir(PCI_IDS_DIR)

    writefile(stash, pci_id)
    return pci_id


def save_x710_intf_lldp_status(intf):
    """This will read the LLDP status being sent for the interface, only if

    it is an x710 network card.

    If its status is already recorded, it returns True
    If not, it will read and save and return True for x710 interfaces
    For all other interfaces, it will return False

    :param intf:
    :return: (boolean, pci_id) True or False based on outcome. pci_id is None
                               if False. Actual pci_id otherwise
    """
    LOG.syslog("Read and save LLDP Tx status from device as needed")

    uplink = intf.strip()
    pci_id = find_pci_id(uplink)
    LOG.syslog("Uplink %(uplink)s is PCI device %(pci_id)s" %
               {"uplink": uplink, "pci_id": pci_id})

    if uplink in lldp_status:
        LOG.syslog("Uplink %s already has LLDP status saved as %s" %
                   (uplink, lldp_status[uplink]))
        return (True, pci_id)

    # check the card type, if x710, read lldp statusfrom nic
    vendor = int(readfile("/sys/bus/pci/devices/%s/vendor" % pci_id), 16)
    device = int(readfile("/sys/bus/pci/devices/%s/device" % pci_id), 16)

    LOG.syslog("pci_id %s vendor %#04x device %#04x" %
               (pci_id, vendor, device))

    # check if X710 NIC, if yes, read lldp status
    if (vendor == 0x8086 and device in X710_DEVICE_LIST):
        # default assume status as lldp is stopped
        lldp_status[uplink] = LLDP_STOP_STR
        if os.path.exists("/sys/bus/pci/devices/%s/driver" % pci_id):
            driver = os.path.basename(
                os.readlink("/sys/bus/pci/devices/%s/driver" % pci_id))
            if driver == X710_INTEL_DRIVER_STR:
                status = readfile("/sys/kernel/debug/%s/%s/command" %
                                  (driver, pci_id))
                # update the status
                if (status is LLDP_START_STR or status is LLDP_STOP_STR):
                    lldp_status[uplink] = status
                LOG.syslog("LLDP status read for Uplink %s pci_id %s "
                           "vendor %#04x device %#04x" %
                           (uplink, pci_id, vendor, device))
                return (True, pci_id)
        else:
            LOG.syslog("LLDP status not read for Uplink %s pci_id %s "
                       "vendor %#04x device %#04x as driver file "
                       "doesn't exist" % (uplink, pci_id, vendor, device))
    return (False, None)


def update_x710_lldp_status(pci_id, status):
    """This method should only be called when interface has been identified as

    x710 interface.

    :param pci_id:
    :param status:
    :return: None
    """
    writefile("/sys/kernel/debug/%s/%s/command"
              % (X710_INTEL_DRIVER_STR, pci_id),
              status)


def save_and_stop_x710_intf_lldp(intf):
    """This checks if the interface is x710 interface, if yes, it will save

    the status in a local variable and stop LLDP on that interface.

    :param intf:
    :return: True, if its x710 interface, False otherwise
    """
    is_x710, pci_id = save_x710_intf_lldp_status(intf)
    if is_x710:
        update_x710_lldp_status(pci_id, LLDP_STOP_STR)
        return True
    return False


def save_and_restore_x710_intf_lldp(intf):
    is_x710, pci_id = save_x710_intf_lldp_status(intf)
    if is_x710:
        update_x710_lldp_status(pci_id, lldp_status[intf.strip()])


def send_pktout_via_ovs(bridge_name, intf_ofport_num, hex_pkt):
    """Performs packet-out on OVS as described in ovs-ofctl manual [1]

    Complete params and options given at [1].

    [1] http://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.txt

    :param bridge_name: bridge name to which interface belongs
    :param intf_ofport_num: OFPort number of the interface w.r.t the bridge
    :param hex_pkt: packet to be sent out in hex format
    :return:
    """
    cmd = ("ovs-ofctl packet-out %(bridge_name)s LOCAL %(intf_ofport_num)s "
           "%(hex_pkt)s" % {'bridge_name': bridge_name,
                            'intf_ofport_num': intf_ofport_num,
                            'hex_pkt': hex_pkt})
    return execute_cmd(cmd)


def _generate_senders_frames(intfs, chassisid, args):
    senders = []
    frames = []
    systemname = socket.getfqdn()
    if args.system_name:
        systemname = args.system_name
    LOG.syslog("LLDP system-name is %s" % systemname)
    systemdesc = SYSTEM_DESC_LACP
    if args.system_desc:
        systemdesc = args.system_desc
    LOG.syslog("LLDP system-desc is %s" % systemdesc)
    for intf in intfs:
        interface = intf.strip()
        frame = lldp_frame_of(chassis_id=chassisid,
                              network_interface=interface,
                              ttl=TTL,
                              system_name=systemname,
                              system_desc=systemdesc)
        frames.append(frame)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((interface, 0))
        senders.append(s)
    return senders, frames


def _send_frames_kernel_socket(network_map, br_bond_name, args):
    """Send LLDP frames on all interfaces for the br_bond_name specified.

    :param network_map:
    :param br_bond_name:
    :param args:
    :return:
    """
    LOG.syslog("LLDP generating frames for %s" % br_bond_name)
    senders = []
    frames = []

    hostname_fqdn = get_fqdn_cli()
    if not hostname_fqdn:
        hostname_fqdn = socket.getfqdn()
    systemname = hostname_fqdn + '_' + br_bond_name
    LOG.syslog("LLDP system-name is %s" % systemname)
    # default system-desc for compute node's DPDK interface is STATIC
    systemdesc = SYSTEM_DESC_STATIC
    if network_map[br_bond_name]['lacp']:
        # if bonded nics, send LACP system-desc
        systemdesc = SYSTEM_DESC_LACP
    LOG.syslog("LLDP system-desc is %s" % systemdesc)
    chassis_id = None

    for member in network_map[br_bond_name]['members']:
        intf_name = member
        LOG.syslog("LLDP interface name is %s" % intf_name)
        mac_addr = get_mac_str(intf_name)
        if not mac_addr:
            # skip this interface if unable to get mac_addr
            LOG.syslog("LLDP unable to get mac_addr. Skip sending LLDP on "
                       "interface %s" % intf_name)
            continue
        LOG.syslog("LLDP interface mac is %s" % systemdesc)
        if not chassis_id:
            chassis_id = mac_addr
        LOG.syslog("LLDP chassis-id is %s" % chassis_id)
        frame = lldp_frame_of(
            chassis_id=chassis_id, network_interface=intf_name, ttl=TTL,
            system_name=systemname, system_desc=systemdesc,
            port_mac_str=mac_addr)
        frames.append(frame)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((intf_name, 0))
        senders.append(s)

    # send frames
    for idx, s in enumerate(senders):
        try:
            s.send(frames[idx])
        except Exception:
            continue


def send_lldp_on_all_interfaces(args, network_map):
    """Given a network_map of all bridges, bonds and their interfaces

    respectively. Send LLDP packets on each interface accordingly.

    :param args:
    :param network_map:
    :return:
    """
    for br_or_bond in network_map:
        root_type = network_map[br_or_bond]['config_type']
        if root_type == 'ovs_bridge':
            # save state in case of x710 nic
            for intf in network_map[br_or_bond]['members']:
                save_and_stop_x710_intf_lldp(intf)
            # send packet via kernel socket
            _send_frames_kernel_socket(
                network_map=network_map, br_bond_name=br_or_bond, args=args)
        elif root_type == 'linux_bond':
            # send  packet via kernel socket
            _send_frames_kernel_socket(
                network_map=network_map, br_bond_name=br_or_bond, args=args)
        elif root_type == 'ovs_user_bridge':
            # send packet via OVS packet out
            bridge_name = br_or_bond
            LOG.syslog("LLDP generating frames for %s" % bridge_name)

            chassis_id = "00:00:00:00:00:00"
            intf_tuple_list = []
            for member in network_map[br_or_bond]['members']:
                intf_name = member
                ofport_num = get_intf_ofport_number(intf_name=intf_name)
                mac_addr = get_dpdk_intf_mac_addr(intf_name=intf_name)
                LOG.syslog("LLDP DPDK interface name %s ofport_num %s "
                           "mac_addr %s" % (intf_name, ofport_num, mac_addr))
                if (not ofport_num or not mac_addr):
                    LOG.syslog("LLDP either ofport_num or mac_addr missing. "
                               "Skip sending LLDP on interface %s" % intf_name)
                    continue
                intf_tuple_list.append((intf_name, ofport_num, mac_addr))
            if len(intf_tuple_list) != 0:
                chassis_id = intf_tuple_list[0][2]
            LOG.syslog("LLDP chassis-id is %s" % chassis_id)
            hostname_fqdn = get_fqdn_cli()
            systemname = hostname_fqdn + '_' + bridge_name
            LOG.syslog("LLDP system-name is %s" % systemname)
            # default system-desc for compute node's DPDK interface is STATIC
            systemdesc = SYSTEM_DESC_STATIC
            if network_map[bridge_name]['lacp']:
                # if bonded nics, send LACP system-desc
                systemdesc = SYSTEM_DESC_LACP
            LOG.syslog("LLDP system-desc is %s" % systemdesc)
            # generate ovs-ofctl packet-out command for each interface
            for (intf_name, ofport_num, mac_addr) in intf_tuple_list:
                raw_frame = lldp_frame_of(
                    chassis_id=chassis_id, network_interface=intf_name,
                    ttl=120, system_name=systemname, system_desc=systemdesc,
                    port_mac_str=mac_addr)
                hex_pkt = raw_frame.encode('hex')
                send_pktout_via_ovs(bridge_name=bridge_name,
                                    intf_ofport_num=ofport_num,
                                    hex_pkt=hex_pkt)


def send_lldp_redhat(args):
    interval = INTERVAL
    if args.interval:
        interval = args.interval
    LOG.syslog("LLDP interval is %d" % interval)
    while True:
        network_map = get_network_interface_map()
        send_lldp_on_all_interfaces(args, network_map)
        time.sleep(interval)


def send_lldp():
    args = parse_args()
    if args.daemonize:
        daemonize()

    intfs = []
    platform_os = platform.linux_distribution()[0]
    os_is_redhat = "red hat" in platform_os.strip().lower()

    if os_is_redhat and not args.sriov:
        send_lldp_redhat(args)

    chassisid = "00:00:00:00:00:00"
    if args.network_interface:
        intfs = args.network_interface.split(',')

    LOG.syslog("LLDP interfaces are %s" % ','.join(intfs))
    LOG.syslog("LLDP chassisid is %s" % chassisid)

    senders, frames = _generate_senders_frames(intfs, chassisid, args)
    interval = INTERVAL
    if args.interval:
        interval = args.interval
    LOG.syslog("LLDP interval is %d" % interval)
    while True:
        for idx, s in enumerate(senders):
            try:
                s.send(frames[idx])
            except Exception:
                continue
        time.sleep(interval)


if __name__ == "__main__":
    send_lldp()
