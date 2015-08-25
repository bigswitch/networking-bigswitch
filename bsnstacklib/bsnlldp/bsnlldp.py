#!/usr/bin/env python
#
# Sends LLDP packets out of a specified network interface,
# either once or periodically at a fixed interval.
# The process can be optionally daemonized.
#
# Previous version:
#
# GitHub Repository: bigswitch/bigswitchcontroller
# Branch: bigdb
# Path: bare-metal/hypervisor/pcap_start_lldp.py
#

import argparse
import socket
import os
import time
# Get all network interfaces
# Based on getifaddrs.py from pydlnadms [http://code.google.com/p/pydlnadms/].
from socket import AF_INET, AF_INET6, inet_ntop
from ctypes import (
    Structure, Union, POINTER,
    pointer, get_errno, cast,
    c_ushort, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
)
import ctypes.util
import ctypes
from subprocess import check_output

LLDP_DST_MAC = "01:80:c2:00:00:0e"
SYSTEM_DESC = "5c:16:c7:00:00:04"
LLDP_ETHERTYPE = 0x88cc
CHASSIS_ID = "Big Cloud Fabric"
TTL = 120
INTERVAL = 10

CHASSIS_ID_LOCALLY_ASSIGNED = 7

PORT_ID_INTERFACE_ALIAS = 1

class struct_sockaddr(Structure):
    _fields_ = [
        ('sa_family', c_ushort),
        ('sa_data', c_byte * 14),]

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
        ('ifu_dstaddr', POINTER(struct_sockaddr)),]

class struct_ifaddrs(Structure):
    pass
struct_ifaddrs._fields_ = [
    ('ifa_next', POINTER(struct_ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),
    ('ifa_addr', POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    ('ifa_ifu', union_ifa_ifu),
    ('ifa_data', c_void_p),]

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
    parser.add_argument("-d", "--daemonize", action="store_true", default=False)

    return parser.parse_args()

def validate_num_bits_of_int(int_value, num_bits, name=None):
    mask = pow(2, num_bits) - 1
    if (int_value & mask) != int_value:
        name = name if name else "The integer value"
        raise ValueError("%s must be %d-bit long. Given: %d (%s)"
                % (name, num_bits, int_value, hex(int_value)))

def raw_bytes_of_hex_str(hex_str):
    return hex_str.decode("hex")

def raw_bytes_of_mac_str(mac_str):
    return raw_bytes_of_hex_str(mac_str.replace(":", ""))

def raw_bytes_of_int(int_value, num_bytes, name=None):
    validate_num_bits_of_int(int_value, num_bytes * 8, name)
    template = "%0" + "%d" % (num_bytes * 2) + "x"
    return raw_bytes_of_hex_str(template % int_value)

def get_mac_str(network_interface):
    with open("/sys/class/net/%s/address" % network_interface) as f:
        return f.read().strip()

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
    return tlv_of(1,
            raw_bytes_of_int(subtype, 1, "Chassis ID subtype") + chassis_id)

def port_id_tlv_of(port_id, subtype=PORT_ID_INTERFACE_ALIAS):
    return tlv_of(2, raw_bytes_of_int(subtype, 1, "Port ID subtype") + port_id)

def ttl_tlv_of(ttl_seconds):
    return tlv_of(3, raw_bytes_of_int(ttl_seconds, 2, "TTL (seconds)"))

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
                  system_desc=None):
    contents = [
        # Ethernet header
        raw_bytes_of_mac_str(LLDP_DST_MAC),
        raw_bytes_of_mac_str(get_mac_str(network_interface)),
        lldp_ethertype(),

        # Required LLDP TLVs
        chassis_id_tlv_of(chassis_id),
        port_id_tlv_of(network_interface),
        ttl_tlv_of(ttl)
        ]

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

def get_hostname():
    return socket.gethostname()

def get_phy_interfaces():
    intf_list = []
    nics = get_network_interfaces()
    for ni in nics:
        if ni.addresses.get(AF_INET):
            continue
        try:
            cmd_out = check_output("ethtool " + ni.name + " | grep 'Supported ports'", shell=True)
            if "[ ]" not in cmd_out:
                # value is present in [ TP ], its not empty list
                intf_list.append(ni.name)
        except:
            # interface doesn't have supported ports list
            pass
    return intf_list

def main():
    args = parse_args()

    if args.daemonize:
        daemonize()

    def _generate_senders_frames():
      senders = []
      frames = []
      intfs = get_phy_interfaces()
      for intf in intfs:
        interface = intf.strip()
        frame = lldp_frame_of(chassis_id=CHASSIS_ID,
                              network_interface=interface,
                              ttl=TTL,
                              system_name=get_hostname(),
                              system_desc=SYSTEM_DESC) 
        frames.append(frame)

        # Send the frame
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((interface, 0))
        senders.append(s)
      return senders, frames


    while True:
        senders, frames = _generate_senders_frames()
        for idx, s in enumerate(senders):
            s.send(frames[idx])
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()

