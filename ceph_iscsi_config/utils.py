#!/usr/bin/env python
__author__ = 'pcuzner@redhat.com'

import socket
import netaddr
import netifaces
import struct
import subprocess
import rados
import datetime

import ceph_iscsi_config.settings as settings

class Defaults(object):
    pass
    # size_suffixes = ['M', 'G', 'T']
    # time_out = 30
    # loop_delay = 2
    # ceph_conf = '/etc/ceph/ceph.conf'
    # keyring = '/etc/ceph/ceph.client.admin.keyring'
    # ceph_user = 'admin'
    # rbd_map_file = '/etc/ceph/rbdmap'


def shellcommand(command_string):

    try:
        response = subprocess.check_output(command_string, shell=True)
    except subprocess.CalledProcessError:
        return None
    else:
        return response

def get_ip(addr):
    """
    return an ipv4 address for the given address - could be an ip or name passed in
    :param addr: name or ip address (dotted quad)
    :return: ipv4 address, or 0.0.0.0 if the address can't be validated as ipv4 or resolved from
             a name
    """

    converted_addr = '0.0.0.0'

    try:
        socket.inet_aton(addr)
    except socket.error:
        # not an ip address, maybe a name
        try:
            converted_addr = socket.gethostbyname(addr)
        except socket.error:
            pass
    else:
        converted_addr = addr


    return converted_addr

def valid_ip(ip, port=22):
    """
    Validate either a single IP or a list of IPs. An IP is valid if I can reach port 22 - since that's a common
    :param args:
    :return: Boolean
    """
    if isinstance(ip, str):
        ip_list = list([ip])
    elif isinstance(ip, list):
        ip_list = ip
    else:
        return False

    ip_OK = True

    for addr in ip_list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((addr, port))
        except socket.error:
            ip_OK = False
            break
        else:
            sock.close()

    return ip_OK


def valid_size(size):
    valid = True
    unit = size[-1]

    if unit.upper() not in settings.config.size_suffixes:
        valid = False
    else:
        try:
            value = int(size[:-1])
        except ValueError:
            valid = False

    return valid


def valid_cidr(subnet):
    """
    Confirm whether a given cidr is valid
    :param subnet: string of the form ip_address/netmask
    :return: Boolean representing when the CIDR passed is valid
    """

    try:
        ip, s_mask = subnet.split('/')
        netmask = int(s_mask)
        if not 1 <= netmask <= 32:
            raise ValueError
        ip_as_long = struct.unpack('!L', socket.inet_aton(ip))[0]
    except ValueError:
        # netmask is invalid
        return False
    except socket.error:
        # illegal ip address component
        return False

    # at this point the ip and netmask are ok to use, so return True
    return True


def ipv4_addresses():
    """
    return a list of IP addresses on the system
    :return: IP address list
    """
    ip_list = []
    for iface in netifaces.interfaces():
        # Skip interfaces that don't have IPv4 information (no AF_INET section (2))
        if netifaces.AF_INET not in netifaces.ifaddresses(iface):
            continue

        for link in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
            ip_list.append(link['addr'])

    return ip_list


def ipv4_address():
    """
    Generator function providing ipv4 network addresses on this host
    :return: IP address - dotted quad format
    """

    for iface in netifaces.interfaces():
        if len(netifaces.ifaddresses(iface)) < 3:
            continue
        for link in netifaces.ifaddresses(iface)[netifaces.AF_INET]:            # 3rd element (2)
            yield link['addr']


def get_ip_address(iscsi_network):
    """
    Return an IP address assigned to the running host that matches the given
    subnet address. This IP becomes the portal IP for the target portal group
    :param iscsi_network: cidr network address
    :return: IP address, or '' if the host does not have an interface on the required subnet
    """

    ip = ''
    subnet = netaddr.IPSet([iscsi_network])
    target_ip_range = [str(ip) for ip in subnet]   # list where each element is an ip address

    for local_ip in ipv4_address():
        if local_ip in target_ip_range:
            ip = local_ip
            break

    return ip


def convert_2_bytes(disk_size):

    power = [2, 3, 4]
    unit = disk_size[-1]
    offset = settings.config.size_suffixes.index(unit)
    value = int(disk_size[:-1])     # already validated, so no need for try/except clause

    _bytes = value*(1024**power[offset])

    return _bytes


def get_pool_id(conf=None, pool_name='rbd'):
    """
    Query Rados to get the pool id of a given pool name
    :param conf: ceph configuration file
    :param pool_name: pool name (str)
    :return: pool id (int)
    """

    if conf is None:
        conf = settings.config.cephconf

    with rados.Rados(conffile=conf) as cluster:
        pool_id = cluster.pool_lookup(pool_name)

    return pool_id


def get_pool_name(conf=None, pool_id=0):
    """
    Query Rados to get the pool name of a given pool_id
    :param conf: ceph configuration file
    :param pool_name: pool id number (int)
    :return: pool name (str)
    """

    if conf is None:
        conf = settings.config.cephconf

    with rados.Rados(conffile=conf) as cluster:
        pool_name = cluster.pool_reverse_lookup(pool_id)

    return pool_name


def get_time():
    utc = datetime.datetime.utcnow()
    return utc.strftime('%Y/%m/%d %H:%M:%S')