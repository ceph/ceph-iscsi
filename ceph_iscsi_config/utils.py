#!/usr/bin/env python

import socket
import netaddr
import netifaces
import struct
import subprocess
import rados
import datetime
import hashlib
import os
import rpm

import ceph_iscsi_config.settings as settings

__author__ = 'pcuzner@redhat.com'

size_suffixes = ['M', 'G', 'T']

class CephiSCSIError(Exception):
    '''
    Generic Ceph iSCSI config error.
    '''
    pass

def shellcommand(command_string):

    try:
        response = subprocess.check_output(command_string, shell=True)
    except subprocess.CalledProcessError:
        return None
    else:
        return response


def get_ip(addr):
    """
    return an ipv4 address for the given address - could be an ip or name
    passed in
    :param addr: name or ip address (dotted quad)
    :return: ipv4 address, or 0.0.0.0 if the address can't be validated as
    ipv4 or resolved from
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
    Validate either a single IP or a list of IPs. An IP is valid if I can
    reach port 22 - since that's a common
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

    if unit.upper() not in size_suffixes:
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


def format_lio_yes_no(value):
    if value:
        return "Yes"
    return "No"


def ipv4_addresses():
    """
    return a list of IPv4 addresses on the system (excluding 127.0.0.1)
    :return: IP address list
    """
    ip_list = []
    for iface in netifaces.interfaces():
        # Skip interfaces that don't have IPv4 information (no AF_INET
        # section (2))
        if netifaces.AF_INET not in netifaces.ifaddresses(iface):
            continue

        for link in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
            ip_list.append(link['addr'])

    ip_list.remove('127.0.0.1')

    return ip_list


def ipv4_address():
    """
    Generator function providing ipv4 network addresses on this host
    :return: IP address - dotted quad format
    """

    for iface in netifaces.interfaces():
        if len(netifaces.ifaddresses(iface)) < 3:
            continue
        for link in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
            if link['addr'] != '127.0.0.1':
                yield link['addr']


def get_ip_address(iscsi_network):
    """
    Return an IP address assigned to the running host that matches the given
    subnet address. This IP becomes the portal IP for the target portal group
    :param iscsi_network: cidr network address
    :return: IP address, or '' if the host does not have an interface on the
    required subnet
    """

    ip = ''
    subnet = netaddr.IPSet([iscsi_network])
    target_ip_range = [str(ip) for ip in subnet]   # list where each element
                                                   # is an ip address

    for local_ip in ipv4_address():
        if local_ip in target_ip_range:
            ip = local_ip
            break

    return ip


def convert_2_bytes(disk_size):

    try:
        # If it's already an integer or a string with no suffix then assume
        # it's already in bytes.
        return int(disk_size)
    except ValueError:
        pass

    power = [2, 3, 4]
    unit = disk_size[-1].upper()
    offset = size_suffixes.index(unit)
    value = int(disk_size[:-1])     # already validated, so no need for
                                    # try/except clause

    _bytes = value*(1024**power[offset])

    return _bytes


def human_size(num):
    """
    convert a bytes value into a more human readable format
    :param num(int): bytes
    :return: Size as M/G/T suffixed
    """
    for unit, precision in [('b', 0), ('K', 0), ('M', 0), ('G', 0), ('T', 0),
                            ('P', 1), ('E', 2), ('Z', 2)]:
        if abs(num) < 1024.0:
            return "{0:.{1}f}{2}".format(num, precision, unit)
        num /= 1024.0
    return "{0:.2f}{1}".format(num, "Y")


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


def this_host():
    """
    return the local machine's shortname
    """
    return socket.gethostname().split('.')[0]


def gen_file_hash(filename, hash_type='sha256'):
    """
    generate a hash(default sha256) of a file and return the result
    :param filename: filename to generate the checksum for
    :param hash_type: type of checksum to generate
    :return: checkum (str)
    """

    if (hash_type not in ['sha1', 'sha256', 'sha512', 'md5'] or
            not os.path.exists(filename)):
        return ''

    hash_function = getattr(hashlib, hash_type)
    h = hash_function()

    with open(filename, 'rb') as file_in:
        chunk = 0
        while chunk != b'':
            chunk = file_in.read(1024)
            h.update(chunk)

    return h.hexdigest()


def valid_rpm(in_rpm):
    """
    check a given rpm matches the current installed rpm
    :param in_rpm: a dict of name, version and release to check against
    :return: bool representing whether the rpm is valid or not
    """
    rpm_state = False

    ts = rpm.TransactionSet()
    mi = ts.dbMatch('name', in_rpm['name'])
    if mi:
        # check the version is OK
        rpm_hdr = mi.next()
        rc = rpm.labelCompare(('1', rpm_hdr['version'], rpm_hdr['release']),
                              ('1', in_rpm['version'], in_rpm['release']))

        if rc < 0:
            # -1 version old
            return False
        else:
            # 0 = version match, 1 = version exceeds min requirement
            return True
    else:
        # rpm not installed
        return False


def encryption_available():
    """
    Determine whether encryption is available by looking for the relevant
    keys
    :return: (bool) True if all keys are present, else False
    """
    encryption_keys = list([settings.config.priv_key,
                           settings.config.pub_key])


    config_dir = settings.config.ceph_config_dir
    keys = [os.path.join(config_dir, key_name)
            for key_name in encryption_keys]

    return all([os.path.exists(key) for key in keys])

def gen_control_string(controls):
    """
    Generate a kernel control string from a given dictionary
    of control arguments.
    :return: control string (str)
    """
    control=''
    for key,value in controls.iteritems():
        if value is not None:
            control += "{}={},".format(key, value)
    return None if control == '' else control[:-1]

class ListComparison(object):

    def __init__(self, current_list, new_list):
        """
        compare two lists to identify changes
        :param current_list : list of current values (existing state)
        :param new_list: list if new values (desired state)
        """
        self.current = current_list
        self.new = new_list
        self.changed = False

    @property
    def added(self):
        """
        provide a list of added items
        :return: (list) in the sequence provided
        """
        additions = set(self.new) - set(self.current)
        if len(additions) > 0:
            self.changed = True

        # simply returning the result of the set comparison does not preserve
        # the list item sequence. By iterating over the new list we can
        # return the expected sequence
        return [item for item in self.new if item in additions]

    @property
    def removed(self):
        """
        calculate the removed items between two lists using set comparisons
        :return: (list) removed items
        """
        removals = set(self.current) - set(self.new)
        if len(removals) > 0:
            self.changed = True
        return list(removals)

