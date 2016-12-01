#!/usr/bin/env python
__author__ = 'pcuzner@redhat.com'

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

    power = [2, 3, 4]
    unit = disk_size[-1]
    offset = settings.config.size_suffixes.index(unit)
    value = int(disk_size[:-1])     # already validated, so no need for
                                    # try/except clause

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


class ConfigData(object):
    """
    base class with generic methods inherited by the upper level
    classes ConfFile, ConfSection and ConfSubsection
    """

    def __init__(self, name='root'):
        self._name = name
        self._children = []

    def __repr__(self):
        return "{} - {}".format(self.__class__.__name__,
                                self._name)

    def _get_items(self):
        return [attribute for attribute in self.__dict__.keys()
                if not attribute.startswith('_')]

    def _num_children(self):
        return len(self._children)

    def _get_sections(self):
        return [section for section in self._children]

    def _get_children(self):
        return self._children

    children = property(_get_children,
                        doc="return a list of subsection objects")
    sections = property(_get_sections,
                        doc="return list of parsed sections in the conf file")
    items = property(_get_items,
                     doc="return a list of field names")
    num_sections = property(_num_children,
                            doc="return a count of child objects")


class ConfFile(ConfigData):
    """
    Configuration File Handler class allowing the files parameters and
    sections to be inspected. The expected file format uses {} to
    enclose sections, and has been tested against lvm.conf and multipath.conf

    """

    # list that defines names that would clash with python internal names
    restricted_sections = {'global': '_global_'}

    def __init__(self, file_name):

        self._file_name = file_name

        ConfigData.__init__(self)
        with open(file_name) as conf_file:
            self._config_file = conf_file.read().splitlines()

        self._parse_conf()

    def _parse_conf(self):

        # current_section stores the breadcrumbs for section/subsection
        # being processed
        current_section = []
        for line in self._config_file:

            line = line.rstrip()

            if line.strip().startswith('#') or \
                    not line:
                continue

            if line.endswith('{'):
                section_name = line.split('{')[0].strip()
                section_name = ConfFile.restricted_sections.get(section_name,
                                                                section_name)
                current_section.append(section_name)

                if len(current_section) == 1:
                    current = getattr(self, section_name, None)
                    if not current:

                        setattr(self,
                                section_name,
                                ConfSection(section_name,
                                            self))

                        current = getattr(self, section_name)

                else:
                    parent = getattr(self, current_section[-2])
                    subsection = ConfSubsection(section_name)
                    parent._children.append(subsection)
                    current = subsection

            elif line.endswith('}'):
                del current_section[-1]

            else:
                if not line:
                    continue
                line = line.strip()

                if '=' in line :
                    fields = line.split('=')
                else:
                    fields = line.split()

                key = fields[0].strip()
                value = fields[-1].lstrip()
                # print "*{}* = *{}*".format(key, value)
                setattr(current, key, value)

    def get(self, section_name, attribute):
        """
        get method similar to the ConfigParser get method
        :param section_name: config file section
        :param attribute: attribute to extract
        :return: value of attribute or None
        """

        section = getattr(self, section_name, None)

        if not section:
            raise ValueError("{} section not in {}".format(section_name,
                                                           self._file_name))

        return getattr(section, attribute, None)

    def items(self, section_name):
        """
        similar method to ConfigParser items, returning a list
        of attributes for the current specified section
        :param section_name: configuration section
        :return: list of attributes present in the configuration section
        """
        section = getattr(self, section_name, None)

        if not section:
            raise ValueError("{} section not in {}".format(section_name,
                                                           self._file_name))

        return section.items

    def __str__(self):
        out = "Filename : {}\n".format(self._file_name)
        for s in self._children:
            out += "Section: {}, {} attributes\n".format(s._name,
                                                         len(s.items))
        return out

    def _valid_config(self):
        return True if len(self._children) > 0 else False

    valid = property(_valid_config,
                     doc="Config object validity(boolean)")

class ConfSection(ConfigData):
    def __init__(self, name, parent):
        # print "created section {}".format(name)
        ConfigData.__init__(self, name)
        self._parent = parent
        self._parent._children.append(self)

    def __str__(self):
        attr_list = self.items
        out = ''
        for i in attr_list:
            out += " {}={}\n".format(i,getattr(self,i))
        return out


class ConfSubsection(ConfigData):
    def __init__(self, name):
        # print "created subsection {}".format(name)
        ConfigData.__init__(self, name)


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
