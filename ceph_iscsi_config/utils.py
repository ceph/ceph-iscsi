import socket
import netifaces
import subprocess
import rados
import rbd
import re
import datetime
import os

import ceph_iscsi_config.settings as settings

__author__ = 'pcuzner@redhat.com'

size_suffixes = ['M', 'G', 'T']


class CephiSCSIError(Exception):
    '''
    Generic Ceph iSCSI config error.
    '''
    pass


class CephiSCSIInval(CephiSCSIError):
    '''
    Invalid setting/param.
    '''
    pass


def shellcommand(command_string):

    try:
        response = subprocess.check_output(command_string, shell=True)
    except subprocess.CalledProcessError:
        return None
    else:
        return response


def normalize_ip_address(ip_address):
    """
    IPv6 addresses should not include the square brackets utilized by
    IPv6 literals (RFC 3986)
    """
    address_regex = re.compile(r"^\[(.*)\]$")
    match = address_regex.match(ip_address)
    if match:
        return match.group(1)
    return ip_address


def normalize_ip_literal(ip_address):
    """
    rtslib expects IPv4 addresses as a dotted-quad string, and IPv6
    addresses surrounded by brackets.
    """
    ip_address = normalize_ip_address(ip_address)
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
        return "[" + ip_address + "]"
    except Exception:
        pass

    return ip_address


def resolve_ip_addresses(addr):
    """
    return list of IPv4/IPv6 address for the given address - could be an ip or
    name passed in
    :param addr: name or ip address (dotted quad)
    :return: list of IPv4/IPv6 addresses
    """
    families = [socket.AF_INET, socket.AF_INET6]
    normalized_addr = normalize_ip_address(addr)
    for family in families:
        try:
            socket.inet_pton(family, normalized_addr)
            return [normalized_addr]
        except Exception:
            pass

    addrs = set()
    for family in families:
        try:
            infos = socket.getaddrinfo(addr, 0, family)
            for info in infos:
                addrs.add(info[4][0])
        except Exception:
            pass

    return list(addrs)


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

    ip_ok = True

    families = [socket.AF_INET, socket.AF_INET6]
    for addr in ip_list:
        addr_ok = False
        for family in families:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                sock.connect((addr, port))
            except socket.error:
                pass
            else:
                sock.close()
                addr_ok = True
                break

        if not addr_ok:
            ip_ok = False
            break
    return ip_ok


def valid_size(size):
    valid = True
    unit = size[-1]

    if unit.upper() not in size_suffixes:
        valid = False
    else:
        try:
            int(size[:-1])
        except ValueError:
            valid = False

    return valid


def format_lio_yes_no(value):
    if value:
        return "Yes"
    return "No"


def ip_addresses():
    """
    return a list of IPv4/IPv6 addresses on the system (excluding 127.0.0.1/::1)
    :return: IP address list
    """
    ip_list = set()
    for iface in netifaces.interfaces():
        if netifaces.AF_INET in netifaces.ifaddresses(iface):
            for link in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
                ip_list.add(link['addr'])
        if netifaces.AF_INET6 in netifaces.ifaddresses(iface):
            for link in netifaces.ifaddresses(iface)[netifaces.AF_INET6]:
                if '%' in link['addr']:
                    continue
                ip_list.add(link['addr'])

    ip_list.discard('::1')
    ip_list.discard('127.0.0.1')

    return list(ip_list)


def human_size(num):
    for unit, precision in [('b', 0), ('K', 0), ('M', 0), ('G', 0), ('T', 1),
                            ('P', 1), ('E', 2), ('Z', 2)]:
        if num % 1024 != 0:
            return "{0:.{1}f}{2}".format(num, precision, unit)
        num /= 1024.0
    return "{0:.2f}{1}".format(num, "Y")


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
    value = int(disk_size[:-1])  # already validated, so no need for try/except clause

    _bytes = value * (1024 ** power[offset])

    return _bytes


def get_pool_id(conf=None, pool_name=None):
    """
    Query Rados to get the pool id of a given pool name
    :param conf: ceph configuration file
    :param pool_name: pool name (str)
    :return: pool id (int)
    """

    if conf is None:
        conf = settings.config.cephconf
    if pool_name is None:
        pool_name = settings.config.pool

    with rados.Rados(conffile=conf, name=settings.config.cluster_client_name) as cluster:
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

    with rados.Rados(conffile=conf, name=settings.config.cluster_client_name) as cluster:
        pool_name = cluster.pool_reverse_lookup(pool_id)

    return pool_name


def get_rbd_size(pool, image, conf=None):
    """
    return the size of a given rbd from the local ceph cluster
    :param pool: (str) pool name
    :param image: (str) rbd image name
    :return: (int) size in bytes of the rbd
    """

    if conf is None:
        conf = settings.config.cephconf

    with rados.Rados(conffile=conf, name=settings.config.cluster_client_name) as cluster:
        with cluster.open_ioctx(pool) as ioctx:
            with rbd.Image(ioctx, image) as rbd_image:
                size = rbd_image.size()
    return size


def get_pools(conf=None):
    """
    return a list of pools in the local ceph cluster
    :param conf: (str) or None
    :return: (list) of pool names
    """

    if conf is None:
        conf = settings.config.cephconf

    with rados.Rados(conffile=conf, name=settings.config.cluster_client_name) as cluster:
        pool_list = cluster.list_pools()

    return pool_list


def get_time():
    utc = datetime.datetime.utcnow()
    return utc.strftime('%Y/%m/%d %H:%M:%S')


def this_host():
    """
    return the local machine's shortname
    """
    return socket.gethostname().split('.')[0]


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


def read_os_release():
    os_release_file = '/etc/os-release'
    d = {}
    if not os.path.exists(os_release_file):
        return d
    with open(os_release_file) as f:
        for line in f:
            rs = line.rstrip()
            if rs:
                k, v = rs.split("=")
                d[k] = v.strip('"')
    return d


def gen_control_string(controls):
    """
    Generate a kernel control string from a given dictionary
    of control arguments.
    :return: control string (str)
    """
    control = ''
    for key, value in controls.items():
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
