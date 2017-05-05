#!/usr/bin/env python

# import ceph_iscsi_config.settings as settings
import socket
import json
import requests
import sys
import rados
import rbd

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.utils import (get_ip, ipv4_addresses, gen_file_hash,
                                     valid_size, convert_2_bytes)


__author__ = 'pcuzner@redhat.com'

class Colors(object):

    map = {'green': '\x1b[32;1m',
           'red': '\x1b[31;1m',
           'yellow': '\x1b[33;1m',
           'blue': '\x1b[34;1m'}

def readcontents(filename):
    with open(filename, 'r') as input_file:
        content = input_file.read().rstrip()
    return content


def human_size(num):
    for unit, precision in [('b', 0), ('K', 0), ('M', 0), ('G', 0), ('T', 1),
                            ('P', 1), ('E', 2), ('Z', 2)]:
        if abs(num) < 1024.0:
            return "{0:.{1}f}{2}".format(num, precision, unit)
        num /= 1024.0
    return "{0:.2f}{1}".format(num, "Y")


def this_host():
    """
    return the local machine's shortname
    """
    return socket.gethostname().split('.')[0]

def get_config():
    """
    use the /config api to return the current gateway configuration
    :return: (dict) of the config object
    """

    http_mode = "https" if settings.config.api_secure else "http"
    api_rqst = "{}://127.0.0.1:{}/api/config".format(http_mode,
                                                     settings.config.api_port)
    api = APIRequest(api_rqst)
    api.get()

    if api.response.status_code == 200:
        return api.response.json()
    else:
        return {}


def valid_gateway(gw_name, gw_ip, config):
    """
    validate the request for a new gateway
    :param gw_name: (str) host (shortname) of the gateway
    :param gw_ip: (str) ipv4 address on the gw that will be used for iSCSI
    :param config: (dict) current config
    :return: (str) "ok" or error description
    """

    http_mode = 'https' if settings.config.api_secure else "http"

    # if the gateway request already exists in the config, computer says "no"
    if gw_name in config['gateways']:
        return "Gateway name {} already defined".format(gw_name)

    if gw_ip in config['gateways'].get('ip_list', []):
        return "IP address already defined to the configuration"

    # validate the gateway name is resolvable
    if get_ip(gw_name) == '0.0.0.0':
        return ("Gateway '{}' is not resolvable to an ipv4"
                " address".format(gw_name))

    # validate the ip_address is valid ipv4
    if get_ip(gw_ip) == '0.0.0.0':
        return ("IP address provided is not usable (name doesn't"
                " resolve, or not a valid ipv4 address)")

    # At this point the request seems reasonable, so lets check a bit deeper

    gw_api = '{}://{}:{}/api'.format(http_mode,
                                     gw_name,
                                     settings.config.api_port)

    # check the intended host actually has the requested IP available
    api = APIRequest(gw_api + '/sysinfo/ipv4_addresses')
    api.get()

    if api.response.status_code != 200:
        return ("ipv4_addresses query to {} failed - check"
                "rbd-target-api log, is the API server "
                "running?".format(gw_name))

    target_ips = api.response.json()['data']
    if gw_ip not in target_ips:
        return ("IP address of {} is not available on {}. Valid "
                "IPs are :{}".format(gw_ip,
                                     gw_name,
                                     ','.join(target_ips)))

    # check that config file on the new gateway matches the local machine
    api = APIRequest(gw_api + '/sysinfo/checkconf')
    api.get()
    if api.response.status_code != 200:
        return ("checkconf API call to {} failed with "
                "code".format(gw_name,
                              api.response.status_code))

    # compare the hash of the new gateways conf file with the local one
    local_hash = gen_file_hash('/etc/ceph/iscsi-gateway.cfg')
    remote_hash = str(api.response.json()['data'])
    if local_hash != remote_hash:
        return ("/etc/ceph/iscsi-gateway.cfg on {} does "
                "not match the local version. Correct and "
                "retry request".format(gw_name))

    # Check for package version dependencies
    api = APIRequest(gw_api + '/sysinfo/checkversions')
    api.get()
    if api.response.status_code != 200:
        errors = api.response.json()['data']
        return ("{} failed package validation checks - "
                "{}".format(gw_name,
                            ','.join(errors)))

    # At this point the gateway seems valid
    return "ok"


def rbd_size(pool, image, conf=None):
    """
    return the size of a given rbd from the local ceph cluster
    :param pool: (str) pool name
    :param image: (str) rbd image name
    :return: (int) size in bytes of the rbd
    """

    if conf is None:
        conf = settings.config.cephconf

    with rados.Rados(conffile=conf) as cluster:
        with cluster.open_ioctx(pool) as ioctx:
            with rbd.Image(ioctx, image) as rbd_image:
                size = rbd_image.size()
    return size


def rados_pools(conf=None):
    """
    return a list of pools in the local ceph cluster
    :param conf: (str) or None
    :return: (list) of pool names
    """

    if conf is None:
        conf = settings.config.cephconf

    with rados.Rados(conffile=conf) as cluster:
        pool_list = cluster.list_pools()

    return pool_list


def valid_disk(**kwargs):
    """
    determine whether the given image info is valid for a disk operation

    :param image_id: (str) <pool>.<image> format
    :return: (str) either 'ok' or an error description
    """

    mode_vars = {"create": ['pool', 'image', 'size'],
                 "resize": ['pool', 'image', 'size'],
                 "delete": ['pool', 'image']}

    config = get_config()

    if not config:
        return "Unable to query the local API for the current config"

    if 'mode' in kwargs.keys():
        mode = kwargs['mode']
    else:
        mode = None

    if mode in mode_vars:
        if not all(x in kwargs for x in mode_vars[mode]):
            return ("{} request must contain the following "
                    "variables: ".format(mode,
                                         ','.join(mode_vars[mode])))
    else:
        return "disk operation mode '{}' is invalid".format(mode)

    disk_key = "{}.{}".format(kwargs['pool'], kwargs['image'])

    if mode in ['create', 'resize']:

        if not valid_size(kwargs['size']):
            return "Size is invalid"

        elif kwargs['pool'] not in rados_pools():
            return "pool name is invalid"

    if mode == 'create':

        if disk_key in config['disks']:
            return "image of that name already defined"

        gateways_defined = len([key for key in config['gateways']
                               if isinstance(config['gateways'][key],
                                             dict)])
        if gateways_defined < settings.config.minimum_gateways:
            return ("disks can not be added until at least {} gateways "
                    "are defined".format(settings.config.minimum_gateways))


    if mode in ["resize", "delete"]:
        # disk must exist in the config
        if disk_key not in config['disks']:
            return ("rbd {}/{} is not defined to the "
                    "configuration".format(kwargs['pool'],
                                           kwargs['image']))


    if mode == 'resize':

        size = kwargs['size'].upper()
        current_size = rbd_size(kwargs['pool'], kwargs['image'])
        if convert_2_bytes(size) <= current_size:
            return ("resize value must be larger than the "
                    "current size ({}/{})".format(human_size(current_size),
                                                  current_size))

    if mode == 'delete':

        # disk must *not* be allocated to a client in the config
        allocation_list = []
        for client_iqn in config['clients']:
            client_metadata = config['clients'][client_iqn]
            if disk_key in client_metadata['luns']:
                allocation_list.append(client_iqn)

        if allocation_list:
            return ("Unable to delete disk {}. It is allocated to the "
                    "following clients:".format(disk_key,
                                                ','.join(allocation_list)))

    return 'ok'

def get_other_gateways(gw_objects):
    """
    Look at the set of objects passed and look for gateway objects,
    then return a list of gateway names that exclude the local
    machine
    :param gw_objects: set of objects to search
    :return: gateway names (list)
    """
    other_gateways = []

    local_gw = this_host()

    gws_root = list(gw_objects)  # children returns a set, so need to
                                                  # cast to a list
    if len(gws_root) > 0:
        gw_group = [obj for obj in gws_root[0].children if obj.name == 'gateways']
        gw_list = list(gw_group[0].children)        # list of Gateway objects

        for gw in gw_list:
            if gw.name == local_gw:
                continue
            other_gateways.append(gw.name)

    return other_gateways


class GatewayError(Exception):
    pass


class GatewayAPIError(GatewayError):
    pass


class GatewayLIOError(GatewayError):
    pass

class APIRequest(object):

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

        # Establish defaults for the API connection
        if 'auth' not in self.kwargs:
            self.kwargs['auth'] = (settings.config.api_user,
                                   settings.config.api_password)
        if 'verify' not in self.kwargs:
            self.kwargs['verify'] = settings.config.api_ssl_verify

        self.http_methods = ['get', 'put',  'delete']
        self.data = None

    def _get_response(self):
        return self.data

    def __getattr__(self, name):
        if name in self.http_methods:
            request_method = getattr(requests, name)
            try:
                self.data = request_method(*self.args, **self.kwargs)
            except requests.ConnectionError:
                raise GatewayAPIError("Unable to connect to api endpoint @ {}".format(self.args[0]))
            else:
                # since the attribute is a callable, we must return with
                # a callable
                return self._get_response
        raise AttributeError()

    response = property(_get_response,
                        doc="get http response output")


def progress_message(text, color='green'):

    sys.stdout.write("{}{}{}\r".format(Colors.map[color],
                                       text,
                                       '\x1b[0m'))
    sys.stdout.flush()

def console_message(text, color='green'):

    color_needed = getattr(settings.config, 'interactive', True)

    if color_needed:
        print("{}{}{}".format(Colors.map[color],
                              text,
                              '\x1b[0m'))
    else:
        print(text)

def get_port_state(ip_address, port):
    """
    Determine port state
    :param ip_address: ipv4 address dotted quad string
    :param port: port number
    :return: 0 = port open, !=0 port closed/inaccessible
    """

    socket.setdefaulttimeout(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        result = sock.connect_ex((ip_address, port))
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
    except socket.error:
        result = 16

    return result
