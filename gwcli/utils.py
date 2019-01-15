#!/usr/bin/env python

import socket
import requests
from requests import Response
import sys
import re
import os
import subprocess


from rtslib_fb.utils import normalize_wwn, RTSLibError
import rtslib_fb.root as root

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.utils import (resolve_ip_addresses, gen_file_hash,
                                     CephiSCSIError)

__author__ = 'Paul Cuzner'


class Colors(object):

    map = {'green': '\x1b[32;1m',
           'red': '\x1b[31;1m',
           'yellow': '\x1b[33;1m',
           'blue': '\x1b[34;1m'}


def readcontents(filename):
    with open(filename, 'r') as input_file:
        content = input_file.read().rstrip()
    return content


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
    api_rqst = "{}://localhost:{}/api/config".format(http_mode,
                                                     settings.config.api_port)
    api = APIRequest(api_rqst)
    api.get()

    if api.response.status_code == 200:
        try:
            return api.response.json()
        except Exception:
            pass

    return {}


def valid_iqn(iqn):
    """
    confirm whether the given iqn is in an acceptable format
    :param iqn: (str) iqn name to check
    :return: (bool) True if iqn is valid for iSCSI
    """

    try:
        normalize_wwn(['iqn'], iqn)
    except RTSLibError:
        return False

    return True


def valid_gateway(target_iqn, gw_name, gw_ip, config):
    """
    validate the request for a new gateway
    :param gw_name: (str) host (shortname) of the gateway
    :param gw_ip: (str) ip address on the gw that will be used for iSCSI
    :param config: (dict) current config
    :return: (str) "ok" or error description
    """

    http_mode = 'https' if settings.config.api_secure else "http"

    # if the gateway request already exists in the config, computer says "no"
    target_config = config['targets'][target_iqn]
    if gw_name in target_config['portals']:
        return "Gateway name {} already defined".format(gw_name)

    if gw_ip in target_config.get('ip_list', []):
        return "IP address already defined to the configuration"

    # validate the gateway name is resolvable
    if not resolve_ip_addresses(gw_name):
        return ("Gateway '{}' is not resolvable to an IP address".format(gw_name))

    # validate the ip_address is valid ip
    if not resolve_ip_addresses(gw_ip):
        return ("IP address provided is not usable (name doesn't"
                " resolve, or not a valid IPv4/IPv6 address)")

    # At this point the request seems reasonable, so lets check a bit deeper

    gw_api = '{}://{}:{}/api'.format(http_mode,
                                     gw_name,
                                     settings.config.api_port)

    # check the intended host actually has the requested IP available
    api = APIRequest(gw_api + '/sysinfo/ip_addresses')
    api.get()

    if api.response.status_code != 200:
        return ("ip_addresses query to {} failed - check "
                "rbd-target-api log. Is the API server "
                "running and in the right mode (http/https)?".format(gw_name))

    try:
        target_ips = api.response.json()['data']
    except Exception:
        return "Malformed REST API response"

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
    try:
        remote_hash = str(api.response.json()['data'])
    except Exception:
        remote_hash = None

    if local_hash != remote_hash:
        return ("/etc/ceph/iscsi-gateway.cfg on {} does "
                "not match the local version. Correct and "
                "retry request".format(gw_name))

    # Check for package version dependencies
    api = APIRequest(gw_api + '/sysinfo/checkversions')
    api.get()
    if api.response.status_code != 200:
        try:
            errors = api.response.json()['data']
        except Exception:
            return "Malformed REST API response"

        return ("{} failed package validation checks - "
                "{}".format(gw_name,
                            ','.join(errors)))

    # At this point the gateway seems valid
    return "ok"


def get_remote_gateways(config, logger, local_gw_required=True):
    '''
    Return the list of remote gws.
    :param: config: Config object with gws setup.
    :param: logger: Logger object
    :param: local_gw_required: Check if local_gw is defined within gateways configuration
    :return: A list of gw names, or CephiSCSIError if not run on a gw in the
             config
    '''
    local_gw = this_host()
    logger.debug("this host is {}".format(local_gw))
    gateways = [key for key in config
                if isinstance(config[key], dict)]
    logger.debug("all gateways - {}".format(gateways))
    if local_gw_required and local_gw not in gateways:
        raise CephiSCSIError("{} cannot be used to perform this operation "
                             "because it is not defined within the gateways "
                             "configuration".format(local_gw))
    if local_gw in gateways:
        gateways.remove(local_gw)
    logger.debug("remote gateways: {}".format(gateways))
    return gateways


def valid_credentials(credentials_str, auth_type='chap'):
    """
    Return a boolean indicating whether the credentials supplied are
    acceptable
    """

    # regardless of the auth_type, the credentials_str must be of
    # for form <username>/<password>
    try:
        user_name, password = credentials_str.split('/')
    except ValueError:
        return False

    if auth_type == 'chap':
        # username is 8-64 chars long containing any alphanumeric in
        # [0-9a-zA-Z] and '.' ':' '@' '_' '-'
        # password is 12-16 chars long containing any alphanumeric in
        # [0-9a-zA-Z] and '@' '-' '_' or !,_,& symbol
        usr_regex = re.compile(r"^[\w\\.\:\@\_\-]{8,64}$")
        pw_regex = re.compile(r"^[\w\@\-\_]{12,16}$")
        if not usr_regex.search(user_name) or not pw_regex.search(password):
            return False

        return True
    else:
        # insert mutual or any other credentials logic here!
        return True


def valid_client(**kwargs):
    """
    validate a client create or update request, based on mode.
    :param kwargs: 'mode' is the key field used to determine process flow
    :return: 'ok' or an error description (str)
    """

    valid_modes = ['create', 'delete', 'auth', 'disk']
    parms_passed = set(kwargs.keys())

    if 'mode' in kwargs:
        if kwargs['mode'] not in valid_modes:
            return ("Invalid client validation mode request - "
                    "asked for {}, available {}".format(kwargs['mode'],
                                                        valid_modes))
    else:
        return "Invalid call to valid_client - mode is needed"

    # at this point we have a mode to work with

    mode = kwargs['mode']
    client_iqn = kwargs['client_iqn']
    target_iqn = kwargs['target_iqn']
    config = get_config()
    if not config:
        return "Unable to query the local API for the current config"
    target_config = config['targets'][target_iqn]

    if mode == 'create':
        # iqn must be valid
        if not valid_iqn(client_iqn):
            return ("Invalid IQN name for iSCSI")

        # iqn must not already exist
        if client_iqn in target_config['clients']:
            return ("A client with the name '{}' is "
                    "already defined".format(client_iqn))

        # Creates can only be done with a minimum number of gw's in place
        num_gws = len([gw_name for gw_name in config['gateways']
                       if isinstance(config['gateways'][gw_name], dict)])
        if num_gws < settings.config.minimum_gateways:
            return ("Clients can not be defined until a HA configuration "
                    "has been defined "
                    "(>{} gateways)".format(settings.config.minimum_gateways))

        # at this point pre-req's look good
        return 'ok'

    elif mode == 'delete':

        # client must exist in the configuration
        if client_iqn not in target_config['clients']:
            return ("{} is not defined yet - nothing to "
                    "delete".format(client_iqn))

        this_client = target_config['clients'].get(client_iqn)
        if this_client.get('group_name', None):
            return ("Unable to delete '{}' - it belongs to "
                    "group {}".format(client_iqn,
                                      this_client.get('group_name')))

        # client to delete must not be logged in - we're just checking locally,
        # since *all* nodes are set up the same, and a client login request
        # would normally login to each gateway
        lio_root = root.RTSRoot()
        clients_logged_in = [session['parent_nodeacl'].node_wwn
                             for session in lio_root.sessions
                             if session['state'] == 'LOGGED_IN']

        if client_iqn in clients_logged_in:
            return ("Client '{}' is logged in - unable to delete until"
                    " it's logged out".format(client_iqn))

        # at this point, the client looks ok for a DELETE operation
        return 'ok'

    elif mode == 'auth':
        chap = kwargs['chap']
        # client iqn must exist
        if client_iqn not in target_config['clients']:
            return ("Client '{}' does not exist".format(client_iqn))

        # must provide chap as either '' or a user/password string
        if 'chap' not in kwargs:
            return ("Client auth needs 'chap' defined")

        # credentials string must be valid
        if chap:
            if not valid_credentials(chap):
                return ("Invalid format for CHAP credentials. Refer to 'help' "
                        "or documentation for the correct format")

        return 'ok'

    elif mode == 'disk':

        this_client = target_config['clients'].get(client_iqn)
        if this_client.get('group_name', None):
            return ("Unable to manage disks for '{}' - it belongs to "
                    "group {}".format(client_iqn,
                                      this_client.get('group_name')))

        if 'image_list' not in parms_passed:
            return ("Disk changes require 'image_list' to be set, containing"
                    " a comma separated str of rbd images (pool.image)")

        rqst_disks = set(kwargs['image_list'].split(','))
        mapped_disks = set(target_config['clients'][client_iqn]['luns'].keys())
        current_disks = set(config['disks'].keys())

        if len(rqst_disks) > len(mapped_disks):
            # this is an add operation

            # ensure the image list is 'complete' not just a single disk
            if not mapped_disks.issubset(rqst_disks):
                return ("Invalid image list - it must contain existing "
                        "disks AND any additions")

            # ensure new disk(s) exist - must yield a result since rqst>mapped
            new_disks = rqst_disks.difference(mapped_disks)
            if not new_disks.issubset(current_disks):
                # disks provided are not currently defined
                return ("Invalid image list - it defines new disks that do "
                        "not current exist")

            return 'ok'

        else:

            # this is a disk removal operation
            if kwargs['image_list']:
                if not rqst_disks.issubset(mapped_disks):
                    return ("Invalid image list ({})".format(rqst_disks))

            return 'ok'

    return 'Unknown error in valid_client function'


def valid_snapshot_name(name):
    regex = re.compile("^[^/@]+$")
    if not regex.search(name):
        return False
    return True


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

        self.http_methods = ['get', 'put', 'delete']
        self.data = None

    def _get_response(self):
        return self.data

    def __getattr__(self, name):
        if name in self.http_methods:
            request_method = getattr(requests, name)
            try:
                self.data = request_method(*self.args, **self.kwargs)
            except requests.ConnectionError:
                msg = ("Unable to connect to api endpoint @ "
                       "{}".format(self.args[0]))
                self.data = Response()
                self.data.status_code = 500
                self.data._content = '{{"message": "{}" }}'.format(msg)
                return self._get_response
            except Exception:
                raise GatewayAPIError("Unknown error connecting to "
                                      "{}".format(self.args[0]))
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


def cmd_exists(command):
    return any(
        os.access(os.path.join(path, command), os.X_OK)
        for path in os.environ["PATH"].split(os.pathsep)
    )


def os_cmd(command):
    """
    Issue a command to the OS and return the output. NB. check_output default
    is shell=False
    :param command: (str) OS command
    :return: (str) command response (lines terminated with \n)
    """
    cmd_list = command.split(' ')
    if cmd_exists(cmd_list[0]):
        cmd_output = subprocess.check_output(cmd_list,
                                             stderr=subprocess.STDOUT).rstrip()
        return cmd_output
    else:
        return ''


def response_message(response, logger=None):
    """
    Attempts to retrieve the "message" value from a JSON-encoded response
    message. If the JSON fails to parse, the response will be returned
    as-is.
    :param response: (requests.Response) response
    :param logger: optional logger
    :return: (str) response message
    """
    try:
        return response.json()['message']
    except Exception:
        if logger:
            logger.debug("Failed API request: {} {}\n{}".format(response.request.method,
                                                                response.request.url,
                                                                response.text))
        return "{} {}".format(response.status_code, response.reason)
