#!/usr/bin/env python

# import ceph_iscsi_config.settings as settings
import socket
import json
import requests
import sys

import ceph_iscsi_config.settings as settings

__author__ = 'pcuzner@redhat.com'

class Colors(object):

    map = {'green': '\x1b[32;1m',
           'red': '\x1b[31;1m',
           ' yellow': '\x1b[33;1m',
           ' blue': '\x1b[34;1m'}

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
    print("{}{}{}".format(Colors.map[color],
                          text,
                          '\x1b[0m'))

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
