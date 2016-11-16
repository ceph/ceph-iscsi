#!/usr/bin/env python
__author__ = 'pcuzner@redhat.com'

# import ceph_iscsi_config.settings as settings
import socket
import json


def readcontents(filename):
    with open(filename, 'r') as input_file:
        content = input_file.read().rstrip()
    return content


def human_size(num):
    for unit, precision in [('b', 0), ('K', 0), ('M', 0), ('G', 0), ('T', 1), ('P', 1), ('E', 2), ('Z', 2)]:
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

    local_gw = this_host()

    gws_root = list(gw_objects)  # children returns a set, so need to
                                                  # cast to a list
    gw_group = [obj for obj in gws_root[0].children if obj.name == 'gateways']
    gw_list = list(gw_group[0].children)        # list of Gateway objects
    other_gateways = []
    for gw in gw_list:
        if gw.name == local_gw:
            continue
        other_gateways.append(gw.name)

    return other_gateways


class GatewayError(Exception):
    pass


class GatewayAPIError(GatewayError):

    def __init__(self, msg):
        msg_js = json.loads(msg)
        self.msg = msg_js['message']
    def __str__(self):
        return repr(self.msg)


class GatewayLIOError(GatewayError):
    pass


# def console_message(message, colour='green'):
#
#     colour_map = {'blue': '\033[94m',
#                   'green': '\033[92m',
#                   'yellow': '\033[93m',
#                   'red': '\033[91m'}
#
#     end_sequence = '\033[0m'
#
#     if colour in colour_map:
#         print colour_map[colour] + message + end_sequence
#     else:
#         print message

