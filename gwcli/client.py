#!/usr/bin/env python

__author__ = 'pcuzner@redhat.com'

import json
import re

from requests import delete, put, get, ConnectionError

from gwcli.node import UIGroup, UINode

from gwcli.utils import (human_size, get_other_gateways,
                    GatewayAPIError, GatewayLIOError,
                    this_host)

import ceph_iscsi_config.settings as settings


import rtslib_fb.root as root
from rtslib_fb.utils import normalize_wwn, RTSLibError

# FIXME - this ignores the warning issued when verify=False is used
from requests.packages import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Clients(UIGroup):
    help_intro = '''
                 Clients bla
                 '''

    def __init__(self, parent, client_info={}):
        UIGroup.__init__(self, 'hosts', parent)
        self.client_info = client_info
        self.logger = self.parent.parent.parent.logger
        self.load_clients()

    def load_clients(self):
        for client_iqn, client_settings in self.client_info.iteritems():
            Client(self, client_iqn, client_settings)

    def reset(self):
        children = set(self.children)  # set of child objects
        for child in children:
            self.remove_child(child)

    def ui_command_create(self, client_iqn):
        """
        Clients may be created using the 'create' sub-command. The initial
        definition will be added to each gateway without any authentication
        set, so once the client is created you must 'cd' to the client and
        add authentication (auth) and any desired disks (disk).

        > create <client_iqn>

        """

        cli_seed = {"luns": {}, "auth": {}}

        # make sure the iqn isn't already defined
        existing_clients = [client.name for client in self.children]
        if client_iqn in existing_clients:
            self.logger.error("Client '{}' is already defined".format(client_iqn))
            return


        try:
            valid_iqn = normalize_wwn(['iqn'], client_iqn)
        except RTSLibError:
            self.logger.critical("An iqn of '{}' is not a valid name for iSCSI".format(client_iqn))
            return


        # run the create locally - to seed the config object
        other_gateways = get_other_gateways(self.parent.parent.parent.target.children)
        api_vars = {"committing_host": this_host()}
        client_api = '{}://127.0.0.1:{}/api/client/{}'.format(self.http_mode,
                                                              settings.config.api_port,
                                                              client_iqn)

        self.logger.debug("Client CREATE for {}".format(client_iqn))
        response = put(client_api,
                       data=api_vars,
                       auth=(settings.config.api_user, settings.config.api_password),
                       verify=settings.config.api_ssl_verify)

        if response.status_code == 200:
            Client(self, client_iqn, cli_seed)
            self.logger.debug("- Client '{}' added locally".format(client_iqn))
            # defined locally OK, so let's apply to the other gateways
            for gw in other_gateways:
                client_api = '{}://{}:{}/api/client/{}'.format(self.http_mode,
                                                               gw,
                                                               settings.config.api_port,
                                                               client_iqn)

                response = put(client_api,
                               data=api_vars,
                               auth=(settings.config.api_user, settings.config.api_password),
                               verify=settings.config.api_ssl_verify)

                if response.status_code == 200:
                    self.logger.debug("- Client '{}' added to {}".format(client_iqn, gw))
                    continue
                else:
                    raise GatewayAPIError(response.text)
        else:
            raise GatewayAPIError(response.text)

        self.logger.info('ok')

    def ui_command_delete(self, client_iqn):
        """
        You may delete a client from the configuration, but you must ensure that
        the client has logged out of the iscsi gateways. Attempting to delete a
        client that has an open session will fail the request

        > delete <client_iqn>

        """
        # check the iqn given matches one of the child objects - i.e. it's valid
        client_names = [child.name for child in self.children]
        if client_iqn not in client_names:
            self.logger.error("Host with an iqn of '{}' is not defined...mis-typed?".format(client_iqn))
            return

        lio_root = root.RTSRoot()
        clients_logged_in = [session['parent_nodeacl'].node_wwn for session in lio_root.sessions
                             if session['state'] == 'LOGGED_IN']

        if client_iqn in clients_logged_in:
            self.logger.error("Host '{}' is logged in - unable to delete until it's logged out".format(client_iqn))
            return

        # At this point we know the client requested is defined to the configuration
        # and is not currently logged in (at least to this host), OK to delete
        self.logger.debug("Client DELETE for {}".format(client_iqn))
        client = [client for client in self.children if client.name == client_iqn][0]

        # Process flow: remote gateways > local > delete config object entry

        other_gateways = get_other_gateways(self.parent.parent.parent.target.children)
        api_vars = {"committing_host": this_host()}

        for gw in other_gateways:
            client_api = '{}://{}:{}/api/client/{}'.format(self.http_mode,
                                                           gw,
                                                           settings.config.api_port,
                                                           client_iqn)

            response = delete(client_api,
                              data=api_vars,
                              auth=(settings.config.api_user, settings.config.api_password),
                              verify=settings.config.api_ssl_verify)

            if response.status_code == 200:
                self.logger.debug("- '{}' removed from {}".format(client_iqn, gw))
                continue
            elif response.status_code == 400:
                self.logger.critical("- '{}' is in use on {}".format(client_iqn, gw))
                return
            else:
                raise GatewayAPIError(response.text)

        # At this point the other gateways have removed the client, so
        # remove from the local instance and delete from the interface
        client_api = '{}://127.0.0.1:{}/api/client/{}'.format(self.http_mode,
                                                              settings.config.api_port,
                                                              client_iqn)

        response = delete(client_api,
                          data=api_vars,
                          auth=(settings.config.api_user, settings.config.api_password),
                          verify=settings.config.api_ssl_verify)

        if response.status_code == 200:

            self.logger.debug("- '{}' removed from local gateway, configuration updated".format(client_iqn))
            self.delete(client)

        self.logger.info('ok')


    def delete(self, child):

        self.remove_child(child)

    def summary(self):
        return "Hosts: {}".format(len(self.children)), None


class Client(UINode):

    display_attributes = ["client_iqn", "logged_in", "auth", "luns"]

    def __init__(self, parent, client_iqn, client_settings):
        UINode.__init__(self, client_iqn, parent)
        self.client_iqn = client_iqn
        self.logger = self.parent.logger

        for k, v in client_settings.iteritems():
            self.__setattr__(k, v)

        for rbd_path in self.luns.keys():
            lun_id = self.luns[rbd_path]['lun_id']
            MappedLun(self, rbd_path, lun_id)

    def _get_logged_in_state(self):

        r = root.RTSRoot()
        for sess in r.sessions:
            if sess['parent_nodeacl'].node_wwn == self.client_iqn:
                return sess['state']
        return ''


    def summary(self):

        all_disks = self.parent.parent.parent.parent.disks.children
        total_bytes = 0

        client_luns = [lun.rbd_name for lun in self.children]

        for disk in all_disks:
            if disk.image_id in client_luns:
                total_bytes += disk.size

        msg = ['LOGGED-IN'] if self.logged_in else []

        # Default stance is no chap, so we need to detect it
        auth_text = "Auth: None"
        status = False

        if 'chap' in self.auth:
            if self.auth['chap']:
                auth_text = "Auth: CHAP"
                status = True

        msg.append(auth_text)

        msg.append("Disks: {}({})".format(len(client_luns),
                                          human_size(total_bytes)))

        return ", ".join(msg), status

    @staticmethod
    def valid_credentials(credentials_str, auth_type='chap'):
        """
        Return a boolean indicating whether the credentials supplied are acceptable
        """

        # regardless of the auth_type, the credentials_str must be of
        # for form <username>/<password>
        try:
            user_name, password = credentials_str.split('/')
        except ValueError:
            return False

        if auth_type == 'chap':
            # username is any length and includes . and : chars
            # password is 12-16 chars long containing any alphanumeric or !,_,& symbol
            usr_regex = re.compile("^[\w\\.\:]+")
            pw_regex = re.compile("^[\w\!\&\_]{12,16}$")
            if not usr_regex.search(user_name) or not pw_regex.search(password):
                return False

            return True
        else:
            # insert mutual or any other credentials logic here!
            return True

    def ui_command_auth(self, chap=None):
        """
        Client authentication can be set to use CHAP by supplying the
        a string of the form <username>/<password>

        > auth chap=myserver/mypassword2016

        username ... The username is freeform, but would normally be the
                     hostname or iqn
        password ... the password must be between 12-16 chars in length
                     containing alphanumeric characters plus the following
                     special characters !,&,_

        """

        if not chap:
            self.logger.error("To set CHAP authentication provide a string of the format 'user/password'")
            return

        else:
            # validate the chap credentials are acceptable
            if not Client.valid_credentials(chap, auth_type='chap'):
                self.logger.error("-> the format of the CHAP string is invalid, use 'help auth' for examples")
                return

        self.logger.debug("Client '{}' AUTH update : {}".format(self.client_iqn, chap))
        # get list of children (luns) to build current image list
        image_list = ','.join(self._get_lun_names())

        other_gateways = get_other_gateways(self.parent.parent.parent.parent.target.children)
        api_vars = {"committing_host": this_host(),
                    "image_list": image_list,
                    "chap": chap}

        clientauth_api = '{}://127.0.0.1:{}/api/clientauth/{}'.format(self.http_mode,
                                                                      settings.config.api_port,
                                                                      self.client_iqn)

        response = put(clientauth_api,
                       data=api_vars,
                       auth=(settings.config.api_user, settings.config.api_password),
                       verify=settings.config.api_ssl_verify)

        if response.status_code == 200:
            self.logger.debug("- Local environment updated")

            self.auth['chap'] = chap

            for gw in other_gateways:
                clientauth_api = '{}://{}:{}/api/clientauth/{}'.format(self.http_mode,
                                                                       gw,
                                                                       settings.config.api_port,
                                                                       self.client_iqn)

                response = put(clientauth_api,
                               data=api_vars,
                               auth=(settings.config.api_user, settings.config.api_password),
                               verify=settings.config.api_ssl_verify)

                if response.status_code == 200:
                    self.logger.debug("- {} updated".format(gw))
                    continue
                else:
                    raise GatewayAPIError(response.text)
        else:
            raise GatewayAPIError(response.text)

        self.logger.info('ok')


    def _get_lun_names(self):
        """
        process the children objects (LUNs), but sort the result by LUN id, so there is a
        prescribed order
        :return: list of sorted mapped disks (list)
        """

        return [lun.rbd_name for lun in self.children]

    def ui_command_disk(self, action='add', disk=None):
        """
        Disks can be added or removed from the client one at a time using
        the disk sub-command. Note that the disk MUST already be defined
        within the configuration

        > disk add|remove <disk_name>

        Adding a disk will result in the disk occupying the client's next
        available lun id.
        Removing a disk will preserve existing lun id allocations

        """

        valid_actions = ['add', 'remove']

        current_luns = self._get_lun_names()

        if action == 'add':

            valid_disk_names = [defined_disk.image_id for defined_disk in self.parent.parent.parent.parent.disks.children]
        else:
            valid_disk_names = current_luns

        if not disk:
            self.logger.critical("You must supply a disk name to add/remove from this client")
            return

        if action not in valid_actions:
            self.logger.error("you can only add and remove disks - {} is invalid ".format(action))
            return

        if disk not in valid_disk_names:
            self.logger.critical("the request to {} disk '{}' is invalid".format(action,
                                                                                 disk))
            return

        # At this point we are either in add/remove mode, with a valid disk to act upon
        self.logger.debug("Client '{}' update - {} disk {}".format(self.client_iqn,
                                                                   action,
                                                                   disk))

        if action == 'add':
            current_luns.append(disk)
        else:
            current_luns.remove(disk)

        image_list = ','.join(current_luns)

        other_gateways = get_other_gateways(self.parent.parent.parent.parent.target.children)

        api_vars = {"committing_host": this_host(),
                    "image_list": image_list,
                    "chap": self.auth['chap']}

        clientlun_api = '{}://127.0.0.1:{}/api/clientlun/{}'.format(self.http_mode,
                                                                    settings.config.api_port,
                                                                    self.client_iqn)

        response = put(clientlun_api,
                       data=api_vars,
                       auth=(settings.config.api_user, settings.config.api_password),
                       verify=settings.config.api_ssl_verify)

        if response.status_code == 200:

            if action == 'add':

                # The addition of the lun will get a lun id assigned so
                # we need to query the api server to get the new configuration
                # to be able to set the local cli entry correctly
                get_api_vars = {"disk": disk}
                response = get(clientlun_api,
                               data=get_api_vars,
                               auth=(settings.config.api_user, settings.config.api_password),
                               verify=settings.config.api_ssl_verify)

                if response.status_code == 200:
                    lun_dict = json.loads(response.text)['message']
                    lun_id = lun_dict[disk]['lun_id']
                    MappedLun(self, disk, lun_id)
                else:
                    raise GatewayAPIError(response.text)

            else:

                # this was a remove request, so simply delete the child
                # MappedLun object corresponding to this rbd name

                mlun = [lun for lun in self.children if lun.rbd_name == disk][0]
                self.remove_child(mlun)

            self.logger.debug("- local environment updated")

            for gw in other_gateways:
                clientlun_api = '{}://{}:{}/api/clientlun/{}'.format(self.http_mode,
                                                                     gw,
                                                                     settings.config.api_port,
                                                                     self.client_iqn)

                response = put(clientlun_api,
                               data=api_vars,
                               auth=(settings.config.api_user, settings.config.api_password),
                               verify=settings.config.api_ssl_verify)

                if response.status_code == 200:
                    self.logger.debug("- gateway '{}' updated".format(gw))
                    continue
                else:
                    raise GatewayAPIError(response.text)
        else:
            raise GatewayAPIError(response.text)

        self.logger.info('ok')

    logged_in = property(_get_logged_in_state,
                         doc="login state of the client")


class MappedLun(UINode):

    display_attributes = ["rbd_path", "owner", "size", "size_h", "lun_id"]

    def __init__(self, parent, name, lun_id):
        self.rbd_name = name
        UINode.__init__(self, 'lun {}'.format(lun_id), parent)
        disk_group = self.parent.parent.parent.parent.parent.disks.disk_info
        self.owner = disk_group[name]['owner']
        self.size = 0
        self.lun_id = lun_id

        disk_map = self.parent.parent.parent.parent.parent.disks.disk_info
        self.size = disk_map[self.rbd_name]['size']
        self.size_h = disk_map[self.rbd_name]['size_h']

    def summary(self):
        return "{}({}), Owner: {}".format(self.rbd_name, self.size_h, self.owner), True
