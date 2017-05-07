#!/usr/bin/env python

import json
import re

from gwcli.node import UIGroup, UINode

from gwcli.utils import (human_size, get_other_gateways,
                         GatewayAPIError, GatewayLIOError,
                         this_host, APIRequest, valid_iqn)

from ceph_iscsi_config.client import CHAP
import ceph_iscsi_config.settings as settings

import rtslib_fb.root as root
from rtslib_fb.utils import normalize_wwn, RTSLibError

# FIXME - this ignores the warning issued when verify=False is used
from requests.packages import urllib3

__author__ = 'pcuzner@redhat.com'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Clients(UIGroup):
    help_intro = '''
                 Clients bla
                 '''

    def __init__(self, parent):
        UIGroup.__init__(self, 'hosts', parent)
        self.logger = self.parent.logger

        # lun_map dict is indexed by the rbd name, pointing to a list
        # of clients that have that rbd allocated.
        self.lun_map = {}

        # record the shortcut
        shortcut = self.shell.prefs['bookmarks'].get('hosts', None)
        if not shortcut or shortcut is not self.path:
            self.shell.prefs['bookmarks']['hosts'] = self.path
            self.shell.prefs.save()
            self.shell.log.debug("Bookmarked %s as %s."
                                 % (self.path, 'hosts'))

    def load(self, client_info):
        for client_iqn, client_settings in client_info.iteritems():
            Client(self, client_iqn, client_settings)

    def ui_command_create(self, client_iqn):
        """
        Clients may be created using the 'create' sub-command. The initial
        definition will be added to each gateway without any authentication
        set. Once a client is created the admin is automatically placed in the
        context of the new client definition for auth and disk configuration
        operations.

        > create <client_iqn>

        """
        self.logger.debug("CMD: ../hosts/ create {}".format(client_iqn))
        cli_seed = {"luns": {}, "auth": {}}

        # Issue the API call to create the client
        client_api = '{}://127.0.0.1:{}/api/all_client/{}'.format(
                     self.http_mode,
                     settings.config.api_port,
                     client_iqn)

        self.logger.debug("Client CREATE for {}".format(client_iqn))
        api = APIRequest(client_api)
        api.put()

        if api.response.status_code == 200:
            Client(self, client_iqn, cli_seed)
            self.logger.debug("- Client '{}' added".format(client_iqn))
            self.logger.info('ok')

        else:
            self.logger.error("Failed: {}".format(api.response.json()['message']))
            return


        # switch the current directory to the new client for auth or disk
        # definitions as part of the users workflow
        return self.ui_command_cd(client_iqn)

    def ui_command_delete(self, client_iqn):
        """
        You may delete a client from the configuration, but you must ensure
        the client has logged out of the iscsi gateways. Attempting to delete a
        client that has an open session will fail the request

        > delete <client_iqn>

        """

        self.logger.debug("CMD: ../hosts/ delete {}".format(client_iqn))

        # check the iqn given matches one of the child objects
        # - i.e. it's valid
        client_names = [child.name for child in self.children]
        if client_iqn not in client_names:
            self.logger.error("Host with an iqn of '{}' is not defined."
                              "..mis-typed?".format(client_iqn))
            return

        lio_root = root.RTSRoot()
        clients_logged_in = [session['parent_nodeacl'].node_wwn
                             for session in lio_root.sessions
                             if session['state'] == 'LOGGED_IN']

        if client_iqn in clients_logged_in:
            self.logger.error("Host '{}' is logged in - unable to delete until"
                              " it's logged out".format(client_iqn))
            return

        # At this point we know the client requested is defined to the
        # configuration and is not currently logged in (at least to this host!),
        # OK to delete
        self.logger.debug("Client DELETE for {}".format(client_iqn))


        # Process flow: remote gateways > local > delete config object entry

        client_api = '{}://{}:{}/api/all_client/{}'.format(self.http_mode,
                                                       "127.0.0.1",
                                                       settings.config.api_port,
                                                       client_iqn)
        api = APIRequest(client_api)
        api.delete()

        if api.response.status_code == 200:
            # Delete successfull across all gateways
            self.logger.debug("- '{}' removed and configuration "
                              "updated".format(client_iqn))

            client = [client for client in self.children
                      if client.name == client_iqn][0]

            # remove any rbd maps from the lun_map for this client
            rbds_mapped = [lun.rbd_name for lun in client.children]
            for rbd in rbds_mapped:
                self.update_lun_map('remove', rbd, client_iqn)

            self.delete(client)

            self.logger.info('ok')

    def update_lun_map(self, action, rbd_path, client_iqn):
        """
        Update the lun_map lookup dict
        :param action: add or remove
        :param rbd_path: disk name (str) i.e. <pool>.<rbd_image>
        :param client_iqn: client IQN (str)
        :return: None
        """

        if action == 'add':
            if rbd_path in self.lun_map:
                self.lun_map[rbd_path].add(client_iqn)
            else:
                self.lun_map[rbd_path] = {client_iqn}
        else:
            if rbd_path in self.lun_map:
                try:
                    self.lun_map[rbd_path].remove(client_iqn)
                except KeyError:
                    # client not in set
                    pass
                else:
                    if len(self.lun_map[rbd_path]) == 0:
                        del self.lun_map[rbd_path]
            else:
                # delete requested for an rbd that is not in lun_map?
                # twilight zone moment
                raise ValueError("Clients.update_lun_map : Attempt to delete "
                                 "rbd from lun_map that is not defined")


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

        # decode the password if necessary
        if 'chap' in self.auth:
            self.chap = CHAP(self.auth['chap'])
            self.auth['chap'] = self.chap.chap_str

        for rbd_path in self.luns.keys():
            lun_id = self.luns[rbd_path]['lun_id']
            self.parent.update_lun_map('add', rbd_path, self.client_iqn)
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
            # username is any length and includes . and : chars
            # password is 12-16 chars long containing any alphanumeric
            # or !,_,& symbol
            usr_regex = re.compile("^[\w\\.\:]+")
            pw_regex = re.compile("^[\w\!\&\_]{12,16}$")
            if not usr_regex.search(user_name) or not pw_regex.search(password):
                return False

            return True
        else:
            # insert mutual or any other credentials logic here!
            return True

    def ui_command_auth(self, nochap=False, chap=None):
        """
        Client authentication can be set to use CHAP by supplying the
        a string of the form <username>/<password>

        > auth nochap | chap=myserver/mypassword2016

        username ... The username is freeform, but would normally be the
                     hostname or iqn
        password ... the password must be between 12-16 chars in length
                     containing alphanumeric characters plus the following
                     special characters !,&,_

        """

        self.logger.debug("CMD: ../hosts/<client_iqn> auth *")

        if nochap:
            chap = ''

        if not nochap and not chap:
            self.logger.error("To set CHAP authentication provide a string of "
                              "the format 'user/password'")
            return

        if chap:
            # validate the chap credentials are acceptable
            if not Client.valid_credentials(chap, auth_type='chap'):
                self.logger.error("-> the format of the CHAP string is invalid"
                                  ", use 'help auth' for examples")
                return

        self.logger.debug("Client '{}' AUTH update".format(self.client_iqn))
        # get list of children (luns) to build current image list
        lun_list = [(lun.rbd_name, lun.lun_id) for lun in self.children]
        image_list = ','.join(Client.get_srtd_names(lun_list))

        other_gateways = get_other_gateways(self.parent.parent.parent.parent.target.children)
        api_vars = {"image_list": image_list,
                    "chap": chap}

        clientauth_api = '{}://127.0.0.1:{}/api/all_clientauth/{}'.format(
                         self.http_mode,
                         settings.config.api_port,
                         self.client_iqn)

        api = APIRequest(clientauth_api, data=api_vars)
        api.put()

        if api.response.status_code == 200:
            self.logger.debug("- client credentials updated")

            self.auth['chap'] = chap

            self.logger.info('ok')

        else:
            raise GatewayAPIError(api.response.json()['message'])

    @staticmethod
    def get_srtd_names(lun_list):
        """
        sort the supplied list of luns (tuples - [('disk1',1),('disk2',0)])
        :return: list of LUN names, in lun_id sequence
        """

        srtd_luns = sorted(lun_list, key=lambda field: field[1])

        return [rbd_name for rbd_name, lun_id in srtd_luns]

    def ui_command_disk(self, action='add', disk=None, size=None):
        """
        Disks can be added or removed from the client one at a time using
        the disk sub-command. Note that the disk MUST already be defined
        within the configuration

        > disk add|remove <disk_name>

        Adding a disk will result in the disk occupying the client's next
        available lun id.
        Removing a disk will preserve existing lun id allocations

        """

        self.logger.debug("CMD: ../hosts/<client_iqn> disk action={}"
                          " disk={}".format(action,
                                           disk))

        valid_actions = ['add', 'remove']

        if not disk:
            self.logger.critical("You must supply a disk name to add/remove "
                                 "for this client")
            return

        if action not in valid_actions:
            self.logger.error("you can only add and remove disks - {} is "
                              "invalid ".format(action))
            return

        lun_list = [(lun.rbd_name, lun.lun_id) for lun in self.children]
        current_luns = Client.get_srtd_names(lun_list)

        if action == 'add':

            if disk not in current_luns:
                ui_root = self.get_ui_root()
                valid_disk_names = [defined_disk.image_id
                                    for defined_disk in ui_root.disks.children]
            else:
                # disk provided is already mapped, so remind the user
                self.logger.error("Disk {} already mapped".format(disk))
                return
        else:
            valid_disk_names = current_luns

        if disk not in valid_disk_names:

            # if this is an add operation, we can create the disk on-the-fly
            # for the admin

            if action == 'add':
                ui_root = self.get_ui_root()
                ui_disks = ui_root.disks
                if not size:
                    self.logger.error("To autodefine the disk to the client"
                                      " you must provide a disk size")
                    return

                # a disk given here would be of the form pool.image
                pool, image = disk.split('.')
                rc = ui_disks.create_disk(pool=pool, image=image, size=size)
                if rc == 0:
                    self.logger.debug("disk autodefine successful")
                else:
                    self.logger.error("disk autodefine failed({}), try "
                                      "using the /disks create "
                                      "command".format(rc))
                    return

            else:
                self.logger.error("disk '{}' is not mapped to this "
                                     "client ".format(disk))
                return

        # At this point we are either in add/remove mode, with a valid disk
        # to act upon
        self.logger.debug("Client '{}' update - {} disk "
                          "{}".format(self.client_iqn,
                                      action,
                                      disk))

        if action == 'add':
            current_luns.append(disk)
        else:
            current_luns.remove(disk)

        image_list = ','.join(current_luns)

        api_vars = {"image_list": image_list,
                    "chap": self.auth.get('chap', '')}

        clientlun_api = '{}://127.0.0.1:{}/api/all_clientlun/{}'.format(
                        self.http_mode,
                        settings.config.api_port,
                        self.client_iqn)

        api = APIRequest(clientlun_api, data=api_vars)
        api.put()

        if api.response.status_code == 200:

            self.logger.debug("disk mapping updated successfully")

            if action == 'add':

                # The addition of the lun will get a lun id assigned so
                # we need to query the api server to get the new configuration
                # to be able to set the local cli entry correctly
                get_api_vars = {"disk": disk}
                clientlun_api = clientlun_api.replace('/all_clientlun/',
                                                      '/clientlun/')
                self.logger.debug("Querying API to get mapped LUN information")
                api = APIRequest(clientlun_api, data=get_api_vars)
                api.get()

                if api.response.status_code == 200:
                    lun_dict = api.response.json()['message']
                    lun_id = lun_dict[disk]['lun_id']
                    MappedLun(self, disk, lun_id)

                    # update the objects lun list (so ui info cmd picks
                    # up the change
                    self.luns[disk] = {'lun_id': lun_id}
                    self.parent.update_lun_map('add', disk, self.client_iqn)
                    active_maps = len(self.parent.lun_map[disk]) - 1
                    if active_maps > 0:
                        self.logger.warning("Warning: '{}' mapped to {} other "
                                            "client(s)".format(disk,
                                                               active_maps))

                else:
                    self.logger.error("Query for disk '{}' failed".format(disk))
                    raise GatewayAPIError()

            else:

                # this was a remove request, so simply delete the child
                # MappedLun object corresponding to this rbd name

                mlun = [lun for lun in self.children
                        if lun.rbd_name == disk][0]
                self.remove_child(mlun)
                del self.luns[disk]
                self.parent.update_lun_map('remove', disk, self.client_iqn)


            self.logger.debug("configuration update successful")
            self.logger.info('ok')

        else:
            # the request to add/remove the disk for the client failed
            self.logger.error("Adding disk '{}' to {} failed".format(disk,
                                                                     self.client_iqn))
            raise GatewayAPIError()

    logged_in = property(_get_logged_in_state,
                         doc="login state of the client")


class MappedLun(UINode):

    display_attributes = ["rbd_name", "owner", "size", "size_h", "lun_id"]

    def __init__(self, parent, name, lun_id):
        self.rbd_name = name
        UINode.__init__(self, 'lun {}'.format(lun_id), parent)

        # navigate back through the object model to pick up the disks
        ui_root = self.get_ui_root()
        disk_lookup = ui_root.disks.disk_lookup

        self.disk = disk_lookup[name]
        self.owner = self.disk.owner
        self.size = self.disk.size
        self.size_h = self.disk.size_h
        self.lun_id = lun_id

    def summary(self):
        self.owner = self.disk.owner
        self.size_h = self.disk.size_h
        return "{}({}), Owner: {}".format(self.rbd_name,
                                          self.size_h,
                                          self.owner), True
