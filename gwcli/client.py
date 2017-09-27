#!/usr/bin/env python

from gwcli.node import UIGroup, UINode

from gwcli.utils import human_size, response_message, APIRequest

from ceph_iscsi_config.client import CHAP
import ceph_iscsi_config.settings as settings

import rtslib_fb.root as root

# this ignores the warning issued when verify=False is used
from requests.packages import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Clients(UIGroup):
    help_intro = '''
                 The host section shows the clients that have been defined 
                 across each of the gateways in the configuration.
                 
                 Clients may be created or deleted, but once defined they can 
                 not be renamed.
                 
                 e.g.
                 create iqn.1994-05.com.redhat:rh7-client4
                 '''

    def __init__(self, parent):
        UIGroup.__init__(self, 'hosts', parent)

        # lun_map dict is indexed by the rbd name, pointing to a list
        # of clients that have that rbd allocated.
        self.lun_map = {}
        self.client_map = {}

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

        e.g.
        > create <client_iqn>

        """
        self.logger.debug("CMD: ../hosts/ create {}".format(client_iqn))
        cli_seed = {"luns": {}, "auth": {}}

        # Issue the API call to create the client
        client_api = ('{}://127.0.0.1:{}/api/'
                      'client/{}'.format(self.http_mode,
                                         settings.config.api_port,
                                         client_iqn))

        self.logger.debug("Client CREATE for {}".format(client_iqn))
        api = APIRequest(client_api)
        api.put()

        if api.response.status_code == 200:
            Client(self, client_iqn, cli_seed)
            self.logger.debug("- Client '{}' added".format(client_iqn))
            self.logger.info('ok')

        else:
            self.logger.error("Failed: {}".format(response_message(api.response,
                                                                   self.logger)))
            return


        # switch the current directory to the new client for auth or disk
        # definitions as part of the users workflow
        return self.ui_command_cd(client_iqn)

    def ui_command_delete(self, client_iqn):
        """
        You may delete a client from the configuration, but you must ensure
        the client has logged out of the iscsi gateways. Attempting to delete a
        client that has an open session will fail the request

        e.g.
        delete <client_iqn>

        """

        self.logger.debug("CMD: ../hosts/ delete {}".format(client_iqn))

        self.logger.debug("Client DELETE for {}".format(client_iqn))

        client_api = ('{}://{}:{}/api/'
                      'client/{}'.format(self.http_mode,
                                         "127.0.0.1",
                                         settings.config.api_port,
                                         client_iqn))
        api = APIRequest(client_api)
        api.delete()

        if api.response.status_code == 200:
            # Delete successful across all gateways
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
        else:
            # client delete request failed
            self.logger.error(response_message(api.response, self.logger))

    def update_lun_map(self, action, rbd_path, client_iqn):
        """
        Update the lun_map lookup dict, each element points to a 'set' of
        clients that have the lun mapped
        :param action: add or remove
        :param rbd_path: disk name (str) i.e. <pool>.<rbd_image>
        :param client_iqn: client IQN (str)
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
        del self.client_map[child.client_iqn]
        self.remove_child(child)

    def summary(self):
        return "Hosts: {}".format(len(self.children)), None


class Client(UINode):
    help_intro = '''
                 Client definitions can be managed through two sub-commands;
                 'auth' and 'disk'. These commands allow you to manage the 
                 CHAP authentication for the client (1-WAY) and change the 
                 rbd images masked to a specific client.
                  
                 LUN masking automatically associates a specific LUN id to the
                 for an rbd image, simplifying the workflow. The lun id's 
                 assigned can be seen by running the 'info' command. This will 
                 show all the clients details that are stored within the 
                 iscsi gateway configuration.
                 
                 '''

    display_attributes = ["client_iqn", "logged_in", "auth",
                          "group_name", "luns"]

    def __init__(self, parent, client_iqn, client_settings):
        UINode.__init__(self, client_iqn, parent)
        self.client_iqn = client_iqn
        self.parent.client_map[client_iqn] = self
        self.group_name = ''

        for k, v in client_settings.iteritems():
            self.__setattr__(k, v)

        # decode the password if necessary
        if 'chap' in self.auth:
            self.chap = CHAP(self.auth['chap'])
            self.auth['chap'] = self.chap.chap_str

        self.refresh_luns()

    def drop_luns(self):
        luns = self.children.copy()
        for lun in luns:
            self.remove_lun(lun)

    def refresh_luns(self):
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

    def __str__(self):
        return self.get_info()

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

    def ui_command_auth(self, chap=None):
        """
        Client authentication can be set to use CHAP by supplying the
        a string of the form <username>/<password>

        e.g.
        auth chap=username/password | nochap

        username ... The username is freeform, but would typically be the
                     host's shortname or iqn
        password ... the password must be between 12-16 chars in length
                     containing alphanumeric characters, plus the following
                     special characters @,_,-

        Specifying 'nochap' will remove chap authentication for the client
        across all gateways.

        """

        self.logger.debug("CMD: ../hosts/<client_iqn> auth *")

        if not chap:
            self.logger.error("To set or reset authentication, specify either "
                              "chap=<user>/<password> or nochap")
            return

        if chap == 'nochap':
            chap = ''
        else:
            # string could have been supplied as chap=user/password or
            # simply user/password - either way all we see is user/password
            if '/' not in chap:
                self.logger.error(
                    "CHAP format is invalid - must be <username>/<password>"
                    ". Use 'help auth' to show more info")
                return

        self.logger.debug(
            "CHAP to be set to '{}' for '{}'".format(chap, self.client_iqn))

        api_vars = {"chap": chap}

        clientauth_api = ('{}://127.0.0.1:{}/api/'
                          'clientauth/{}'.format(self.http_mode,
                                                 settings.config.api_port,
                                                 self.client_iqn))

        api = APIRequest(clientauth_api, data=api_vars)
        api.put()

        if api.response.status_code == 200:
            self.logger.debug("- client credentials updated")
            self.auth['chap'] = chap
            self.logger.info('ok')

        else:
            self.logger.error("Failed to update the client's auth"
                              " :{}".format(response_message(api.response,
                                                             self.logger)))
            return

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
        the 'disk' sub-command. Note that if the disk does not currently exist
        in the configuration, the cli will attempt to create it for you.

        e.g.
        disk add <disk_name> <size>
        disk remove <disk_name>

        Adding a disk will result in the disk occupying the client's next
        available lun id. Once allocated removing a LUN will not change the
        LUN id associations for the client.

        Note that if the client is a member of a host group, disk management
        *must* be performed at the group level. Attempting to add/remove disks
        at the client level will fail.

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
                    self.logger.error("To auto-define the disk to the client"
                                      " you must provide a disk size")
                    return

                # a disk given here would be of the form pool.image
                pool, image = disk.split('.')
                rc = ui_disks.create_disk(pool=pool, image=image, size=size)
                if rc == 0:
                    self.logger.debug("disk auto-define successful")
                else:
                    self.logger.error("disk auto-define failed({}), try "
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

        api_vars = {"disk": disk}

        clientlun_api = ('{}://127.0.0.1:{}/api/'
                         'clientlun/{}'.format(self.http_mode,
                                               settings.config.api_port,
                                               self.client_iqn))

        api = APIRequest(clientlun_api, data=api_vars)
        if action == 'add':
            api.put()
        else:
            api.delete()

        if api.response.status_code == 200:

            self.logger.debug("disk mapping updated successfully")

            if action == 'add':

                # The addition of the lun will get a lun id assigned so
                # we need to query the api server to get the new configuration
                # to be able to set the local cli entry correctly
                get_api_vars = {"disk": disk}

                clientlun_api = clientlun_api.replace('/clientlun/',
                                                      '/_clientlun/')

                self.logger.debug("Querying API to get mapped LUN information")
                api = APIRequest(clientlun_api, data=get_api_vars)
                api.get()

                if api.response.status_code == 200:
                    try:
                        lun_dict = api.response.json()['message']
                    except:
                        self.logger.error("Malformed REST API response")
                        return

                    # now update the UI
                    lun_id = lun_dict[disk]['lun_id']
                    self.add_lun(disk, lun_id)

                else:
                    self.logger.error("Query for disk '{}' meta data "
                                      "failed".format(disk))
                    return

            else:

                # this was a remove request, so simply delete the child
                # MappedLun object corresponding to this rbd name
                mlun = [lun for lun in self.children
                        if lun.rbd_name == disk][0]
                self.remove_lun(mlun)

            self.logger.debug("configuration update successful")
            self.logger.info('ok')

        else:
            # the request to add/remove the disk for the client failed
            self.logger.error("disk {} for '{}' against {} failed"
                              "\n{}".format(action,
                                            disk,
                                            self.client_iqn,
                                            response_message(api.response,
                                                             self.logger)))
            return

    def add_lun(self, disk, lun_id):

        MappedLun(self, disk, lun_id)

        # update the objects lun list (so ui info cmd picks
        # up the change
        self.luns[disk] = {'lun_id': lun_id}

        self.parent.update_lun_map('add',
                                   disk,
                                   self.client_iqn)

        active_maps = len(self.parent.lun_map[disk]) - 1
        if active_maps > 0:
            self.logger.warning("Warning: '{}' mapped to {} other "
                                "client(s)".format(disk,
                                                   active_maps))

    def remove_lun(self, lun):
        self.remove_child(lun)
        del self.luns[lun.rbd_name]
        self.parent.update_lun_map('remove',
                                   lun.rbd_name,
                                   self.client_iqn)

    @property
    def logged_in(self):

        r = root.RTSRoot()
        for sess in r.sessions:
            if sess['parent_nodeacl'].node_wwn == self.client_iqn:
                return sess['state']
        return ''


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
