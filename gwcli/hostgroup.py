#!/usr/bin/env python2

from gwcli.node import UIGroup, UINode
from gwcli.utils import APIRequest
from gwcli.client import MappedLun
import ceph_iscsi_config.settings as settings

__author__ = "Paul Cuzner"


class HostGroups(UIGroup):

    help_intro = '''
                 Hosts groups provide a more convenient way of managing multiple
                 hosts that require access to the same set of LUNs. The host 
                 group defines the clients and the LUNs (rbd images) that all 
                 members of the group should have masked to them.

                 Once a client is a member of a host group, the disks that are
                 masked to the client can only be managed at the group level. 

                 Deleting a host group, simply removes the group membership for
                 hosts. Existing LUN masking will remain in place.

    '''

    def __init__(self, parent):
        UIGroup.__init__(self, 'host-groups', parent)

        # record the shortcut
        shortcut = self.shell.prefs['bookmarks'].get('host-groups', None)
        if not shortcut or shortcut is not self.path:

            self.shell.prefs['bookmarks']['host-groups'] = self.path
            self.shell.prefs.save()

        self.load()

    def load(self):

        for child in self.children:
            self.delete(child)

        groups = self.get_ui_root().config['groups']
        for group_name in groups:
            HostGroup(self, group_name, groups[group_name])

    def _get_groups(self):
        return [child.name for child in self.children]

    def summary(self):
        return "Groups : {}".format(len(self.children)), None

    def ui_command_create(self, group_name):
        """
        Create a host group definition
        """
        self.logger.debug("CMD: ../host-groups/ create {}".format(group_name))

        if group_name in self.groups:
            self.logger.error("Group {} already defined".format(group_name))
            return

        # this is a new group
        group_api = ('{}://{}:{}/api/hostgroup/'
                     '{}'.format(self.http_mode,
                                 "127.0.0.1",
                                 settings.config.api_port,
                                 group_name))

        api = APIRequest(group_api)
        api.put()
        if api.response.status_code != 200:
            self.logger.error("Failed to create the host group")
            return

        self.logger.debug('Adding group to the UI')
        HostGroup(self, group_name)

        # Switch to the new group
        return self.ui_command_cd(group_name)

    def ui_command_delete(self, group_name):
        """
        Delete a host group definition
        """
        self.logger.debug("CMD: ../host-groups/ delete {}".format(group_name))

        if group_name not in self.groups:
            self.logger.error("Group '{}' does not exist")
            return

        # OK, so the group exists...
        group_api = ('{}://{}:{}/api/hostgroup/'
                     '{}'.format(self.http_mode,
                                 "127.0.0.1",
                                 settings.config.api_port,
                                 group_name))

        api = APIRequest(group_api)
        api.delete()
        if api.response.status_code != 200:
            self.logger.error("failed to delete group '{}'".format(group_name))
            return

        self.logger.debug("removing group from the UI")
        child = [child for child in self.children
                 if child.name == group_name][0]
        self.delete(child)

        self.logger.info('ok')

    def delete(self, child):
        self.logger.debug("removing '{}' from local client "
                          "definitions".format(child.name))
        ui_root = self.get_ui_root()
        clients = ui_root.target.client_group
        for iqn in clients:
            if clients[iqn].get('group_name') == child.name:
                clients[iqn]['group_name'] = ''

        self.remove_child(child)

    groups = property(_get_groups,
                      doc="return a list of defined host groups")


class HostGroup(UIGroup):

    help_intro = '''
                 Hosts and disks may be added and removed from a host group
                 definition.
                 
                 This is managed through the host and disk subcommands
                 e.g.
                 
                 host add|remove iqn.1994-05.com.redhat:rh7-client
                 disk add|remove rbd.disk_1
                 
    '''

    valid_actions = ['add', 'remove']

    def __init__(self, parent, group_name, group_settings={}):
        UIGroup.__init__(self, group_name, parent)

        self.name = group_name

        for disk in group_settings.get('disks', []):
            HostGroupMember(self, 'disk', disk)
        for member in group_settings.get('members', []):
            HostGroupMember(self, 'host', member)

    def ui_command_host(self, action, client_iqn):
        """
        Add or remove a host from a host group
        :return:
        """
        if action not in HostGroup.valid_actions:
            self.logger.error("Invalid request - must be "
                              "host add|remove <client_iqn>")
            return

        # basic checks
        ui_root = self.get_ui_root()
        clients = ui_root.target.client_group
        if client_iqn not in clients:
            self.logger.error("'{}' is not in the "
                              "configuration".format(client_iqn))
            return
        current_group = clients[client_iqn].get('group_name', None)
        if action == 'add' and current_group:
            self.logger.error("'{}' already belongs to "
                              "'{}'".format(client_iqn,
                                            current_group))
            return
        elif action == 'remove' and current_group != self.name:
            self.logger.error("'{}' does not belong to this "
                              "group".format(client_iqn))
            return

        # Basic checks passed, hand-off to the API now
        group_api = ('{}://{}:{}/api/hostgroup/'
                     '{}'.format(self.http_mode,
                                 "127.0.0.1",
                                 settings.config.api_port,
                                 self.name))

        api_vars = {"action": action,
                    "member": client_iqn}

        api = APIRequest(group_api, data=api_vars)
        api.put()
        self.logger.debug("- api call responded "
                          "{}".format(api.response.status_code))
        if api.response.status_code != 200:
            self.logger.error("host group change failed: "
                              "{}".format(api.response.json()['message']))
            return

        # group updated, so update the UI
        self.logger.debug("Updating the UI")
        if action == 'add':
            HostGroupMember(self, 'host', client_iqn)
            clients[client_iqn]['group_name'] = self.name
            # add disks in the group to the host
            self.logger.debug('fetching the complete group definition')
            group_info = self._fetch_group()
            self.logger.debug('syncing group clients')
            for disk in group_info.get('disks'):
                self.update_clients_UI('add', disk)

        elif action == 'remove':
            child = [child for child in self.children
                     if child.name == client_iqn][0]
            self.delete(child)

        self.logger.info('ok')

    def _fetch_group(self):
        group_api = ('{}://{}:{}/api/hostgroup/'
                     '{}'.format(self.http_mode,
                                 "127.0.0.1",
                                 settings.config.api_port,
                                 self.name))
        api = APIRequest(group_api)
        api.get()
        if api.response.status_code == 200:
            return api.response.json()
        else:
            # problem getting hostgroup definition
            pass

    def delete(self, child):

        if child.member_type == 'host':
            ui_root = self.get_ui_root()
            clients = ui_root.target.client_group
            clients[child.name]['group_name'] = ''

        self.remove_child(child)

    def ui_command_disk(self, action, disk_name):
        """
        Add or remove a disk from a host group
        :return:
        """

        if action not in HostGroup.valid_actions:
            self.logger.error("Invalid request - must be "
                              "disk add|remove <disk_image>")
            return

        # simple sanity check - does the disk exist?
        ui_root = self.get_ui_root()
        if disk_name not in [disk.name for disk in ui_root.disks.children]:
            self.logger.error("Disk '{}' is not defined within the "
                              "configuration".format(disk_name))
            return

        # Basic checks passed, hand-off to the API
        group_api = ('{}://{}:{}/api/hostgroup/'
                     '{}'.format(self.http_mode,
                                 "127.0.0.1",
                                 settings.config.api_port,
                                 self.name))

        api_vars = {"action": action,
                    "disk": disk_name}

        api = APIRequest(group_api, data=api_vars)
        api.put()
        self.logger.debug("- api call responded {}".format(api.response.status_code))
        if api.response.status_code != 200:
            self.logger.error("host group change failed")
            return

        # group updated, so update the host-groups UI elements
        self.logger.debug("Updating the UI")
        if action == 'add':
            HostGroupMember(self, 'disk', disk_name)
        elif action == 'remove':
            child = [child for child in self.children
                     if child.name == disk_name][0]
            self.delete(child)

        self.update_clients_UI(action, disk_name)

        self.logger.info('ok')

    def update_clients_UI(self, action, disk_name):

        self.logger.debug("process each member of the group")

        grp_clients = [mbr.name for mbr in self.children
                       if mbr.member_type == 'host']

        ui_root = self.get_ui_root()
        if action == 'add':
            # let's get an updated version of the client/lun mapping
            config = ui_root._get_config()
            clients = config['clients']

        target_subtree = [child for child in ui_root.target.children][0]
        clients_subtree = target_subtree.client_group

        for client in clients_subtree.children:
            if client.name in grp_clients:
                if action == 'add':
                    client_luns = clients[client.name].get('luns')
                    client_ui_disks = [lun.rbd_name for lun in client.children]
                    if disk_name in client_ui_disks:
                        self.logger.debug("skipping add of {} to "
                                          "{}".format(disk_name,
                                                      client.name))
                        continue
                    else:
                        lun_id = client_luns[disk_name].get('lun_id')
                        self.logger.debug("adding {} to {}".format(disk_name,
                                                                   client.name))
                        client.add_lun(disk_name, lun_id)

                else:
                    # remove the disk from the client UI subtree
                    self.logger.debug("removing {} from {}".format(disk_name,
                                                                   client.name))
                    mapped_lun = [lun for lun in client.children
                                  if lun.rbd_name == disk_name][0]
                    client.remove_lun(mapped_lun)

    def summary(self):
        counts = {'disk': 0, 'host': 0}
        for child in self.children:
            counts[child.member_type] += 1
        return "Hosts: {}, Disks: {}".format(counts['host'],
                                             counts['disk']), \
               None


class HostGroupMember(UINode):
    help_intro = "hello"

    def __init__(self, parent, member_type, name):
        UINode.__init__(self, name, parent)
        self.member_type = member_type

    def summary(self):
        return "{}".format(self.member_type), True
