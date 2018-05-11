#!/usr/bin/env python2

import re

from gwcli.node import UIGroup, UINode
from gwcli.utils import response_message, APIRequest
import ceph_iscsi_config.settings as settings


class HostGroups(UIGroup):

    help_intro = '''
                 Hosts groups provide a more convenient way of managing multiple
                 hosts that require access to the same set of LUNs. The host 
                 group 'policy' defines the clients and the LUNs (rbd images) 
                 that should be associated together.

                 There are two commands used to manage the host group
                 
                 create <group_name>
                 delete <group_name>

                 Since the same disks will be seen by multiple systems, you 
                 should only use this feature for hosts that are cluster aware.
                 Failing to adhere to this constraint is likely to result in 
                 **data loss**
                 
                 Once a group has been created you can associate clients and 
                 LUNs to the group with the 'host' and 'disk' sub-commands. 
                 
                 Note that a client can only belong to a single group definition, 
                 but a disk can be defined across several groups.

    '''

    group_name_length = 32

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

    @property
    def groups(self):
        return [child.name for child in self.children]

    def summary(self):
        return "Groups : {}".format(len(self.children)), None

    def ui_command_create(self, group_name):
        """
        Create a host group definition. Group names can be use up to 32
        alphanumeric characters, including '_', '-' and '@'. Note that once a
        group is it can not be renamed.
        """
        self.logger.debug("CMD: ../host-groups/ create {}".format(group_name))

        if group_name in self.groups:
            self.logger.error("Group {} already defined".format(group_name))
            return

        grp_regex = re.compile(
            "^[\w\@\-\_]{{1,{}}}$".format(HostGroups.group_name_length))
        if not grp_regex.search(group_name):
            self.logger.error("Invalid group name - max of {} chars of "
                              "alphanumeric and -,_,@ "
                              "characters".format(HostGroups.group_name_length))
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
            self.logger.error("Failed : "
                              "{}".format(response_message(api.response,
                                                           self.logger)))
            return

        self.logger.debug('Adding group to the UI')
        HostGroup(self, group_name)

        self.logger.info('ok')

        # Switch to the new group
        return self.ui_command_cd(group_name)

    def ui_command_delete(self, group_name):
        """
        Delete a host group definition. The delete process will remove the group
        definition and remove the group name association within any client.

        Note the deletion of a group will not remove the lun masking already
        defined to clients. If this is desired, it will need to be performed
        manually once the group is deleted.
        """

        self.logger.debug("CMD: ../host-groups/ delete {}".format(group_name))

        if group_name not in self.groups:
            self.logger.error("Group '{}' does not exist".format(group_name))
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

        client_group = child._get_client_group()
        client_map = client_group.client_map
        group_clients = [client_iqn for client_iqn in client_map
                         if client_map[client_iqn].group_name == child.name]

        for iqn in group_clients:

            self.logger.debug("removing group name from {}".format(iqn))
            client_map[iqn].group_name = ''

        self.remove_child(child)


class HostGroup(UIGroup):

    help_intro = '''
                 A host group provides a simple way to manage the LUN masking 
                 of a number of iscsi clients as a single unit. The host group
                 contains hosts (iscsi clients) and disks (rbd images). 
                 
                 Once a host is defined to a group, it's lun masking must be 
                 managed through the group. In fact attempts to manage the 
                 disks of a client directly are blocked.
                 
                 The following commands enable you to manage the membership of
                 the host group.

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
        use the 'host' sub-command to add and remove hosts from a host group.
        Adding a host will automatically map the host group's disks to that
        specific host. Removing a host however, does not change the hosts
        disk masking - it simply removes the host from group.

        e.g.
        host add|remove iqn.1994-05.com.redhat:rh7-client
        """

        if action not in HostGroup.valid_actions:
            self.logger.error("Invalid request - must be "
                              "host add|remove <client_iqn>")
            return

        # basic checks
        client_group = self._get_client_group()
        client_map = client_group.client_map
        if client_iqn not in client_map:
            self.logger.error("'{}' is not managed by a "
                              "group".format(client_iqn))
            return

        current_group = client_map[client_iqn].group_name
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
                    "members": client_iqn}

        api = APIRequest(group_api, data=api_vars)
        api.put()
        self.logger.debug("- api call responded "
                          "{}".format(api.response.status_code))
        if api.response.status_code != 200:
            self.logger.error("Failed :"
                              "{}".format(response_message(api.response,
                                                           self.logger)))
            return

        # group updated, so update the UI
        self.logger.debug("Updating the UI")
        if action == 'add':
            HostGroupMember(self, 'host', client_iqn)
            self.update_clients_UI([client_iqn])

        elif action == 'remove':
            child = [child for child in self.children
                     if child.name == client_iqn][0]
            self.delete(child)

        self.logger.info('ok')

    def delete(self, child):

        if child.member_type == 'host':
            client_group = self._get_client_group()
            client = client_group.client_map[child.name]
            client.group_name = ''

        self.remove_child(child)

    def ui_command_disk(self, action, disk_name):
        """
        use the 'disk' sub-command to add or remove a disk from a specific
        host group. Removing disks should be done with care, as the remove
        operation will be executed across all hosts defined to the host group.

        e.g.
        disk add|remove rbd.disk_1
        """

        if action not in HostGroup.valid_actions:
            self.logger.error("Invalid request - must be "
                              "disk add|remove <disk_image>")
            return

        # simple sanity checks
        # 1. does the disk exist in the configuration
        ui_root = self.get_ui_root()
        if disk_name not in [disk.name for disk in ui_root.disks.children]:
            self.logger.error("Disk '{}' is not defined within the "
                              "configuration".format(disk_name))
            return

        # 2. For an 'add' request, the disk must not already be in the host
        # group. Whereas, for a remove request the disk must exist.
        if action == 'add':
            if disk_name in self.disks:
                self.logger.error("'{}' is already defined to this "
                                  "host-group".format(disk_name))
                return
        else:
            if disk_name not in self.disks:
                self.logger.error("'{}' is not a member of this "
                                  "group".format(disk_name))
                return

        # Basic checks passed, hand-off to the API
        group_api = ('{}://{}:{}/api/hostgroup/'
                     '{}'.format(self.http_mode,
                                 "127.0.0.1",
                                 settings.config.api_port,
                                 self.name))

        api_vars = {"action": action,
                    "disks": disk_name}

        api = APIRequest(group_api, data=api_vars)
        api.put()
        self.logger.debug("- api call responded {}".format(api.response.status_code))
        if api.response.status_code != 200:
            self.logger.error("Failed: "
                              "{}".format(response_message(api.response,
                                                           self.logger)))
            return

        # group updated, so update the host-groups UI elements
        self.logger.debug("Updating the UI")
        if action == 'add':
            HostGroupMember(self, 'disk', disk_name)
        elif action == 'remove':
            child = [child for child in self.children
                     if child.name == disk_name][0]
            self.delete(child)

        self.update_clients_UI(self.members)

        self.logger.info('ok')

    @property
    def members(self):
        return [child.name for child in self.children
                if child.member_type == 'host']
    @property
    def disks(self):
        return [child.name for child in self.children
                if child.member_type == 'disk']

    def _get_client_group(self):
        ui_root = self.get_ui_root()
        # we only support one target, so take the first child
        iscsi_target = list(ui_root.target.children)[0]

        return iscsi_target.client_group

    def update_clients_UI(self, client_list):
        self.logger.debug("rereading the config object")
        root = self.get_ui_root()
        config = root._get_config()
        clients = config['clients']

        client_group = self._get_client_group()     # Clients Object
        clients_to_update = [client for client in client_group.children
                             if client.name in client_list]

        # refresh the client with the new config
        self.logger.debug("resync'ing client lun maps")
        client_map = client_group.client_map
        for client in clients_to_update:
            client_map[client.client_iqn].group_name = self.name
            client.drop_luns()
            client.luns = clients[client.client_iqn].get('luns', {})
            client.refresh_luns()

    def summary(self):
        counts = {'disk': 0, 'host': 0}
        for child in self.children:
            counts[child.member_type] += 1
        return "Hosts: {}, Disks: {}".format(counts['host'],
                                             counts['disk']), \
               None


class HostGroupMember(UINode):
    help_intro = '''
                    The entries here show the hosts and disks that are held
                    within a specific host group definition. Care should be 
                    taken when removing disks from a host group, as the remove
                    operation will be performed across each client within the 
                    group.
                 '''

    def __init__(self, parent, member_type, name):
        UINode.__init__(self, name, parent)
        self.member_type = member_type

    def summary(self):
        return "{}".format(self.member_type), True
