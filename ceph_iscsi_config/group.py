#!/usr/bin/env python2

# import ceph_iscsi_config.settings as settings
import json

from ceph_iscsi_config.common import Config
from ceph_iscsi_config.client import GWClient
from ceph_iscsi_config.utils import ListComparison


class Group(object):

    def __init__(self, logger, target_iqn, group_name, members=[], disks=[]):

        """
        Manage a host group definition. The input for the group object is the
        desired state of the group where the logic enforced produces an
        idempotent group definition across API/CLI and more importantly Ansible

        :param logger: (logging object) used for centralised logging
        :param target_iqn: (str) target iqn
        :param group_name: (str) group name
        :param members: (list) iscsi IQN's of the clients
        :param disks: (list) disk names of the format pool.image
        """

        self.logger = logger

        self.error = False
        self.error_msg = ''
        self.num_changes = 0

        self.config = Config(logger)
        if self.config.error:
            self.error = self.config.error
            self.error_msg = self.config.error_msg
            return

        self.target_iqn = target_iqn
        self.group_name = group_name
        self.group_members = members
        self.disks = disks

        target_config = self.config.config['targets'][self.target_iqn]
        if group_name in target_config['groups']:
            self.new_group = False
        else:
            self.new_group = True

        self.logger.debug("Group : name={}".format(self.group_name))
        self.logger.debug("Group : members={}".format(self.group_members))
        self.logger.debug("Group : disks={}".format(self.disks))

    def __str__(self):
        return ("Group: {}\n- Members: {}\n- "
                "Disks: {}".format(self.group_name,
                                   self.group_members,
                                   self.disks))

    def _set_error(self, error_msg):
        self.error = True
        self.error_msg = error_msg
        self.logger.debug("Error: {}".format(self.error_msg))

    def _valid_client(self, action, client_iqn):
        """
        validate the addition of a specific client
        :param action: (str) add or remove request
        :param client_iqn: (str) iqn of the client to add tot he group
        :return: (bool) true/false whether the client should be accepted
        """

        target_config = self.config.config['targets'][self.target_iqn]

        self.logger.debug("checking '{}'".format(client_iqn))

        # to validate the request, pass through a 'negative' filter
        if action == 'add':
            client = target_config['clients'].get(client_iqn, {})
            if not client:
                self._set_error("client '{}' doesn't exist".format(client_iqn))
                return False
            elif client.get('luns'):
                self._set_error("Client '{}' already has luns. "
                                "Only clients without prior lun maps "
                                "can be added to a group".format(client_iqn))
                return False
            elif client.get('group_name'):
                self._set_error("Client already assigned to {} - a client "
                                "can only belong to one host "
                                "group".format(client.get('group_name')))
                return False
        else:
            # client_iqn must exist in the group
            if client_iqn not in target_config['groups'][self.group_name].get('members'):
                self._set_error("client '{}' is not a member of "
                                "{}".format(client_iqn,
                                            self.group_name))
                return False

        # to reach here the request is considered valid
        self.logger.debug("'{}' client '{}' for group '{}'"
                          " is valid".format(action,
                                             client_iqn,
                                             self.group_name))
        return True

    def _valid_disk(self, action, disk):

        self.logger.debug("checking disk '{}'".format(disk))
        target_config = self.config.config['targets'][self.target_iqn]
        if action == 'add':

            if disk not in target_config['disks']:
                self._set_error("disk '{}' doesn't exist".format(disk))
                return False
        else:
            if disk not in target_config['groups'][self.group_name]['disks']:
                self._set_error("disk '{}' is not in the group".format(disk))
                return False

        return True

    def _next_lun(self):
        """
        Look at the disk list for the group and return the 1st available free
        LUN id used for adding disks to the group
        :return: (int) lun Id
        """

        lun_range = list(range(0, 256, 1))      # 0->255
        target_config = self.config.config['targets'][self.target_iqn]
        group = target_config['groups'][self.group_name]
        group_disks = group.get('disks')
        for d in group_disks:
            lun_range.remove(group_disks[d].get('lun_id'))

        return lun_range[0]

    def apply(self):
        """
        setup/manage the group definition
        :return: NULL
        """
        group_seed = {
            "members": [],
            "disks": {}
        }

        target_config = self.config.config['targets'][self.target_iqn]

        if self.new_group:

            # New Group definition, so seed it
            self.logger.debug("Processing request for new group "
                              "'{}'".format(self.group_name))
            if len(set(self.group_members)) != len(self.group_members):
                self._set_error("Member must contain unique clients - no "
                                "duplication")
                return

            self.logger.debug("New group definition required")

            # new_group = True
            target_config['groups'][self.group_name] = group_seed

        # Now the group definition is at least seeded, so let's look at the
        # member and disk information passed

        this_group = target_config['groups'][self.group_name]

        members = ListComparison(this_group.get('members'),
                                 self.group_members)
        disks = ListComparison(this_group.get('disks').keys(),
                               self.disks)

        if set(self.disks) != set(this_group.get('disks')) or \
                set(self.group_members) != set(this_group.get('members')):
            group_changed = True
        else:
            group_changed = False

        if group_changed or self.new_group:

            if self.valid_request(members, disks):
                self.update_metadata(members, disks)
            else:
                self._set_error("Group request failed validation")
                return

        else:
            # no changes required
            self.logger.info("Current group definition matches request")

        self.enforce_policy()

    def valid_request(self, members, disks):

        self.logger.info("Validating client membership")
        for mbr in members.added:
            if not self._valid_client('add', mbr):
                self.logger.error("'{}' failed checks".format(mbr))
                return False
        for mbr in members.removed:
            if not self._valid_client('remove', mbr):
                self.logger.error("'{}' failed checks".format(mbr))
                return False

        self.logger.debug("Client membership checks passed")
        self.logger.debug("clients to add : {}".format(members.added))
        self.logger.debug("clients to remove : {}".format(members.removed))

        # client membership is valid, check disks
        self.logger.info("Validating disk membership")
        for disk_name in disks.added:
            if not self._valid_disk('add', disk_name):
                self.logger.error("'{}' failed checks".format(disk_name))
                return False
        for disk_name in disks.removed:
            if not self._valid_disk('remove', disk_name):
                self.logger.error("'{}' failed checks".format(disk_name))
                return False

        self.logger.info("Disk membership checks passed")
        self.logger.debug("disks to add : {}".format(disks.added))
        self.logger.debug("disks to remove : {}".format(disks.removed))

        return True

    def update_metadata(self, members, disks):

        target_config = self.config.config['targets'][self.target_iqn]
        this_group = target_config['groups'].get(self.group_name, {})
        group_disks = this_group.get('disks', {})
        if disks.added:
            # update the groups disk list
            for disk in disks.added:
                lun_seq = self._next_lun()
                group_disks[disk] = {"lun_id": lun_seq}
                self.logger.debug("- adding '{}' to group '{}' @ "
                                  "lun id {}".format(disk,
                                                     self.group_name,
                                                     lun_seq))

        if disks.removed:
            # remove disk from the group definition
            for disk in disks.removed:
                del group_disks[disk]
                self.logger.debug("- removed '{}' from group "
                                  "{}".format(disk,
                                              self.group_name))

        if disks.added or disks.removed:
            # update each clients meta data
            self.logger.debug("updating clients LUN masking with "
                              "{}".format(json.dumps(group_disks)))

            for client_iqn in self.group_members:
                self.update_disk_md(client_iqn, group_disks)

        # handle client membership
        if members.changed:
            for client_iqn in members.added:
                self.add_client(client_iqn)
                self.update_disk_md(client_iqn, group_disks)
            for client_iqn in members.removed:
                self.remove_client(client_iqn)

        this_group['members'] = self.group_members
        this_group['disks'] = group_disks

        self.logger.debug("Group '{}' updated to "
                          "{}".format(self.group_name,
                                      json.dumps(this_group)))
        target_config['groups'][self.group_name] = this_group
        self.config.update_item('targets', self.target_iqn, target_config)
        self.config.commit()

    def enforce_policy(self):

        target_config = self.config.config['targets'][self.target_iqn]
        this_group = target_config['groups'][self.group_name]
        group_disks = this_group.get('disks')
        host_group = this_group.get('members')

        image_list = sorted(group_disks.items(),
                            key=lambda v: v[1]['lun_id'])

        for client_iqn in host_group:
            self.update_client(client_iqn, image_list)
            if self.error:
                # Applying the policy failed, so report and abort
                self.logger.error("Unable to apply policy to {} "
                                  ": {}".format(client_iqn,
                                                self.error_msg))
                return

    def add_client(self, client_iqn):
        target_config = self.config.config['targets'][self.target_iqn]
        client_metadata = target_config['clients'][client_iqn]
        client_metadata['group_name'] = self.group_name
        self.config.update_item('targets', self.target_iqn, target_config)
        self.logger.info("Added {} to group {}".format(client_iqn,
                                                       self.group_name))

    def update_disk_md(self, client_iqn, group_disks):
        target_config = self.config.config['targets'][self.target_iqn]
        md = target_config['clients'].get(client_iqn)
        md['luns'] = group_disks
        self.config.update_item('targets', self.target_iqn, target_config)
        self.logger.info("updated {} disk map to "
                         "{}".format(client_iqn,
                                     json.dumps(group_disks)))

    def update_client(self, client_iqn, image_list):

        client = GWClient(self.logger, client_iqn, image_list, '', self.target_iqn)
        client.manage('reconfigure')

        # grab the client's metadata from the config (needed by setup_luns)
        target_config = self.config.config['targets'][self.target_iqn]
        client.metadata = target_config['clients'][client_iqn]
        client.setup_luns()

        if client.error:
            self._set_error(client.error_msg)

    def remove_client(self, client_iqn):
        target_config = self.config.config['targets'][self.target_iqn]
        client_md = target_config["clients"][client_iqn]

        # remove the group_name setting from the client
        client_md['group_name'] = ''
        self.config.update_item('targets', self.target_iqn, target_config)
        self.logger.info("Removed {} from group {}".format(client_iqn,
                                                           self.group_name))

    def purge(self):

        # act on the group name
        # get the members from the current definition
        target_config = self.config.config['targets'][self.target_iqn]
        groups = target_config['groups']
        if self.group_name in groups:
            for mbr in groups[self.group_name]["members"]:
                self.remove_client(mbr)

            # issue a del_item to the config object for this group_name
            groups.pop(self.group_name)
            self.config.update_item('targets', self.target_iqn, target_config)
            self.config.commit()
            self.logger.info("Group {} removed".format(self.group_name))
        else:

            self._set_error("Group name requested does not exist")
            return
