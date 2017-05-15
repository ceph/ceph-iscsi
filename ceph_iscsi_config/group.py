#!/usr/bin/env python

# import ceph_iscsi_config.settings as settings

from ceph_iscsi_config.common import Config
from ceph_iscsi_config.client import GWClient
# from ceph_iscsi_config.utils import convert_2_bytes

__author__ = 'pcuzner@redhat.com'


class Group(object):

    def __init__(self, logger, group_name, members=[], disks=[],
                 mode='create'):
        self.logger = logger

        self.error = False
        self.error_msg = ''
        self.num_changes = 0

        self.config = Config(logger)
        if self.config.error:
            self.error = self.config.error
            self.error_msg = self.config.error_msg
            return

        # check that the config object has a group section
        Group._check_config(self.logger, self.config)

        self.group_name = group_name
        self.group_members = members
        self.disks = disks
        self.mode = mode

    @staticmethod
    def _check_config(logger, config_object):

        if 'groups' in config_object.config:
            logger.debug("Config object contains a 'groups' section - upgrade "
                         "not required")
            return
        else:
            # Need to upgrade the config object to include the new
            # 'groups' section
            logger.info("Adding 'groups' section to config object")
            config_object.add_item("groups", element_name=None,
                                   initial_value={})
            config_object.update_item("version", element_name=None,
                                      element_value=3)
            config_object.commit()

    def __str__(self):
        return ("Group: {}\n- Members: {}\n- "
                "Disks: {}".format(self.group_name,
                                   self.group_members,
                                   self.disks))

    def _set_error(self, error_msg):
        self.error = True
        self.error_msg = error_msg
        self.logger.debug("Error: {}".format(self.error_msg))

    def manage(self):

        if self.mode == 'create':
            self.apply()
        else:
            self.purge()

    def _valid_client(self, client_iqn, config):

        client = config['clients'].get(client_iqn, {})
        if not client:
            self._set_error("Group member ({}) doesn't "
                            "exist".format(client_iqn))
            return False
        elif client.get('luns'):
            self._set_error("Client '{}' already has luns. "
                            "Only clients without prior lun maps "
                            "can be added to a group".format(client_iqn))
            return False

        return True

    def apply(self):

        if self.group_name not in self.config.config['groups']:
            self.logger.debug("Group mgmt processing new request for "
                              "{}".format(self.group_name))
            if len(set(self.group_members)) != len(self.group_members):
                self._set_error("Member must contain unique clients - no "
                                "duplicatoion")
                return

            # this is a new group definition, and must have members
            config_dict = self.config.config
            if self.group_members:
                self.logger.debug("Validating group members")
                for mbr in self.group_members:
                    if not self._valid_client(mbr, config_dict):
                        return
            else:
                self._set_error("group defined without members")
                return

            self.logger.debug("Validating requested disks")
            bad_disks = [disk_name for disk_name in self.disks
                         if disk_name not in self.config.config['disks']]
            if not self.disks:
                self._set_error("a list of disks must be supplied")
                return
            elif bad_disks:
                self._set_error("disk(s) {} do not"
                                " exist".format(','.join(bad_disks)))
                return

            # Group definition is ok to use
            self.logger.info("Group request is valid")

            # update the respective client definitions
            self.logger.debug("Applying the group definition for "
                              "{}".format(self.group_name))
            image_list = self.disks
            for mbr in self.group_members:

                client = GWClient(self.logger, mbr, image_list, '')
                client.define_client()      # set up clients ACL

                # grab the metadata from the current definition
                client.metadata = self.config.config['clients'][mbr]
                client.setup_luns()

                if client.error:
                    self._set_error(client.error_msg)
                    return
                else:
                    self.logger.info("Updating config object for "
                                     "client '{}'".format(mbr))
                    client.metadata['group_name'] = self.group_name
                    self.config.update_item("clients", mbr, client.metadata)

            # update the config object to include the new group definition
            self.logger.debug("Adding group definition to the config object")
            group_def = {"members": self.group_members,
                         "disks": self.disks}
            self.config.add_item("groups", self.group_name, group_def)
            self.config.commit()

        else:
            # this is an existing definition
            self.logger.debug("Updating existing group: "
                              "{}".format(self.group_name))

    def purge(self):

        # act on the group name
        # get the members from the current definition
        groups = self.config.config['groups']
        if self.group_name in groups:
            for mbr in groups[self.group_name]["members"]:
                client_md = self.config.config["clients"][mbr]

                # remove the group_name setting from each client
                client_md['group_name'] = ''
                self.config.update_item("clients", mbr, client_md)

            # issue a del_item to the config object for this group_name
            self.config.del_item("groups", self.group_name)
            self.config.commit()
        else:
            self._set_error("Group name requested does not exist")
            return
