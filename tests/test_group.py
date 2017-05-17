#!/usr/bin/env python

import sys
import logging

from ceph_iscsi_config.group import Group
import ceph_iscsi_config.settings as settings

settings.init()


# Pre-reqs
# 1. You need a working ceph iscsi environment
# 2. disks and clients need to pre-exist

log = logging.getLogger()
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
log.addHandler(ch)


#1. Create a new group definition
new_group = Group(log, "mygroup",
                  ['iqn.1994-05.com.redhat:my-esx-1',
                   'iqn.1994-05.com.redhat:my-esx-2'],
                  ['rbd.disk_2', 'rbd.disk_1'])

new_group.apply()
assert not new_group.error, "Error caught when creating the group"

assert "mygroup" in new_group.config.config["groups"], \
       "Group did not create/commit correctly to the configuration"

update_group = Group(log, "mygroup",
                  ['iqn.1994-05.com.redhat:my-esx-1',
                   'iqn.1994-05.com.redhat:my-esx-2',
                   'iqn.1994-05.com.redhat:my-esx-3'],
                  ['rbd.disk_2', 'rbd.disk_1','rbd.disk_3'])

update_group.apply()
assert len(update_group.config.config['groups']['mygroup']['members']) == 3, \
       "mygroup doesn't contain 3 members"

#?. Delete the group, just created
old_group = Group(log, "mygroup")
old_group.purge()
#
assert "mygroup" not in old_group.config.config["groups"], \
       "Group did not get removed from the config object"
