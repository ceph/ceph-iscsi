#!/usr/bin/env python

import sys
import logging

from ceph_iscsi_config.group import Group
import ceph_iscsi_config.settings as settings

settings.init()


# Pre-reqs
# 1. You need a working ceph iscsi environment
# 2. target, disks and clients need to pre-exist

log = logging.getLogger()
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
log.addHandler(ch)


# 1. Create a new group definition
target_iqn = 'iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw'

new_group = Group(log, target_iqn, "mygroup",
                  ['iqn.1994-05.com.redhat:my-esx-1',
                   'iqn.1994-05.com.redhat:my-esx-2'],
                  ['rbd.disk_2', 'rbd.disk_1'])

new_group.apply()
assert not new_group.error, "Error caught when creating the group"

target_config = new_group.config.config['targets'][target_iqn]
assert "mygroup" in target_config["groups"], \
       "Group did not create/commit correctly to the configuration"

update_group = Group(log, target_iqn, "mygroup",
                     ['iqn.1994-05.com.redhat:my-esx-1',
                      'iqn.1994-05.com.redhat:my-esx-2',
                      'iqn.1994-05.com.redhat:my-esx-3'],
                     ['rbd.disk_2', 'rbd.disk_1', 'rbd.disk_3'])

update_group.apply()
target_config = update_group.config.config['targets'][target_iqn]
assert len(target_config['groups']['mygroup']['members']) == 3, \
    "mygroup doesn't contain 3 members"

# ?. Delete the group, just created
old_group = Group(log, target_iqn, "mygroup")
old_group.purge()
#
target_config = old_group.config.config['targets'][target_iqn]
assert "mygroup" not in target_config["groups"], \
       "Group did not get removed from the config object"
