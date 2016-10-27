#!/usr/bin/env python

__author__ = 'Paul Cuzner, Michael Christie'

import subprocess
import fileinput
import os

from rtslib_fb import root
from rtslib_fb.utils import RTSLibError, RTSLibNotInCFS

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.alua import ALUATargetPortGroup


def dm_remove_device(dm_device):
    rm_ok = True

    try:
        subprocess.check_output("multipath -f {}".format(os.path.basename(dm_device)),
                                shell=True)

    except subprocess.CalledProcessError:
        rm_ok = False

    return rm_ok


def rbd_unmap(rbd_path):

    try:
        subprocess.check_output("rbd unmap {}".format(rbd_path), shell=True)
    except subprocess.CalledProcessError:
        unmap_ok = False
    else:
        unmap_ok = True

        # unmap'd from runtime, now remove from the rbdmap file referenced at boot
        for rbdmap_entry in fileinput.input('/etc/ceph/rbdmap', inplace=True):
            if rbdmap_entry.startswith(rbd_path):
                continue
            print rbdmap_entry.strip()

    return unmap_ok

class LIO(object):

    def __init__(self):
        self.lio_root = root.RTSRoot()
        self.error = False
        self.error_msg = ''
        self.changed = False

    def save_config(self):
        self.lio_root.save_to_file()

    def drop_lun_maps(self, config, update_config):

        # disk_keys = config.config['disks'].keys()

        for disk_key in config.config['disks'].keys():

            # pool, image = disk_key.split('/')
            dm_device = config.config['disks'][disk_key]['dm_device']

            for stg_object in self.lio_root.storage_objects:

                if stg_object.name == disk_key:

                    # this is temp until the rtslib lun/backstore deletes the
                    # alua groups for the backstore/lun too.
                    alua_dir = os.path.join(stg_object.path, "alua")

                    for dirname in next(os.walk(alua_dir))[1]:
                        if dirname != "default_tg_pt_gp":
                            try:
                                alua_tpg = ALUATargetPortGroup(stg_object, dirname)
                                alua_tpg.delete()
                            except (RTSLibError, RTSLibNotInCFS) as err:
                                self.error = True
                                self.error_msg = err
                                # fall below. We might be able to clean up still

                    # this is an rbd device that's in the config object, so remove it
                    try:
                        stg_object.delete()
                    except RTSLibError as err:
                        self.error = True
                        self.error_msg = err
                    else:
                        dm_remove_device(dm_device)
                        rbd_path = disk_key.replace('.', '/', 1)
                        rbd_unmap(rbd_path)

                        self.changed = True

                        if update_config:
                            # update the disk item to remove the wwn information
                            image_metadata = config.config['disks'][disk_key]   # current disk meta data dict
                            image_metadata['wwn'] = ''
                            image_metadata['dm_device'] = ''
                            config.update_item("disks", disk_key, image_metadata)


class Gateway(LIO):

    def __init__(self, config_object):
        LIO.__init__(self)

        self.config = config_object

    def session_count(self):
        return len(list(self.lio_root.sessions))

    def drop_target(self, this_host, update_config):
        iqn = self.config.config['gateways'][this_host]['iqn']

        lio_root = root.RTSRoot()
        for tgt in lio_root.targets:
            if tgt.wwn == iqn:
                tgt.delete()
                self.changed = True
                if update_config:
                    # remove the gateway from the config dict
                    self.config.del_item('gateways', this_host)
