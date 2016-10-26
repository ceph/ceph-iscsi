#!/usr/bin/env python

__author__ = 'pcuzner@redhat.com'

import ceph_iscsi_config.settings as settings

from ceph_iscsi_config.common import Config
from ceph_iscsi_config.alua import ALUATargetPortGroup
from ceph_iscsi_config.utils import convert_2_bytes, shellcommand, get_pool_id

import fileinput
from rtslib_fb import BlockStorageObject, root
from rtslib_fb.utils import RTSLibError, RTSLibNotInCFS, fread

import rados
import rbd
import json
import os
import glob

from time import sleep
from socket import gethostname


class RBDDev(object):

    rbd_feature_list = ['RBD_FEATURE_LAYERING', 'RBD_FEATURE_EXCLUSIVE_LOCK']

    def __init__(self, image, size, pool='rbd'):
        self.image = image
        self.size = size
        self.pool = pool
        self.pool_id = get_pool_id(pool_name=self.pool)
        self.error = False
        self.error_msg = ''
        self.rbd_map = None
        self.map_needed = False
        self.changed = False

    def create(self):
        """
        Create an rbd image compatible with exporting through LIO to multiple clients
        :return: status code and msg
        """

        size_bytes = convert_2_bytes(self.size)

        # build the required feature settings into an int
        feature_int = 0
        for feature in RBDDev.rbd_feature_list:
            feature_int += getattr(rbd, feature)

        with rados.Rados(conffile=settings.config.cephconf) as cluster:
            with cluster.open_ioctx(self.pool) as ioctx:
                rbd_inst = rbd.RBD()
                try:
                    rbd_inst.create(ioctx, self.image, size_bytes, features=feature_int, old_format=False)
                except (rbd.ImageExists, rbd.InvalidArgument) as err:
                    self.error = True
                    self.error_msg = "Failed to create rbd image {} in pool {} : {}".format(self.image,
                                                                                            self.pool,
                                                                                            err)

    def delete_rbd(self):
        """
        Delete the current rbd image
        :return: nothing, but the objects error attribute is set if there are problems
        """

        rbd_deleted = False
        with rados.Rados(conffile=settings.config.cephconf) as cluster:
            with cluster.open_ioctx(self.pool) as ioctx:
                rbd_inst = rbd.RBD()

                ctr = 0
                while ctr < settings.config.time_out:

                    try:
                        rbd_inst.remove(ioctx, self.image)
                    except rbd.ImageBusy:
                        # catch and ignore the busy state - rbd probably still mapped on
                        # another gateway, so we keep trying
                        pass
                    else:
                        rbd_deleted = True
                        break

                    sleep(settings.config.loop_delay)
                    ctr += settings.config.loop_delay

                if rbd_deleted:
                    return
                else:
                    self.error = True


    def rbd_size(self):
        """
        Confirm that the existing rbd image size, matches the requirement passed in the ansible
        config file - if the required size is > than current, resize the rbd image to match
        :return: boolean value reflecting whether the rbd image was resized
        """

        with rados.Rados(conffile=settings.config.cephconf) as cluster:
            with cluster.open_ioctx(self.pool) as ioctx:
                with rbd.Image(ioctx, self.image) as rbd_image:

                    # get the current size in bytes
                    current_bytes = rbd_image.size()     # bytes
                    target_bytes = convert_2_bytes(self.size)

                    if target_bytes > current_bytes:

                        # resize method, doesn't document potential exceptions
                        # so using a generic catch all (Yuk!)
                        try:
                            rbd_image.resize(target_bytes)
                        except:
                            self.error = True
                            self.error_msg = "rbd image resize failed for {}".format(self.image)
                        else:
                            self.changed = True

    def _get_rbd_id(self):
        """
        pass back the rbdX component of the rbd_map attribute
        :return: str - rbdX
        """
        return os.path.basename(self.rbd_map)

    def _get_size_bytes(self):
        """
        return the current size of the rbd from sysfs query
        :return:
        """
        rbd_bytes = 0
        if self.rbd_map:
            rbd_id = self.rbd_map.split('/')[-1]
            rbd_sysfs_path = "/sys/class/block/{}/size".format(rbd_id)
            # size is defined in 512b sectors
            rbd_bytes = int(fread(rbd_sysfs_path))*512
        return rbd_bytes

    def rbdmap_entry(self):
        """
        check the given image has an entry in /etc/ceph/rbdmap - if not add it!
        :return: boolean indicating whether the rbdmap file was updated
        """

        # Assume it's not there, so if we find it flip this to False
        entry_needed = True

        srch_str = "{}/{}".format(self.pool, self.image)
        with open(settings.config.rbd_map_file, 'a+') as rbdmap:

            for entry in rbdmap:
                if entry.startswith(srch_str):
                    # found it - get out,
                    entry_needed = False
                    break

            if entry_needed:
                # need to add an entry to the rbdmap file
                rbdmap.write("{}\t\tid={},keyring=/etc/ceph/{},"
                             "options=noshare\n".format(srch_str,
                                                        settings.config.ceph_user,
                                                        settings.config.gateway_keyring))

        return entry_needed

    def unmap_rbd(self):
        """
        Unmap this rbd image from the local system
        :return: None
        """

        rbd_path = "{}/{}".format(self.pool, self.image)
        resp = shellcommand("rbd -c {} unmap {}".format(settings.config.cephconf, rbd_path))
        if resp != '':
            self.error = True
            return

        # unmap'd from runtime, now remove from the rbdmap file referenced at boot
        for rbdmap_entry in fileinput.input(settings.config.rbd_map_file, inplace=True):
            if rbdmap_entry.startswith(rbd_path):
                continue
            print rbdmap_entry.strip()



    def get_rbd_map(self):
        """
        Set objects rbd_map attribute based on the rbd showmapped command
        e.g. /dev/rbdX
        :return: nothing
        """

        # Now look at mapping of the device - which would execute on all target hosts
        showmap_cmd = 'rbd -c {} showmapped --format=json'.format(settings.config.cephconf)
        response = shellcommand(showmap_cmd)
        if not response:                        # showmapped command must have failed
            self.rbd_map = None
            return

        # Check the showmapped output for this rbd image, and if so set the mapped device name
        mapped_rbds = json.loads(response)
        for rbd_id in mapped_rbds:
            if (mapped_rbds[rbd_id]['name'] == self.image and
                    mapped_rbds[rbd_id]['pool'] == self.pool):
                self.rbd_map = mapped_rbds[rbd_id]['device'].rstrip()
                return

        # At this point the rbd image is not in showmap output, so map it
        self.map_needed = True
        # lock_on_read was not merged until RHCS 2.1. We temporarily
        # support it on/off to make the transition during devel easier
        map_cmd = 'rbd -c {} map -o noshare,lock_on_read {}/{}'.format(settings.config.cephconf,
                                                                       self.pool,
                                                                       self.image)
        response = shellcommand(map_cmd)
        if response is None:
            map_cmd = 'rbd -c {} map -o noshare {}/{}'.format(settings.config.cephconf,
                                                              self.pool,
                                                              self.image)
            response = shellcommand(map_cmd)

        if response:
            self.rbd_map = response.rstrip()

    @staticmethod
    def rbd_list(conf=None, pool='rbd'):
        """
        return a list of rbd images in a given pool
        :param pool: pool name to look at to return a list of rbd image names for (str)
        :return: list of rbd image names (list)
        """

        if conf is None:
            conf = settings.config.cephconf

        with rados.Rados(conffile=conf) as cluster:
            with cluster.open_ioctx(pool) as ioctx:
                rbd_inst = rbd.RBD()
                rbd_names = rbd_inst.list(ioctx)
        return rbd_names

    size_bytes = property(_get_size_bytes,
                          doc="return the current size of the rbd in bytes from sysfs")

    rbd_id = property(_get_rbd_id,
                      doc="return the mapped rbd name for this rbd")


class LUN(object):

    def __init__(self, logger, pool, image, size, allocating_host):
        self.logger = logger
        self.image = image
        self.pool = pool
        self.pool_id = 0
        self.size = size
        self.config_key = '{}.{}'.format(self.pool, self.image)

        # the allocating host could be fqdn or shortname - but the config
        # only uses shortname so it needs to be converted to shortname format
        self.allocating_host = allocating_host.split('.')[0]

        self.owner = ''                             # gateway host that owns the preferred path for this LUN
        self.error = False
        self.error_msg = ''
        self.num_changes = 0
        self.dm_device = ''                         # e.g. /dev/mapper/0-58f8b515f007c

        self.config = Config(logger)
        if self.config.error:
            self.error = self.config.error
            self.error_msg = self.config.error_msg
            return

        self._validate_request()

    def _validate_request(self):

            # Before we start make sure that the target host is actually defined to the config
        if self.allocating_host not in self.config.config['gateways'].keys():
            self.logger.critical("Owning host is not valid, please provide a valid gateway name for this rbd image")
            self.error = True
            self.error_msg = ("host name given for {} is not a valid gateway name, "
                              "listed in the config".format(self.image))
        elif not rados_pool(pool=self.pool):
            # Could create the pool, but a fat finger moment in the config file would mean rbd images
            # get created and mapped, and then need correcting. Better to exit if the pool doesn't exist
            self.error = True
            self.error_msg = "Pool '{}' does not exist. Unable to continue".format(self.pool)

    @staticmethod
    def remove_dm_device(dm_path):
        dm_name = os.path.basename(dm_path)
        resp = shellcommand('multipath -f {}'.format(dm_name))

        return False if resp else True

    def remove_lun(self):

        this_host = gethostname().split('.')[0]
        self.logger.info("LUN deletion request received, rbd removal to be "
                         "performed by {}".format(self.allocating_host))

        # First ensure the LUN is not allocated to a client
        clients = self.config.config['clients']
        lun_in_use = False
        for iqn in clients:
            client_luns = clients[iqn]['luns'].keys()
            if self.config_key in client_luns:
                lun_in_use = True
                break

        if lun_in_use:
            # this will fail the ansible task for this lun/host
            self.error = True
            self.error_msg = "Unable to delete {} - allocated to {}".format(self.config_key,
                                                                            iqn)
            self.logger.warning(self.error_msg)
            return

        # Check that the LUN is in LIO - if not there is nothing to do for this request
        lun = self.lun_in_lio()
        if not lun:
            return

        # Now we know the request is for a LUN in LIO, and it's not masked to a client
        self.remove_dev_from_lio()
        if self.error:
            return

        rbd_image = RBDDev(self.image, '0G', self.pool)
        rbd_image.get_rbd_map()

        dm_path = LUN.dm_device_name_from_rbd_map(rbd_image.rbd_map)
        if LUN.remove_dm_device(dm_path):

            rbd_image.unmap_rbd()
            if rbd_image.error:
                self.error = True
                self.error_msg = "Unable to unmap {} from host".format(self.config_key)
                self.logger.error(self.error_msg)
                return

            self.num_changes += 1

            if this_host == self.allocating_host:
                # by using the allocating host we ensure the delete is not
                # issue by several hosts when initiated through ansible
                rbd_image.delete_rbd()
                if rbd_image.error:
                    self.error = True
                    self.error_msg = "Unable to delete the underlying rbd image {}".format(self.config_key)
                    return

                # remove the definition from the config object
                self.config.del_item('disks', self.config_key)
                self.config.commit()

        else:
            self.error = True
            self.error_msg = "Unable to remove dm device for {}".format(self.config_key)
            self.logger.error(self.error_msg)
            return

    def manage(self, desired_state):

        self.logger.debug("lun.manage request for {}, desired state {}".format(self.image, desired_state))

        if desired_state == 'present':

            self.allocate()

        elif desired_state == 'absent':

            self.remove_lun()


    def allocate(self):
        self.logger.debug("LUN.allocate starting, getting a list of rbd devices")
        disk_list = RBDDev.rbd_list(pool=self.pool)
        self.logger.debug("rados pool '{}' contains the following - {}".format(self.pool, disk_list))
        this_host = gethostname().split('.')[0]
        self.logger.debug("Hostname Check - this host is {}, target host for "
                          "allocations is {}".format(this_host, self.allocating_host))
        rbd_image = RBDDev(self.image, self.size, self.pool)
        self.pool_id = rbd_image.pool_id

        # if the image required isn't defined, create it!
        if self.image not in disk_list:
            # create the requested disk if this is the 'owning' host
            if this_host == self.allocating_host:            # is_this_host(target_host):

                rbd_image.create()

                if not rbd_image.error:
                    self.config.add_item('disks', self.config_key)
                    self.logger.info("(LUN.allocate) created {}/{} successfully".format(self.pool, self.image))
                    self.num_changes += 1
                else:
                    self.error = True
                    self.error_msg = rbd_image.error_msg
                    return

            else:
                # the image isn't there, and this isn't the 'owning' host
                # so wait until the disk arrives
                waiting = 0
                while self.image not in disk_list:
                    sleep(settings.config.loop_delay)
                    disk_list = RBDDev.rbd_list(pool=self.pool)
                    waiting += settings.config.loop_delay
                    if waiting >= settings.config.time_out:
                        self.error = True
                        self.error_msg = "(LUN.allocate) timed out waiting for rbd to show up"
                        return
        else:
            # requested image is defined to ceph, so ensure it's in the config
            if self.config_key not in self.config.config['disks']:
                self.config.add_item('disks', self.config_key)

        # make sure the rbd is mapped. this will also ensure the
        # RBDDEV object will hold a valid dm_device attribute
        rbd_image.get_rbd_map()
        if rbd_image.map_needed:
            self.num_changes += 1

        self.logger.debug("Check the rbd image size matches the request")

        # if updates_made is not set, the disk pre-exists so on the owning host see if it needs to be resized
        if self.num_changes == 0 and this_host == self.allocating_host:       # is_this_host(target_host):

            # check the size, and update if needed
            rbd_image.rbd_size()
            if rbd_image.error:
                self.logger.critical(rbd_image.error_msg)
                self.error = True
                self.error_msg = rbd_image.error_msg
                return

            if rbd_image.changed:
                self.logger.info("rbd image {} resized to {}".format(self.image, self.size))
                self.num_changes += 1
            else:
                self.logger.debug("rbd image {} size matches the configuration file request".format(self.image))

        # for LIO mapping purposes, we use the device mapper device not the raw /dev/rbdX device
        # Using the dm device ensures that any connectivity issue doesn't result in stale device
        # structures in the kernel, since device-mapper will tidy those up
        self.dm_get_device(rbd_image.rbd_map)
        if self.dm_device is None:
            self.logger.critical("Could not find dm multipath device for {}. Make sure the multipathd"
                                 " service is enabled, and confirm entry is in /dev/mapper/".format(self.image))
            self.error = True
            self.error_msg = "Could not find dm multipath device for {}".format(self.image)
            return

        # ensure the dm device size matches the request size
        if not self.dm_size_ok(rbd_image):
            self.error = True
            self.error_msg = "Unable to sync the dm device to the parent rbd size - {}".format(self.image)
            self.logger.critical(self.error_msg)
            return

        self.logger.debug("Begin processing LIO mapping requirement")

        self.logger.debug("(LUN.allocate) {} is mapped to {}.".format(self.image, self.dm_device))

        # check this rbd image is in the /etc/ceph/rbdmap file
        if rbd_image.rbdmap_entry():
            self.logger.debug('(LUN.allocate) Entry added to /etc/ceph/rbdmap for {}/{}'.format(self.pool, self.image))
            self.num_changes += 1

        # now see if we need to add this rbd image to LIO
        lun = self.lun_in_lio()

        if not lun:

            # this image has not been defined to this hosts LIO, so check the config for the details and
            # if it's  missing define the wwn/alua_state and update the config
            if this_host == self.allocating_host:
                # first check to see if the device needs adding
                try:
                    wwn = self.config.config['disks'][self.config_key]['wwn']
                except KeyError:
                    wwn = ''

                if wwn == '':
                    # disk hasn't been defined to LIO yet, it' not been defined to the config yet
                    # and this is the allocating host
                    lun = self.add_dev_to_lio()
                    if self.error:
                        return

                    # lun is now in LIO, time for some housekeeping :P
                    wwn = lun._get_wwn()
                    self.owner = LUN.set_owner(self.config.config['gateways'])
                    self.logger.debug("Owner for {} will be {}".format(self.image, self.owner))

                    disk_attr = {"wwn": wwn,
                                 "image": self.image,
                                 "owner": self.owner,
                                 "pool": self.pool,
                                 "pool_id": rbd_image.pool_id,
                                 "dm_device": self.dm_device}

                    self.config.update_item('disks', self.config_key, disk_attr)

                    gateway_dict = self.config.config['gateways'][self.owner]
                    gateway_dict['active_luns'] += 1

                    self.config.update_item('gateways', self.owner, gateway_dict)

                    self.logger.debug("(LUN.allocate) registered '{}' with wwn '{}' with the"
                                      " config object".format(self.image, wwn))
                    self.logger.info("(LUN.allocate) added '{}/{}' to LIO and config object".format(self.pool,
                                                                                                    self.image))

                else:
                    # config object already had wwn for this rbd image
                    lun = self.add_dev_to_lio(wwn)
                    if self.error:
                        return
                    self.logger.debug("(LUN.allocate) registered '{}' to LIO with wwn '{}' from "
                                      "the config object".format(self.image, wwn))

                self.num_changes += 1

            else:
                # lun is not already in LIO, but this is not the owning node that defines the wwn
                # we need the wwn from the config (placed by the allocating host), so we wait!
                waiting = 0
                while waiting < settings.config.time_out:
                    self.config.refresh()
                    if self.config_key in self.config.config['disks']:
                        if 'wwn' in self.config.config['disks'][self.config_key]:
                            if self.config.config['disks'][self.config_key]['wwn']:
                                wwn = self.config.config['disks'][self.config_key]['wwn']
                                break
                    sleep(settings.config.loop_delay)
                    waiting += settings.config.loop_delay
                    self.logger.debug("(LUN.allocate) waiting for config object to show {}"
                                      " with it's wwn".format(self.image))

                if waiting >= settings.config.time_out:
                    self.error = True
                    self.error_msg = ("(LUN.allocate) waited too long for the wwn information "
                                      "on image {} to arrive".format(self.image))
                    return

                # At this point we have a wwn from the config for this rbd image, so just add to LIO
                lun = self.add_dev_to_lio(wwn)
                if self.error:
                    return

                self.logger.info("(LUN.allocate) added {} to LIO using wwn '{}'"
                                 " defined by {}".format(self.image,
                                                         wwn,
                                                         self.allocating_host))

                self.num_changes += 1

        self.logger.debug("config meta data for this disk is {}".format(self.config.config['disks'][self.config_key]))

        # the owning host for an image is the only host that commits to the config
        if this_host == self.allocating_host and self.config.changed:

            self.logger.debug("(LUN.allocate) Committing change(s) to the config object in pool {}".format(self.pool))
            self.config.commit()
            self.error = self.config.error
            self.error_msg = self.config.error_msg

    def dm_get_device(self, map_device):
        """
        set the dm_device attribute based on the rbd map device entry
        :param map_device: /dev/rbdX
        :return: None
        """

        self.dm_device = LUN.dm_device_name_from_rbd_map(map_device)
        if self.dm_device is None:
            return

        if not LUN.dm_wait_for_device(self.dm_device):
            self.dm_device = None

    def dm_size_ok(self, rbd_object):
        """
        Check that the dm device matches the request. if the size request is lower than
        current size, just return since resizing down is not support and problematic
        for client filesystems anyway
        :return boolean indicating whether the size matches
        """

        target_bytes = convert_2_bytes(self.size)
        if rbd_object.size_bytes > target_bytes:
            return True

        tmr = 0
        size_ok = False
        rbd_size_ok = False
        dm_path_found = False

        # we have to wait for the rbd size to match, since the rbd could have been
        # resized on another gateway host when this is called from Ansible
        while tmr < settings.config.time_out:
            if rbd_object.size_bytes == target_bytes:
                rbd_size_ok = True
                break
            sleep(settings.config.loop_delay)
            tmr += settings.config.loop_delay

        # since the size matches underneath device mapper, now we ensure the size
        # matches with device mapper - if not issue a resize map request
        if rbd_size_ok:

            # find the dm-X device
            dm_devices = glob.glob('/sys/class/block/dm-*/')
            # convert the full dm_device path to just the name (last component of path
            dm_name = os.path.basename(self.dm_device)

            for dm_dev in dm_devices:
                if fread(os.path.join(dm_dev, 'dm/name')) == dm_name:
                    dm_path_found = True
                    break

            if dm_path_found:

                # size is in sectors, so read it and * 512 = bytes
                dm_size_bytes = int(fread(os.path.join(dm_dev, 'size')))*512
                if dm_size_bytes != target_bytes:

                    self.logger.info("Issuing a resize map for {}".format(dm_name))
                    response = shellcommand('multipathd resize map {}'.format(dm_name))

                    self.logger.debug("resize result : {}".format(response))
                    dm_size_bytes = int(fread(os.path.join(dm_dev, 'size')))*512

                    if response.lower().startswith('ok') and dm_size_bytes == target_bytes:
                        size_ok = True
                    else:
                        self.logger.critical("multipathd resize map for {} failed".format(dm_name))
                else:
                    # size matches
                    size_ok = True
            else:
                self.logger.critical("Unable to locate a dm-X device for this rbd image - {}".format(self.image))

        return size_ok

    def lun_in_lio(self):
        found_it = False
        rtsroot = root.RTSRoot()
        for stg_object in rtsroot.storage_objects:

            # First match on name, but then check the pool incase the same name exists in multiple pools
            if stg_object.name == self.config_key:

                found_it = True
                break

        return stg_object if found_it else None

    def add_dev_to_lio(self, in_wwn=None):
        """
        Add an rbd device to the LIO configuration
        :param in_wwn: optional wwn identifying the rbd image to clients - must match across gateways
        :return: LIO LUN object
        """

        self.logger.info("(LUN.add_dev_to_lio) Adding image '{}' with path {} to LIO".format(self.image,
                                                                                             self.dm_device))
        new_lun = None
        try:
            new_lun = BlockStorageObject(name=self.config_key, dev=self.dm_device, wwn=in_wwn)
        except RTSLibError as err:
            self.error = True
            self.error_msg = "failed to add {} to LIO - error({})".format(self.image, str(err))

        return new_lun

    def remove_dev_from_lio(self):
        lio_root = root.RTSRoot()

        # remove the device from all tpgs
        for t in lio_root.tpgs:
            for lun in t.luns:
                if lun.storage_object.name == self.config_key:
                    try:
                        lun.delete()
                    except RTSLibError as e:
                        self.error = True
                        self.error_msg = "Delete from LIO/TPG failed - {}".format(e)
                        return
                    else:
                        break       # continue to the next tpg

        for stg_object in lio_root.storage_objects:
            if stg_object.name == self.config_key:

                alua_dir = os.path.join(stg_object.path, "alua")

                # remove the alua directories (future versions will handle this
                # natively within rtslib_fb
                for dirname in next(os.walk(alua_dir))[1]:
                    if dirname != "default_tg_pt_gp":
                        try:
                            alua_tpg = ALUATargetPortGroup(stg_object, dirname)
                            alua_tpg.delete()
                        except (RTSLibError, RTSLibNotInCFS) as err:
                            self.error = True
                            self.error_msg = "Delete of ALUA directories failed - {}".format(err)
                            return

                try:
                    stg_object.delete()
                except RTSLibError as e:
                    self.error = True
                    self.error_msg = "Delete from LIO/backstores failed - {}".format(e)
                    return

                break

    @staticmethod
    def set_owner(gateways):
        """
        Determine the gateway in the configuration with the lowest number of active LUNs. This
        gateway is then selected as the owner for the primary path of the current LUN being
        processed
        :param gateways: gateway dict returned from the RADOS configuration object
        :return: specific gateway hostname (str) that should provide the active path for the next LUN
        """

        # Gateways contains simple attributes and dicts. The dicts define the gateways settings, so
        # first we extract only the dicts within the main gateways dict
        gw_nodes = {key: gateways[key] for key in gateways if isinstance(gateways[key], dict)}
        gw_items = gw_nodes.items()

        # first entry is the lowest number of active_luns
        gw_items.sort(key=lambda x: (x[1]['active_luns']))

        # 1st tuple is gw with lowest active_luns, so return the 1st
        # element which is the hostname
        return gw_items[0][0]

    @staticmethod
    def dm_device_name_from_rbd_map(map_device):
        """
        take a mapped device name /dev/rbdX to determine the /dev/mapper/X
        equivalent by reading the devices attribute files in sysfs
        :param map_device: device path of the form /dev/rbdX
        :return: device mapper name for the rbd device /dev/mapper/<pool>-<image-id>
        """

        rbd_bus_id = map_device[8:]
        dm_uid = None

        # TODO - could fread encounter an IOerror?
        rbd_path = os.path.join('/sys/bus/rbd/devices', rbd_bus_id)
        if os.path.exists(rbd_path):
            pool_id = fread(os.path.join(rbd_path, "pool_id"))
            image_id = fread(os.path.join(rbd_path, "image_id"))
            current_snap = fread(os.path.join(rbd_path, "current_snap"))

            dm_uid = "/dev/mapper/{}-{}".format(pool_id, image_id)
            if current_snap != "-":
                dm_uid += "-{}".format(fread(os.path.join(rbd_path, "snap_id")))

        return dm_uid

    @staticmethod
    def dm_wait_for_device(dm_device):
        """
        multipath may take a few seconds for the device to appear, so we
        need to wait until we see it - but use a timeout to abort if necessary
        :param dm_device: dm device name /dev/mapper/<pool>-<image_id>
        :return boolean representing when the device has been found
        """

        waiting = 0

        # wait for multipathd and udev to setup /dev node
        # /dev/mapper/<pool_id>-<rbd_image_id>
        # e.g. /dev/mapper/0-519d42ae8944a
        while os.path.exists(dm_device) is False:
            sleep(settings.config.loop_delay)
            waiting += settings.config.loop_delay
            if waiting >= settings.config.time_out:
                break

        return os.path.exists(dm_device)



def rados_pool(conf=None, pool='rbd'):
    """
    determine if a given pool name is defined within the ceph cluster
    :param pool: pool name to check for (str)
    :return: Boolean representing the pool's existence
    """

    if conf is None:
        conf = settings.config.cephconf


    with rados.Rados(conffile=conf) as cluster:
        pool_list = cluster.list_pools()

    return pool in pool_list

