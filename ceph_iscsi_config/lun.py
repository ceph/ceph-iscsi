#!/usr/bin/env python
__author__ = 'paul'

from ceph_iscsi_config.common import Config
from ceph_iscsi_config.utils import convert_2_bytes, shellcommand, Defaults, get_pool_id

from rtslib_fb import BlockStorageObject, root
from rtslib_fb.utils import RTSLibError, fwrite, fread

import rados
import rbd
import json
import os

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
        self.device_map = None
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

        with rados.Rados(conffile=Defaults.ceph_conf) as cluster:
            with cluster.open_ioctx(self.pool) as ioctx:
                rbd_inst = rbd.RBD()
                try:
                    rbd_inst.create(ioctx, self.image, size_bytes, features=feature_int, old_format=False)
                except (rbd.ImageExists, rbd.InvalidArgument) as err:
                    self.error = True
                    self.error_msg = "Failed to create rbd image {} in pool {} : {}".format(self.image,
                                                                                            self.pool,
                                                                                            err)

    def rbd_size(self):
        """
        Confirm that the existing rbd image size, matches the requirement passed in the ansible
        config file - if the required size is > than current, resize the rbd image to match
        :return: boolean value reflecting whether the rbd image was resized
        """

        with rados.Rados(conffile=Defaults.ceph_conf) as cluster:
            with cluster.open_ioctx(self.pool) as ioctx:
                with rbd.Image(ioctx, self.image) as rbd_image:

                    # logger.debug('rbd image {} opened OK'.format(image))

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
                            pass
                            # Once an image is resized we need to tell multipathd, so
                            # the size is correct within LIO (targetcli)
                            dm_path = LUN.dm_device_name_from_rbd_map(self.device_map)
                            dm_device = dm_path[12:]
                            response = shellcommand('multipathd resize map {}'.format(dm_device))
                            if response.lower().startswith('ok'):
                                self.changed = True
                            else:
                                self.error = True
                                self.error_msg = "multipathd update failed on {} for {}".format(self.dm_device,
                                                                                                self.image)

    def rbdmap_entry(self):
        """
        check the given image has an entry in /etc/ceph/rbdmap - if not add it!
        :return: boolean indicating whether the rbdmap file was updated
        """

        # Assume it's not there, so if we find it flip this to False
        entry_needed = True

        srch_str = "{}/{}".format(self.pool, self.image)
        with open(Defaults.rbd_map_file, 'a+') as rbdmap:

            for entry in rbdmap:
                if entry.startswith(srch_str):
                    # found it - get out,
                    entry_needed = False
                    break

            if entry_needed:
                # need to add an entry to the rbdmap file
                rbdmap.write("{}\t\tid={},keyring={},options=noshare\n".format(srch_str,
                                                                               Defaults.ceph_user,
                                                                               Defaults.keyring))

        return entry_needed

    def get_rbd_map(self):

        # Now look at mapping of the device - which would execute on all target hosts
        showmap_cmd = 'rbd showmapped --format=json'
        response = shellcommand(showmap_cmd)
        if not response:                        # showmapped command must have failed
            self.device_map = None
            return

        # Check the showmapped output for this rbd image, and if so set the mapped device name
        mapped_rbds = json.loads(response)
        for rbd_id in mapped_rbds:
            if (mapped_rbds[rbd_id]['name'] == self.image and
                    mapped_rbds[rbd_id]['pool'] == self.pool):
                self.device_map = mapped_rbds[rbd_id]['device'].rstrip()
                return

        # At this point the rbd image is not in showmap output, so map it
        self.map_needed = True
        # lock_on_read was not merged until RHCS 2.1. We temporarily
        # support it on/off to make the transition during devel easier
        map_cmd = 'rbd map -o noshare,lock_on_read {}/{}'.format(self.pool, self.image)
        response = shellcommand(map_cmd)
        if response is None:
            map_cmd = 'rbd map -o noshare {}/{}'.format(self.pool, self.image)
            response = shellcommand(map_cmd)

        if response:
            self.device_map = response.rstrip()

    @staticmethod
    def rbd_list(conf=Defaults.ceph_conf, pool='rbd'):
        """
        return a list of rbd images in a given pool
        :param pool: pool name to look at to return a list of rbd image names for (str)
        :return: list of rbd image names (list)
        """

        with rados.Rados(conffile=conf) as cluster:
            with cluster.open_ioctx(pool) as ioctx:
                rbd_inst = rbd.RBD()
                rbd_names = rbd_inst.list(ioctx)
        return rbd_names


class LUN(object):

    def __init__(self, logger, pool, image, size, allocating_host):
        self.logger = logger
        self.image = image
        self.pool = pool
        self.pool_id = 0
        self.size = size
        self.config_key = '{}/{}'.format(self.pool, self.image)

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
                    self.logger.info("(LUN.allocate) created {}/{} successfully".format(self.image, self.pool))
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
                    sleep(Defaults.loop_delay)
                    disk_list = RBDDev.rbd_list(pool=self.pool)
                    waiting += Defaults.loop_delay
                    if waiting >= Defaults.time_out:
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
                self.logger.critical("Unable to resize {}".format(self.image))
                self.error = True
                self.error_msg = "Unable to resize {}".format(self.image)
                return

            # resize either worked or was not required, so let's log accordingly
            if rbd_image.changed:
                self.logger.debug("rbd image {} resized to {}".format(self.image, self.size))
                self.num_changes += 1
            else:
                self.logger.debug("rbd image {} size matches the configuration file request".format(self.image))

        self.logger.debug("Begin processing LIO mapping requirement")

        # for LIO mapping purposes, we use the device mapper device not the raw /dev/rbdX device
        # Using the dm device ensures that any connectivity issue doesn't result in stale device
        # structures in the kernel, since device-mapper will tidy those up
        self.dm_get_device(rbd_image.device_map)
        if self.dm_device is None:
            self.logger.critical("Could not find dm multipath device for {}. Make sure the multipathd"
                                 " service is enabled, and confirm entry is in /dev/mapper/".format(self.image))
            self.error = True
            self.error_msg = "Could not find dm multipath device for {}".format(self.image)
            return

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
                while waiting < Defaults.time_out:
                    self.config.refresh()
                    if self.config_key in self.config.config['disks']:
                        if 'wwn' in self.config.config['disks'][self.config_key]:
                            if self.config.config['disks'][self.config_key]['wwn']:
                                wwn = self.config.config['disks'][self.config_key]['wwn']
                                break
                    sleep(Defaults.loop_delay)
                    waiting += Defaults.loop_delay
                    self.logger.debug("(LUN.allocate) waiting for config object to show {}"
                                      " with it's wwn".format(self.image))

                if waiting >= Defaults.time_out:
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
        self.dm_device = LUN.dm_device_name_from_rbd_map(map_device)
        if self.dm_device is None:
            return

        if not LUN.dm_wait_for_device(self.dm_device):
            self.dm_device = None

    def lun_in_lio(self):
        found_it = False
        rtsroot = root.RTSRoot()
        for stg_object in rtsroot.storage_objects:

            # First match on name, but then check the pool incase the same name exists in multiple pools
            if stg_object.name == self.image:

                # udev_path shows something like '/dev/mapper/0-8fd91515f007c' - the first component is the
                # pool id
                pool_id = int(os.path.basename(stg_object.udev_path).split('-')[0])
                if pool_id == self.pool_id:
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
            new_lun = BlockStorageObject(name=self.image, dev=self.dm_device, wwn=in_wwn)
        except RTSLibError as err:
            self.error = True
            self.error_msg = "failed to add {} to LIO - error({})".format(self.image, str(err))

        return new_lun

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
        waiting = 0

        # wait for multipathd and udev to setup /dev node
        # /dev/mapper/<pool_id>-<rbd_image_id>
        # e.g. /dev/mapper/0-519d42ae8944a
        while os.path.exists(dm_device) is False:
            sleep(Defaults.loop_delay)
            waiting += Defaults.loop_delay
            if waiting >= Defaults.time_out:
                break

        return os.path.exists(dm_device)



def rados_pool(conf=Defaults.ceph_conf, pool='rbd'):
    """
    determine if a given pool name is defined within the ceph cluster
    :param pool: pool name to check for (str)
    :return: Boolean representing the pool's existence
    """

    with rados.Rados(conffile=conf) as cluster:
        pool_list = cluster.list_pools()

    return pool in pool_list

