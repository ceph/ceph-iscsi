#!/usr/bin/env python

import rados
import rbd
import re

from time import sleep
from socket import gethostname

from rtslib_fb import UserBackedStorageObject, root
from rtslib_fb.utils import RTSLibError

import ceph_iscsi_config.settings as settings

from ceph_iscsi_config.utils import (convert_2_bytes, gen_control_string,
                                     valid_size, get_pool_id, ip_addresses,
                                     get_pools, get_rbd_size, this_host,
                                     human_size, CephiSCSIError)
from ceph_iscsi_config.gateway_object import GWObject
from ceph_iscsi_config.gateway import GWTarget
from ceph_iscsi_config.client import GWClient, CHAP
from ceph_iscsi_config.group import Group

__author__ = 'pcuzner@redhat.com'


class RBDDev(object):

    rbd_feature_list = ['RBD_FEATURE_LAYERING', 'RBD_FEATURE_EXCLUSIVE_LOCK',
                        'RBD_FEATURE_OBJECT_MAP', 'RBD_FEATURE_FAST_DIFF',
                        'RBD_FEATURE_DEEP_FLATTEN']

    def __init__(self, image, size, pool='rbd'):
        self.image = image
        self.size_bytes = convert_2_bytes(size)
        self.pool = pool
        self.pool_id = get_pool_id(pool_name=self.pool)
        self.error = False
        self.error_msg = ''
        self.changed = False

    def create(self):
        """
        Create an rbd image compatible with exporting through LIO to multiple
        clients
        :return: status code and msg
        """

        with rados.Rados(conffile=settings.config.cephconf) as cluster:
            with cluster.open_ioctx(self.pool) as ioctx:
                rbd_inst = rbd.RBD()
                try:
                    rbd_inst.create(ioctx,
                                    self.image,
                                    self.size_bytes,
                                    features=RBDDev.supported_features(),
                                    old_format=False)

                except (rbd.ImageExists, rbd.InvalidArgument) as err:
                    self.error = True
                    self.error_msg = ("Failed to create rbd image {} in "
                                      "pool {} : {}".format(self.image,
                                                            self.pool,
                                                            err))

    def delete(self):
        """
        Delete the current rbd image
        :return: nothing, but the objects error attribute is set if there
        are problems
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
        Confirm that the existing rbd image size, matches the requirement
        passed in the request - if the required size is > than
        current, resize the rbd image to match
        :return: boolean value reflecting whether the rbd image was resized
        """

        with rados.Rados(conffile=settings.config.cephconf) as cluster:
            with cluster.open_ioctx(self.pool) as ioctx:
                with rbd.Image(ioctx, self.image) as rbd_image:

                    # get the current size in bytes
                    current_bytes = rbd_image.size()

                    if self.size_bytes > current_bytes:

                        # resize method, doesn't document potential exceptions
                        # so using a generic catch all (Yuk!)
                        try:
                            rbd_image.resize(self.size_bytes)
                        except Exception:
                            self.error = True
                            self.error_msg = ("rbd image resize failed for "
                                              "{}".format(self.image))
                        else:
                            self.changed = True

    def _get_size_bytes(self):
        """
        Return the current size of the rbd image
        :return: (int) rbd image size in bytes
        """

        with rados.Rados(conffile=settings.config.cephconf) as cluster:
            with cluster.open_ioctx(self.pool) as ioctx:
                with rbd.Image(ioctx, self.image) as rbd_image:
                    image_size = rbd_image.size()

        return image_size

    @staticmethod
    def rbd_list(conf=None, pool='rbd'):
        """
        return a list of rbd images in a given pool
        :param pool: pool name (str) to return a list of rbd image names for
        :return: list of rbd image names (list)
        """

        if conf is None:
            conf = settings.config.cephconf

        with rados.Rados(conffile=conf) as cluster:
            with cluster.open_ioctx(pool) as ioctx:
                rbd_inst = rbd.RBD()
                rbd_names = rbd_inst.list(ioctx)
        return rbd_names

    @staticmethod
    def rbd_lock_cleanup(logger, local_ips, rbd_image):
        """
        cleanup locks left if this node crashed and was not able to release them
        :param logger: logger object to print to
        :param local_ips: list of local ip addresses.
        :rbd_image: rbd image to clean up locking for
        :raise CephiSCSIError.
        """

        lock_info = rbd_image.list_lockers()
        if not lock_info:
            return

        lockers = lock_info.get("lockers")
        for holder in lockers:
            for ip in local_ips:
                if ip in holder[2]:
                    logger.info("Cleaning up stale local lock for {} {}".format(
                                holder[0], holder[1]))
                    try:
                        rbd_image.break_lock(holder[0], holder[1])
                    except Exception as err:
                        raise CephiSCSIError("Could not break lock for {}. "
                                             "Error {}".format(rbd_image, err))

    def _valid_rbd(self):

        valid_state = True
        with rados.Rados(conffile=settings.config.cephconf) as cluster:
            ioctx = cluster.open_ioctx(self.pool)
            with rbd.Image(ioctx, self.image) as rbd_image:

                if rbd_image.features() & RBDDev.required_features() != \
                        RBDDev.required_features():
                        valid_state = False

        return valid_state

    @classmethod
    def supported_features(cls):
        """
        Return an int representing the supported features for LIO export
        :return: int
        """
        # build the required feature settings into an int
        feature_int = 0
        for feature in RBDDev.rbd_feature_list:
            feature_int += getattr(rbd, feature)

        return feature_int

    @classmethod
    def required_features(cls):
        """
        Return an int representing the required features for LIO export
        :return: int
        """
        return rbd.RBD_FEATURE_EXCLUSIVE_LOCK

    current_size = property(_get_size_bytes,
                            doc="return the current size of the rbd(bytes)")

    valid = property(_valid_rbd,
                     doc="check the rbd is valid for export through LIO"
                         " (boolean)")


class LUN(GWObject):
    SETTINGS = [
        "max_data_area_mb",
        "qfull_timeout",
        "osd_op_timeout",
        "hw_max_sectors"]

    def __init__(self, logger, pool, image, size, allocating_host):
        self.logger = logger
        self.image = image
        self.pool = pool
        self.pool_id = 0
        self.size_bytes = convert_2_bytes(size)
        self.config_key = '{}.{}'.format(self.pool, self.image)

        # the allocating host could be fqdn or shortname - but the config
        # only uses shortname so it needs to be converted to shortname format
        self.allocating_host = allocating_host.split('.')[0]

        self.owner = ''     # gateway that owns the preferred path for this LUN
        self.error = False
        self.error_msg = ''
        self.num_changes = 0

        try:
            super(LUN, self).__init__('disks', self.config_key, logger,
                                      LUN.SETTINGS)
        except CephiSCSIError as err:
            self.error = True
            self.error_msg = err

        self._validate_request()

    def _validate_request(self):

        # Before we start make sure that the target host is actually
        # defined to the config
        if self.allocating_host not in self.config.config['gateways'].keys():
            self.logger.critical("Owning host is not valid, please provide a "
                                 "valid gateway name for this rbd image")
            self.error = True
            self.error_msg = ("host name given for {} is not a valid gateway"
                              " name, listed in the config".format(self.image))

        elif not rados_pool(pool=self.pool):
            # Could create the pool, but a fat finger moment in the config
            # file would mean rbd images get created and mapped, and then need
            # correcting. Better to exit if the pool doesn't exist
            self.error = True
            self.error_msg = ("Pool '{}' does not exist. Unable to "
                              "continue".format(self.pool))

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
            self.error_msg = ("Unable to delete {} - allocated to "
                              "{}".format(self.config_key,
                                          iqn))

            self.logger.warning(self.error_msg)
            return

        # Check that the LUN is in LIO - if not there is nothing to do for
        # this request
        lun = self.lio_stg_object()
        if not lun:
            return

        # Now we know the request is for a LUN in LIO, and it's not masked
        # to a client
        self.remove_dev_from_lio()
        if self.error:
            return

        rbd_image = RBDDev(self.image, '0G', self.pool)

        if this_host == self.allocating_host:
            # by using the allocating host we ensure the delete is not
            # issue by several hosts when initiated through ansible
            rbd_image.delete()
            if rbd_image.error:
                self.error = True
                self.error_msg = ("Unable to delete the underlying rbd "
                                  "image {}".format(self.config_key))
                return

            # determine which host was the path owner
            disk_owner = self.config.config['disks'][self.config_key]['owner']

            #
            # remove the definition from the config object
            self.config.del_item('disks', self.config_key)

            # update the active_luns count for gateway that owned this
            # lun
            gw_metadata = self.config.config['gateways'][disk_owner]
            if gw_metadata['active_luns'] > 0:
                gw_metadata['active_luns'] -= 1

                self.config.update_item('gateways',
                                        disk_owner,
                                        gw_metadata)

            self.config.commit()

    def manage(self, desired_state):

        self.logger.debug("LUN.manage request for {}, desired state "
                          "{}".format(self.image, desired_state))

        if desired_state == 'present':

            self.allocate()

        elif desired_state == 'absent':

            self.remove_lun()

    def deactivate(self):
        so = self.lio_stg_object()
        if not so:
            # Could be due to a restart after failure. Just log and ignore.
            self.logger.warning("LUN {} already deactivated".format(self.image))
            return

        for alun in so.attached_luns:
            for mlun in alun.mapped_luns:
                node_acl = mlun.parent_nodeacl

                if node_acl.session and \
                        node_acl.session.get('state', '').upper() == 'LOGGED_IN':
                    raise CephiSCSIError("LUN {} in-use".format(self.image))

        self.remove_dev_from_lio()
        if self.error:
            raise CephiSCSIError("LUN deactivate failure - {}".format(self.error_msg))

    def activate(self):
        disk = self.config.config['disks'].get(self.config_key, None)
        if not disk:
            raise CephiSCSIError("Image {} not found.".format(self.image))

        wwn = disk.get('wwn', None)
        if not wwn:
            raise CephiSCSIError("LUN {} missing wwn".format(self.image))

        # re-add backend storage object
        so = self.lio_stg_object()
        if not so:
            self.add_dev_to_lio(wwn)
            if self.error:
                raise CephiSCSIError("LUN activate failure - {}".format(self.error_msg))

        # re-add LUN to target
        iqn = self.config.config['gateways']['iqn']
        ip_list = self.config.config['gateways']['ip_list']

        # Add the mapping for the lun to ensure the block device is
        # present on all TPG's
        gateway = GWTarget(self.logger, iqn, ip_list)

        gateway.manage('map')
        if gateway.error:
            raise CephiSCSIError("LUN mapping failed - {}".format(gateway.error_msg))

        # re-map LUN to hosts
        client_err = ''
        for client_iqn in self.config.config['clients']:
            client_metadata = self.config.config['clients'][client_iqn]
            if client_metadata.get('group_name', ''):
                continue

            image_list = client_metadata['luns'].keys()
            if self.config_key not in image_list:
                continue

            client_chap = CHAP(client_metadata['auth']['chap'])
            chap_str = client_chap.chap_str
            if client_chap.error:
                raise CephiSCSIError("Password decode issue : "
                                     "{}".format(client_chap.error_msg))

            client = GWClient(self.logger, client_iqn, image_list, chap_str)
            client.manage('present')
            if client.error:
                client_err = "LUN mapping failed {} - {}".format(client_iqn,
                                                                 client.error_msg)

        # re-map LUN to host groups
        for group_name in self.config.config['groups']:
            host_group = self.config.config['groups'][group_name]
            members = host_group.get('members')
            disks = host_group.get('disks').keys()
            if self.config_key not in disks:
                continue

            group = Group(self.logger, group_name, members, disks)
            group.apply()
            if group.error:
                client_err = "LUN mapping failed {} - {}".format(group_name,
                                                                 group.error_msg)

        if client_err:
            raise CephiSCSIError(client_err)

    def allocate(self):
        self.logger.debug("LUN.allocate starting, listing rbd devices")
        disk_list = RBDDev.rbd_list(pool=self.pool)
        self.logger.debug("rados pool '{}' contains the following - "
                          "{}".format(self.pool, disk_list))

        this_host = gethostname().split('.')[0]
        self.logger.debug("Hostname Check - this host is {}, target host for "
                          "allocations is {}".format(this_host,
                                                     self.allocating_host))

        rbd_image = RBDDev(self.image, self.size_bytes, self.pool)
        self.pool_id = rbd_image.pool_id

        # if the image required isn't defined, create it!
        if self.image not in disk_list:
            # create the requested disk if this is the 'owning' host
            if this_host == self.allocating_host:

                rbd_image.create()

                if not rbd_image.error:
                    self.config.add_item('disks', self.config_key)
                    self.logger.info("(LUN.allocate) created {}/{} "
                                     "successfully".format(self.pool,
                                                           self.image))
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
                        self.error_msg = ("(LUN.allocate) timed out waiting "
                                          "for rbd to show up")
                        return
        else:
            # requested image is already defined to ceph

            if rbd_image.valid:
                # rbd image is OK to use, so ensure it's in the config
                # object
                if self.config_key not in self.config.config['disks']:
                    self.config.add_item('disks', self.config_key)

            else:
                # rbd image is not valid for export, so abort
                self.error = True
                self.error_msg = ("(LUN.allocate) rbd '{}' is not compatible "
                                  "with LIO\nOnly image features {} are"
                                  " supported".format(self.image,
                                                      ','.join(RBDDev.rbd_feature_list)))
                self.logger.error(self.error_msg)
                return

        self.logger.debug("Check the rbd image size matches the request")

        # if updates_made is not set, the disk pre-exists so on the owning
        # host see if it needs to be resized
        if self.num_changes == 0 and this_host == self.allocating_host:

            # check the size, and update if needed
            rbd_image.rbd_size()
            if rbd_image.error:
                self.logger.critical(rbd_image.error_msg)
                self.error = True
                self.error_msg = rbd_image.error_msg
                return

            if rbd_image.changed:
                self.logger.info("rbd image {} resized "
                                 "to {}".format(self.config_key,
                                                self.size_bytes))
                self.num_changes += 1
            else:
                self.logger.debug("rbd image {} size matches the configuration"
                                  " file request".format(self.config_key))

        self.logger.debug("Begin processing LIO mapping")

        # now see if we need to add this rbd image to LIO
        so = self.lio_stg_object()
        if not so:

            # this image has not been defined to this hosts LIO, so check the
            # config for the details and if it's  missing define the
            # wwn/alua_state and update the config
            if this_host == self.allocating_host:
                # first check to see if the device needs adding
                try:
                    wwn = self.config.config['disks'][self.config_key]['wwn']
                except KeyError:
                    wwn = ''

                if wwn == '':
                    # disk hasn't been defined to LIO yet, it' not been defined
                    # to the config yet and this is the allocating host
                    lun = self.add_dev_to_lio()
                    if self.error:
                        return

                    # lun is now in LIO, time for some housekeeping :P
                    wwn = lun._get_wwn()
                    self.owner = LUN.set_owner(self.config.config['gateways'])
                    self.logger.debug("{} owner will be {}".format(self.image,
                                                                   self.owner))

                    disk_attr = {"wwn": wwn,
                                 "image": self.image,
                                 "owner": self.owner,
                                 "pool": self.pool,
                                 "pool_id": rbd_image.pool_id,
                                 "controls": self.controls}

                    self.config.update_item('disks',
                                            self.config_key,
                                            disk_attr)

                    gateway_dict = self.config.config['gateways'][self.owner]
                    gateway_dict['active_luns'] += 1

                    self.config.update_item('gateways',
                                            self.owner,
                                            gateway_dict)

                    self.logger.debug("(LUN.allocate) registered '{}' with "
                                      "wwn '{}' with the config "
                                      "object".format(self.image,
                                                      wwn))
                    self.logger.info("(LUN.allocate) added '{}/{}' to LIO and"
                                     " config object".format(self.pool,
                                                             self.image))

                else:
                    # config object already had wwn for this rbd image
                    self.add_dev_to_lio(wwn)
                    if self.error:
                        return

                    self.commit_controls()
                    self.logger.debug("(LUN.allocate) registered '{}' to LIO "
                                      "with wwn '{}' from the config "
                                      "object".format(self.image,
                                                      wwn))

                self.num_changes += 1

            else:
                # lun is not already in LIO, but this is not the owning node
                # that defines the wwn we need the wwn from the config
                # (placed by the allocating host), so we wait!
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
                    self.logger.debug("(LUN.allocate) waiting for config object"
                                      " to show {} with it's wwn".format(self.image))

                if waiting >= settings.config.time_out:
                    self.error = True
                    self.error_msg = ("(LUN.allocate) waited too long for the "
                                      "wwn information on image {} to "
                                      "arrive".format(self.image))
                    return

                # At this point we have a wwn from the config for this rbd
                # image, so just add to LIO
                self.add_dev_to_lio(wwn)
                if self.error:
                    return

                self.logger.info("(LUN.allocate) added {} to LIO using wwn "
                                 "'{}' defined by {}".format(self.image,
                                                             wwn,
                                                             self.allocating_host))

                self.num_changes += 1

        else:
            # lun exists in LIO, check the size is correct
            if not self.lio_size_ok(rbd_image, so):
                self.error = True
                self.error_msg = "Unable to sync the rbd device size with LIO"
                self.logger.critical(self.error_msg)
                return

        self.logger.debug("config meta data for this disk is "
                          "{}".format(self.config.config['disks'][self.config_key]))

        # the owning host for an image is the only host that commits to the
        # config
        if this_host == self.allocating_host and self.config.changed:

            self.logger.debug("(LUN.allocate) Committing change(s) to the "
                              "config object in pool {}".format(self.pool))
            self.config.commit()
            self.error = self.config.error
            self.error_msg = self.config.error_msg

    def lio_size_ok(self, rbd_object, stg_object):
        """
        Check that the SO in LIO matches the current size of the rbd. if the
        size requested < current size, just return. Downsizing an rbd is not
        supported by this code and problematic for client filesystems anyway!
        :return boolean indicating whether the size matches
        """

        tmr = 0
        size_ok = False
        rbd_size_ok = False
        # dm_path_found = False

        # We have to wait for the rbd size to match, since the rbd could have
        # been resized on another gateway host
        while tmr < settings.config.time_out:
            if self.size_bytes <= rbd_object.current_size:
                rbd_size_ok = True
                break
            sleep(settings.config.loop_delay)
            tmr += settings.config.loop_delay

        # we have the right size for the rbd - check that LIO dev size matches
        if rbd_size_ok:

            # If the LIO size is not right, poke it with the new value
            if stg_object.size < self.size_bytes:
                self.logger.info("Resizing {} in LIO "
                                 "to {}".format(self.config_key,
                                                self.size_bytes))

                stg_object.set_attribute("dev_size", self.size_bytes)

                size_ok = stg_object.size == self.size_bytes

            else:
                size_ok = True

        return size_ok

    def lio_stg_object(self):
        found_it = False
        rtsroot = root.RTSRoot()
        for stg_object in rtsroot.storage_objects:

            # First match on name, but then check the pool incase the same
            # name exists in multiple pools
            if stg_object.name == self.config_key:

                found_it = True
                break

        return stg_object if found_it else None

    def add_dev_to_lio(self, in_wwn=None):
        """
        Add an rbd device to the LIO configuration
        :param in_wwn: optional wwn identifying the rbd image to clients
        (must match across gateways)
        :return: LIO LUN object
        """
        self.logger.info("(LUN.add_dev_to_lio) Adding image "
                         "'{}' to LIO".format(self.config_key))

        # extract control parameter overrides (if any) or use default
        controls = {}
        for k in ['max_data_area_mb', 'hw_max_sectors']:
            controls[k] = getattr(self, k)

        control_string = gen_control_string(controls)
        if control_string:
            self.logger.debug("control=\"{}\"".format(control_string))

        new_lun = None
        try:
            # config string = rbd identifier / config_key (pool/image) /
            # optional osd timeout
            cfgstring = "rbd/{}/{};osd_op_timeout={}".format(self.pool,
                                                             self.image,
                                                             self.osd_op_timeout)
            if (settings.config.cephconf != '/etc/ceph/ceph.conf'):
                cfgstring += ";conf={}".format(settings.config.cephconf)

            new_lun = UserBackedStorageObject(name=self.config_key,
                                              config=cfgstring,
                                              size=self.size_bytes,
                                              wwn=in_wwn, control=control_string)
        except (RTSLibError, IOError) as err:
            self.error = True
            self.error_msg = ("failed to add {} to LIO - "
                              "error({})".format(self.config_key,
                                                 str(err)))
            self.logger.error(self.error_msg)
            return None

        try:
            new_lun.set_attribute("cmd_time_out", 0)
            new_lun.set_attribute("qfull_time_out", self.qfull_timeout)
        except RTSLibError as err:
            self.error = True
            self.error_msg = ("Could not set LIO device attribute "
                              "cmd_time_out/qfull_time_out for device: {}. "
                              "Kernel not supported. - "
                              "error({})".format(self.config_key, str(err)))
            self.logger.error(self.error_msg)
            new_lun.delete()
            return None

        self.logger.info("(LUN.add_dev_to_lio) Successfully added {}"
                         " to LIO".format(self.config_key))

        return new_lun

    def remove_dev_from_lio(self):
        lio_root = root.RTSRoot()

        # remove the device from all tpgs
        for t in lio_root.tpgs:
            for lun in t.luns:
                if lun.storage_object.name == self.config_key:
                    try:
                        lun.delete()
                    except Exception as e:
                        self.error = True
                        self.error_msg = ("Delete from LIO/TPG failed - "
                                          "{}".format(e))
                        return
                    else:
                        break       # continue to the next tpg

        for stg_object in lio_root.storage_objects:
            if stg_object.name == self.config_key:
                try:
                    stg_object.delete()
                except Exception as e:
                    self.error = True
                    self.error_msg = ("Delete from LIO/backstores failed - "
                                      "{}".format(e))
                    return

                break

    @staticmethod
    def valid_disk(ceph_iscsi_config, logger, **kwargs):
        """
        determine whether the given image info is valid for a disk operation

        :param ceph_iscsi_config: Config object
        :param logger: logger object
        :param image_id: (str) <pool>.<image> format
        :return: (str) either 'ok' or an error description
        """

        # create can also pass optional controls dict
        mode_vars = {"create": ['pool', 'image', 'size', 'count'],
                     "resize": ['pool', 'image', 'size'],
                     "reconfigure": ['pool', 'image', 'controls'],
                     "delete": ['pool', 'image']}

        if 'mode' in kwargs.keys():
            mode = kwargs['mode']
        else:
            mode = None

        if mode in mode_vars:
            if not all(x in kwargs for x in mode_vars[mode]):
                return ("{} request must contain the following "
                        "variables: ".format(mode,
                                             ','.join(mode_vars[mode])))
        else:
            return "disk operation mode '{}' is invalid".format(mode)

        config = ceph_iscsi_config.config

        disk_key = "{}.{}".format(kwargs['pool'], kwargs['image'])

        if mode in ['create', 'resize']:

            if not valid_size(kwargs['size']):
                return "Size is invalid"

            elif kwargs['pool'] not in get_pools():
                return "pool name is invalid"

        if mode == 'create':
            disk_regex = re.compile(r"^[a-zA-Z0-9\-_]+$")
            if not disk_regex.search(kwargs['pool']):
                return "Invalid pool name (use alphanumeric, '_', or '-' characters)"
            if not disk_regex.search(kwargs['image']):
                return "Invalid image name (use alphanumeric, '_', or '-' characters)"

            if kwargs['count'].isdigit():
                if not 1 <= int(kwargs['count']) <= 10:
                    return "invalid count specified, must be an integer (1-10)"
            else:
                return "invalid count specified, must be an integer (1-10)"

            if kwargs['count'] == '1':
                new_disks = {disk_key}
            else:
                limit = int(kwargs['count']) + 1
                new_disks = set(['{}{}'.format(disk_key, ctr)
                                 for ctr in range(1, limit)])

            if any(new_disk in config['disks'] for new_disk in new_disks):
                return ("at least one rbd image(s) with that name/prefix is "
                        "already defined")

            gateways_defined = len([key for key in config['gateways']
                                   if isinstance(config['gateways'][key],
                                                 dict)])
            if gateways_defined < settings.config.minimum_gateways:
                return ("disks can not be added until at least {} gateways "
                        "are defined".format(settings.config.minimum_gateways))

        if mode in ["resize", "delete", "reconfigure"]:
            # disk must exist in the config
            if disk_key not in config['disks']:
                return ("rbd {}/{} is not defined to the "
                        "configuration".format(kwargs['pool'],
                                               kwargs['image']))

        if mode == 'resize':

            size = kwargs['size'].upper()
            current_size = get_rbd_size(kwargs['pool'], kwargs['image'])
            if convert_2_bytes(size) <= current_size:
                return ("resize value must be larger than the "
                        "current size ({}/{})".format(human_size(current_size),
                                                      current_size))

        if mode in ['create', 'reconfigure']:

            try:
                settings.Settings.normalize_controls(kwargs['controls'],
                                                     LUN.SETTINGS)
            except ValueError as err:
                return(err)

        if mode == 'delete':

            # disk must *not* be allocated to a client in the config
            allocation_list = []
            for client_iqn in config['clients']:
                client_metadata = config['clients'][client_iqn]
                if disk_key in client_metadata['luns']:
                    allocation_list.append(client_iqn)

            if allocation_list:
                return ("Unable to delete {}. Allocated "
                        "to: {}".format(disk_key,
                                        ','.join(allocation_list)))

        return 'ok'

    @staticmethod
    def set_owner(gateways):
        """
        Determine the gateway in the configuration with the lowest number of
        active LUNs. This gateway is then selected as the owner for the
        primary path of the current LUN being processed
        :param gateways: gateway dict returned from the RADOS configuration
               object
        :return: specific gateway hostname (str) that should provide the
               active path for the next LUN
        """

        # Gateways contains simple attributes and dicts. The dicts define the
        # gateways settings, so first we extract only the dicts within the
        # main gateways dict
        gw_nodes = {key: gateways[key] for key in gateways
                    if isinstance(gateways[key], dict)}
        gw_items = gw_nodes.items()

        # first entry is the lowest number of active_luns
        gw_items.sort(key=lambda x: (x[1]['active_luns']))

        # 1st tuple is gw with lowest active_luns, so return the 1st
        # element which is the hostname
        return gw_items[0][0]

    @staticmethod
    def define_luns(logger, config, gateway):
        """
        define the disks in the config to LIO
        :param logger: logger object to print to
        :param config: configuration dict from the rados pool
        :param gateway: (object) gateway object - used for mapping
        :raises CephiSCSIError.
        """

        local_gw = this_host()

        # sort the disks dict keys, so the disks are registered in a specific
        # sequence
        disks = config.config['disks']
        srtd_disks = sorted(disks)
        pools = {disks[disk_key]['pool'] for disk_key in srtd_disks}

        if pools is None:
            logger.info("No LUNs to export")
            return True

        ips = ip_addresses()

        with rados.Rados(conffile=settings.config.cephconf) as cluster:

            for pool in pools:

                logger.debug("Processing rbd's in '{}' pool".format(pool))

                with cluster.open_ioctx(pool) as ioctx:

                    pool_disks = [disk_key for disk_key in srtd_disks
                                  if disk_key.startswith(pool + '.')]
                    for disk_key in pool_disks:

                        pool, image_name = disk_key.split('.')

                        try:
                            with rbd.Image(ioctx, image_name) as rbd_image:
                                RBDDev.rbd_lock_cleanup(logger, ips, rbd_image)

                                lun = LUN(logger, pool, image_name,
                                          rbd_image.size(), local_gw)
                                if lun.error:
                                    raise CephiSCSIError("Error defining rbd "
                                                         "image {}".format(disk_key))

                                lun.allocate()
                                if lun.error:
                                    raise CephiSCSIError("Error unable to "
                                                         "register  {} with "
                                                         "LIO - {}".format(disk_key,
                                                                           lun.error_msg))

                        except rbd.ImageNotFound:
                            raise CephiSCSIError("Disk '{}' defined to the "
                                                 "config, but image '{}' can "
                                                 "not be found in '{}' "
                                                 "pool".format(disk_key,
                                                               image_name,
                                                               pool))

        # Gateway Mapping : Map the LUN's registered to all tpg's within the
        # LIO target
        gateway.manage('map')
        if gateway.error:
            raise CephiSCSIError("Error mapping the LUNs to the tpg's within "
                                 "the iscsi Target")


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
