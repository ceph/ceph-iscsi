#!/usr/bin/env python

import os
import time
import Queue
import threading
import rados
import rbd

from gwcli.node import UIGroup, UINode

from gwcli.client import Clients

from gwcli.utils import (human_size, readcontents, console_message,
                         response_message, GatewayAPIError, GatewayError,
                         this_host, APIRequest, valid_snapshot_name, get_config)

from ceph_iscsi_config.utils import valid_size, convert_2_bytes

import ceph_iscsi_config.settings as settings

# FIXME - this ignores the warning issued when verify=False is used
from requests.packages import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Disks(UIGroup):

    scan_interval = 0.02

    help_intro = '''
                 The disks section provides a summary of the rbd images that
                 have been defined and added to the gateway nodes. Each disk
                 listed will provide a view of it's capacity, and you can use
                 the 'info' subcommand to retrieve lower level information
                 about the rbd image.

                 The capacity shown against each disk is the logical size of
                 the rbd image, not the physical space the image is consuming
                 within rados.

                 '''

    def __init__(self, parent):
        UIGroup.__init__(self, 'disks', parent)
        self.disk_info = {}
        self.disk_lookup = {}

        self.scan_threads = self.get_ui_root().scan_threads
        self.scan_queue = None
        self.scan_mutex = None

    def _get_disk_meta(self, cluster_ioctx, disk_meta):
        """
        Use the provided cluster context to take an rbd image name from the
        queue and extract size and feature code. The resulting data is then
        stored in a shared dict accessible by all scan threads
        :param cluster_ioctx: cluster io context object
        :param disk_meta: dict of rbd images, holding metadata
        :return: None
        """

        while True:

            time.sleep(Disks.scan_interval)

            try:
                rbd_name = self.scan_queue.get(block=False)
            except Queue.Empty:
                break
            else:
                pool, image = rbd_name.split('.')
                with cluster_ioctx.open_ioctx(pool) as ioctx:
                    with rbd.Image(ioctx, image) as rbd_image:
                        size = rbd_image.size()
                        features = rbd_image.features()
                        snapshots = list(rbd_image.list_snaps())

                        self.scan_mutex.acquire()
                        disk_meta[rbd_name] = {
                            "size": size,
                            "features": features,
                            "snapshots": snapshots
                        }
                        self.scan_mutex.release()

    def refresh(self, disk_info):
        """
        refresh the disk information by triggering a rescan of the rbd images
        defined in the config object. Scanning uses a common queue object, and
        multiple rbd scan threads to reduce the rescan time for larger
        environments.
        :param disk_info: dict corresponding to the disk subtree of the config
               object
        :return: None
        """

        self.logger.debug("Refreshing disk information from the config object")
        self.disk_info = disk_info

        self.logger.debug("- Scanning will use {} scan "
                          "threads".format(self.scan_threads))

        self.scan_queue = Queue.Queue()
        self.scan_mutex = threading.Lock()
        disk_meta = dict()

        # Load the queue
        for disk_name in disk_info.keys():
            self.scan_queue.put(disk_name)

        start_time = int(time.time())
        scan_threads = []
        # Open a connection to the cluster
        with rados.Rados(conffile=settings.config.cephconf) as cluster:
            # Initiate the scan threads
            for _t in range(0, self.scan_threads, 1):
                _thread = threading.Thread(target=self._get_disk_meta,
                                           args=(cluster, disk_meta))
                _thread.start()
                scan_threads.append(_thread)

            for _t in scan_threads:
                _t.join()

        end_time = int(time.time())
        self.logger.debug("- rbd image scan complete: {}s".format(end_time - start_time))

        # Load the disk configuration
        for image_id in disk_info:
            image_config = disk_info[image_id]
            Disk(self,
                 image_id=image_id,
                 image_config=image_config,
                 size=disk_meta[image_id].get('size', 0),
                 features=disk_meta[image_id].get('features', 0),
                 snapshots=disk_meta[image_id].get('snapshots', []))

    def reset(self):
        children = set(self.children)  # set of child objects
        for child in children:
            self.remove_child(child)

    def ui_command_create(self, pool=None, image=None, size=None, count=1, max_data_area_mb=None):
        """
        Create a LUN and assign to the gateway(s).

        The create command supports two request formats;

        Long format  : create pool=<name> image=<name> size=<size> [max_data_area_mb=<buffer_size>]
        Short format : create pool.image <size>

        e.g.
        create pool=rbd image=testimage size=100g ring_buffer_size=16
        create rbd.testimage 100g

        The syntax of each parameter is as follows;
        pool  : Pool and image name may contain a-z, A-Z, 0-9 or '-' chars
        image
        size  : integer, suffixed by the allocation unit - either m/M, g/G or
                t/T representing the MB/GB/TB [1]
        count : integer (default is 1)[2]. If the request provides a count=<n>
                parameter the image name will be used as a prefix, and the count
                used as a suffix to create multiple LUNs from the same request.
                e.g.
                create rbd.test 1g count=5
                -> create 5 LUNs called test1..test5 each of 1GB in size
                   from the rbd pool
        max_data_area_mb : integer, optional size of kernel data ring buffer (MiB).

        Notes.
        1) size does not support decimal representations
        2) Using a count to create multiple LUNs will lock the CLI until all
           LUNs have been created
        """
        # NB the text above is shown on a help create request in the CLI

        if '.' in pool:
            # shorthand version of the command
            self.logger.debug("user provided pool.image format request")

            if image:
                if size:
                    try:
                        count = int(size)
                    except ValueError:
                        self.logger.error("Invalid count provided "
                                          "({} ?)".format(size))
                        return
                size = image
            else:
                self.logger.error("Shorthand command is create <pool>.<image>"
                                  " <size>")
                return
            pool, image = pool.split('.')

        else:
            # long format request
            if not pool or not image or not size:
                self.logger.error("Invalid create: pool, image and size "
                                  "parameters are needed")
                return

        if not valid_size(size):
            self.logger.error("Invalid size requested. Must be an integer, "
                              "suffixed by M, G or T. See help for more info")
            return

        if count:
            if not str(count).isdigit():
                self.logger.error("invalid count format, must be an integer")
                return
        if max_data_area_mb:
            if not str(max_data_area_mb).isdigit():
                self.logger.error("invalid max data area format, must be an integer in MiB")
                return

        self.logger.debug("CMD: /disks/ create pool={} "
                          "image={} size={} count={} "
                          "max_data_area_mb={}".format(pool, image, size, count,
                                                       max_data_area_mb))

        self.create_disk(pool=pool, image=image, size=size,
                         count=count, max_data_area_mb=max_data_area_mb)

    def _valid_pool(self, pool=None):
        """
        ensure the requested pool is ok to use. currently this is just a
        pool type check, but could also include checks against freespace in the
        pool, it's overcommit ratio etc etc
        :param pool: (str) pool name
        :return: (bool) showing whether the pool is acceptable for a new disk
        """

        # first check that the intended pool is compatible with rbd images
        root = self.get_ui_root()
        clusters = root.ceph.cluster_map
        local_cluster = [clusters[cluster_name] for cluster_name in clusters
                         if clusters[cluster_name]['local']][0]['object']
        pools = local_cluster.pools
        pool_object = pools.pool_lookup.get(pool, None)
        if pool_object:
            if pool_object.type == 'replicated':
                self.logger.debug("pool '{}' is ok to use".format(pool))
                return True

        self.logger.error("Invalid pool ({}). Must already exist and "
                          "be replicated".format(pool))
        return False

    def create_disk(self, pool=None, image=None, size=None, count=1,
                    max_data_area_mb=None, parent=None):

        rc = 0

        if not parent:
            parent = self

        local_gw = this_host()

        disk_key = "{}.{}".format(pool, image)

        if not self._valid_pool(pool):
            return

        self.logger.debug("Creating/mapping disk {}/{}".format(pool,
                                                               image))

        # make call to local api server's disk endpoint
        disk_api = '{}://127.0.0.1:{}/api/disk/{}'.format(self.http_mode,
                                                              settings.config.api_port,
                                                              disk_key)

        api_vars = {'pool': pool, 'size': size.upper(), 'owner': local_gw,
                    'count': count, 'max_data_area_mb': max_data_area_mb,
                    'mode': 'create'}

        self.logger.debug("Issuing disk create request")

        api = APIRequest(disk_api, data=api_vars)
        api.put()

        if api.response.status_code == 200:
            # rbd create and map successful across all gateways so request
            # it's details and add to the UI
            self.logger.debug("- LUN(s) ready on all gateways")
            self.logger.info("ok")

            self.logger.debug("Updating UI for the new disk(s)")
            for n in range(1, (int(count)+1), 1):

                if count > 1:
                    disk_key = "{}.{}{}".format(pool, image, n)
                else:
                    disk_key = "{}.{}".format(pool, image)

                disk_api = ('{}://127.0.0.1:{}/api/disk/'
                            '{}'.format(self.http_mode,
                                        settings.config.api_port,
                                        disk_key))

                api = APIRequest(disk_api)
                api.get()

                if api.response.status_code == 200:
                    try:
                        image_config = api.response.json()
                    except:
                        raise GatewayAPIError("Malformed REST API response")

                    Disk(parent, disk_key, image_config)
                    self.logger.debug("{} added to the UI".format(disk_key))
                else:
                    raise GatewayAPIError("Unable to retrieve disk details "
                                          "for '{}' from the API".format(disk_key))

            ceph_pools = self.parent.ceph.local_ceph.pools
            ceph_pools.refresh()

        else:
            self.logger.error("Failed : {}".format(response_message(api.response,
                                                                    self.logger)))
            rc = 8

        return rc

    def find_hosts(self):
        hosts = []

        tgt_group = self.parent.target.children
        for tgt in tgt_group:
            for tgt_child in tgt.children:
                if isinstance(tgt_child, Clients):
                    hosts += list(tgt_child.children)

        return hosts

    def disk_in_use(self, image_id):
        """
        determine if a given disk image is mapped to any of the defined clients
        @param: image_id ... rbd image name (<pool>.<image> format)
        :return: either an empty list or a list of clients using the disk image
        """
        disk_users = []

        client_list = self.find_hosts()
        for client in client_list:
            client_disks = [mlun.rbd_name for mlun in client.children]
            if image_id in client_disks:
                disk_users.append(client.name)

        return disk_users

    def ui_command_resize(self, image_id=None, size=None):
        """
        The resize command allows you to increase the size of an
        existing rbd image. Attempting to decrease the size of an
        rbd will be ignored.

        image_id: disk name (pool.image format)
        size: new size including unit suffix e.g. 300G
        """
        self.logger.debug("CMD: /disks/ resize {} {}".format(image_id,
                                                             size))
        if image_id and size:
            if image_id in self.disk_lookup:
                disk = self.disk_lookup[image_id]
                disk.resize(size)
                return
            else:
                self.logger.error("the disk '{}' does not exist in this "
                                  "configuration".format(image_id))

                return

        else:
            self.logger.error("resize needs the disk image name and new size")
            return

    def ui_command_reconfigure(self, image_id, attribute, value):
        """
        The reconfigure command allows you to tune various lun attributes.
        An empty value for an attribute resets the lun attribute to its
        default.

        image_id  : disk name (pool.image format)
        attribute : attribute to reconfigure. supported attributes:
            - max_data_area_mb : integer, size of kernel data ring buffer (MiB).
        value     : value of the attribute to reconfigure

        e.g.
        set max_data_area_mb
          - reconfigure image=rbd.disk_1 attribute=max_data_area_mb value=128
        reset max_data_area_mb to default
          - reconfigure image=rbd.disk_1 attribute=max_data_area_mb value=
        """
        if image_id in self.disk_lookup:
            disk = self.disk_lookup[image_id]
            disk.reconfigure(attribute, value)
        else:
            self.logger.error("the disk '{}' does not exist in this "
                              "configuration".format(image_id))

    def ui_command_info(self, image_id):
        """
        Provide disk configuration information (rbd and LIO details are
        provided)
        """
        self.logger.debug("CMD: /disks/ info {}".format(image_id))
        if image_id in self.disk_lookup:
            disk = self.disk_lookup[image_id]
            text = disk.get_info()
            console_message(text)
        else:
            self.logger.error("disk name provided does not exist")



    def ui_command_delete(self, image_id):
        """
        Delete a given rbd image from the configuration and ceph. This is a
        destructive action that could lead to data loss, so please ensure
        the rbd image name is correct!

        > delete <disk_name>
        e.g.
        > delete rbd.disk_1

        "disk_name" refers to the name of the disk as shown in the UI, for
        example rbd.disk_1.

        Also note that the delete process is a synchronous task, so the larger
        the rbd image is, the longer the delete will take to run.

        """

        # Perform a quick 'sniff' test on the request
        if image_id not in [disk.image_id for disk in self.children]:
            self.logger.error("Disk '{}' is not defined to the "
                              "configuration".format(image_id))
            return

        self.logger.debug("CMD: /disks delete {}".format(image_id))

        self.logger.debug("Starting delete for rbd {}".format(image_id))

        local_gw = this_host()
        # other_gateways = get_other_gateways(self.parent.target.children)

        api_vars = {'purge_host': local_gw}

        disk_api = '{}://{}:{}/api/disk/{}'.format(self.http_mode,
                                                       local_gw,
                                                       settings.config.api_port,
                                                       image_id)
        api = APIRequest(disk_api, data=api_vars)
        api.delete()

        if api.response.status_code == 200:
            self.logger.debug("- rbd removed from all gateways, and deleted")
            disk_object = [disk for disk in self.children
                           if disk.name == image_id][0]
            self.remove_child(disk_object)
            del self.disk_info[image_id]
            del self.disk_lookup[image_id]
        else:
            self.logger.debug("delete request failed - "
                              "{}".format(api.response.status_code))
            self.logger.error("{}".format(response_message(api.response,
                                                           self.logger)))
            return

        ceph_pools = self.parent.ceph.local_ceph.pools
        ceph_pools.refresh()

        self.logger.info('ok')

    def _valid_request(self, pool, image, size):
        """
        Validate the parameters of a create request
        :param pool: rados pool name
        :param image: rbd image name
        :param size: size of the rbd (unit suffixed e.g. 20G)
        :return: boolean, indicating whether the parameters may be used or not
        """

        ui_root = self.get_ui_root()
        state = True
        discovered_pools = [rados_pool.name for rados_pool in
                            ui_root.ceph.local_ceph.pools.children]
        existing_rbds = self.disk_info.keys()

        storage_key = "{}.{}".format(pool, image)
        if not size:
            self.logger.error("Size parameter is missing")
            state = False
        elif not valid_size(size):
            self.logger.error("Size is invalid")
            state = False
        elif pool not in discovered_pools:
            self.logger.error("pool name is invalid")
            state = False
        elif storage_key in existing_rbds:
            self.logger.error("image of that name already defined")
            state = False

        return state

    def summary(self):
        total_bytes = 0
        for disk in self.children:
            total_bytes += disk.size
        return '{}, Disks: {}'.format(human_size(total_bytes),
                                      len(self.children)), None


class Disk(UINode):

    display_attributes = ["image", "ceph_cluster", "pool", "wwn", "size_h",
                          "feature_list", "snapshots", "owner", "control_values"]

    def __init__(self, parent, image_id, image_config, size=None,
                 features=None, snapshots=None):
        """
        Create a disk entry under the Disks subtree
        :param parent: parent object (instance of the Disks class)
        :param image_id: key used in the config object for this rbd image
               (pool.image_name) - str
        :param image_config: meta data for this image
        :return:
        """
        self.pool, self.rbd_image = image_id.split('.', 1)

        UINode.__init__(self, image_id, parent)

        self.image_id = image_id
        self.size = 0
        self.size_h = ''
        self.features = 0
        self.feature_list = []
        self.controls = {}
        self.control_values = {}
        self.ceph_cluster = self.parent.parent.ceph.local_ceph.name

        disk_map = self.parent.disk_info
        if image_id not in disk_map:
            disk_map[image_id] = {}

        if image_id not in self.parent.disk_lookup:
            self.parent.disk_lookup[image_id] = self

        self._apply_config(image_config)

        if not size:
            # Size/features are not stored in the config, since it can be changed
            # outside of this tool-chain, so we get them dynamically
            self._refresh_config()
        else:
            # size and features have been passed in from the Disks.refresh
            # method
            self.size = size
            self.size_h = human_size(self.size)
            self.features = features
            self.feature_list = self._get_features()
            self._parse_snapshots(snapshots)

        # update the parent's disk info map
        disk_map = self.parent.disk_info
        disk_map[self.image_id]['size'] = self.size
        disk_map[self.image_id]['size_h'] = self.size_h

    def _apply_config(self, image_config):
        # set the remaining attributes based on the fields in the dict
        disk_map = self.parent.disk_info
        for k, v in image_config.iteritems():
            disk_map[self.image_id][k] = v
            self.__setattr__(k, v)
        for k in ['max_data_area_mb']:
            val = self.controls.get(k)
            default_val = getattr(settings.config, k, None)
            if val is None or str(val) == str(default_val):
                self.control_values[k] = default_val
            else:
                self.control_values[k] = "{} (override)".format(val)

    def summary(self):
        msg = [self.image, "({})".format(self.size_h)]

        return " ".join(msg), True

    def _parse_snapshots(self, snapshots):
        self.snapshots = ["{name} ({size})".format(name=s['name'],
                                                   size=human_size(s['size']))
                          for s in snapshots]
        self.snapshot_names = [s['name'] for s in snapshots]

    def _get_features(self):
        """
        return a human readable list of features for this rbd
        :return: (list) of feature names from the feature code
        """
        rbd_features = {getattr(rbd, f): f for f in rbd.__dict__ if
                        'RBD_FEATURE_' in f}
        feature_idx = sorted(rbd_features)

        disk_features = []

        b_num = bin(self.features).replace('0b', '')
        ptr = len(b_num) - 1
        key_ptr = 0
        while ptr >= 0:
            if b_num[ptr] == '1':
                disk_features.append(rbd_features[feature_idx[key_ptr]])
            key_ptr += 1
            ptr -= 1

        return disk_features

    def _refresh_config(self):
        self._get_meta_data_tcmu()
        self._get_meta_data_config()

    def _get_meta_data_config(self):
        config = get_config()
        if not config:
            return
        self._apply_config(config['disks'][self.image_id])

    def _get_meta_data_tcmu(self):
        """
        query the rbd to get the features and size of the rbd
        :return:
        """
        self.logger.debug("Refreshing image metadata")
        with rados.Rados(conffile=settings.config.cephconf) as cluster:
            with cluster.open_ioctx(self.pool) as ioctx:
                with rbd.Image(ioctx, self.image) as rbd_image:
                    self.size = rbd_image.size()
                    self.size_h = human_size(self.size)
                    self.features = rbd_image.features()
                    self.feature_list = self._get_features()
                    self._parse_snapshots(list(rbd_image.list_snaps()))

    # def get_meta_data_krbd(self):
    #     """
    #     KRBD based method to get size and rbd features information
    #     :return:
    #     """
    #     # image_path is a symlink to the actual /dev/rbdX file
    #     image_path = "/dev/rbd/{}/{}".format(self.pool, self.rbd_image)
    #     dev_id = os.path.realpath(image_path)[8:]
    #     rbd_path = "/sys/devices/rbd/{}".format(dev_id)
    #
    #     try:
    #         self.features = readcontents(os.path.join(rbd_path, 'features'))
    #         self.size = int(readcontents(os.path.join(rbd_path, 'size')))
    #     except IOError:
    #         # if we get an ioError here, it means the config object passed
    #         # back from the API is out of step with the physical configuration
    #         # this can happen after a purge_gateways ansible playbook run if
    #         # the gateways do not have there rbd-target-gw daemons reloaded
    #         error_msg = "The API has returned disks that are not on this " \
    #                     "server...reload rbd-target-api?"
    #
    #         self.logger.critical(error_msg)
    #         raise GatewayError(error_msg)
    #     else:
    #
    #         self.size_h = human_size(self.size)
    #
    #         # update the parent's disk info map
    #         disk_map = self.parent.disk_info
    #
    #         disk_map[self.image_id]['size'] = self.size
    #         disk_map[self.image_id]['size_h'] = self.size_h

    def reconfigure(self, attribute, value):
        allowed_attributes = ['max_data_area_mb']
        if not attribute in allowed_attributes:
            self.logger.error("supported attributes: {}".format(",".join(allowed_attributes)))
            return

        local_gw = this_host()

        # Issue the api request for reconfigure
        disk_api = ('{}://127.0.0.1:{}/api/'
                    'disk/{}'.format(self.http_mode,
                                     settings.config.api_port,
                                     self.image_id))

        api_vars = {'pool': self.pool, 'owner': local_gw,
                    attribute: value, 'mode': 'reconfigure'}

        self.logger.debug("Issuing reconfigure request: attribute={}, "
                          "value={}".format(attribute, value))
        api = APIRequest(disk_api, data=api_vars)
        api.put()

        if api.response.status_code == 200:
            self.logger.info('ok')
            self._refresh_config()
        else:
            self.logger.error("Failed to reconfigure : "
                              "{}".format(response_message(api.response,
                                                           self.logger)))

    def resize(self, size=None):
        """
        Perform the resize operation, and sync the disk size across each of the
        gateways
        :param size: (int) new size for the rbd image
        :return:
        """
        # resize is actually managed by the same lun and api endpoint as
        # create so this logic is very similar to a 'create' request

        size_rqst = size.upper()

        # At this point the size request needs to be honoured
        self.logger.debug("Resizing {} to {}".format(self.image_id,
                                                     size_rqst))

        local_gw = this_host()

        # Issue the api request for the resize
        disk_api = ('{}://127.0.0.1:{}/api/'
                    'disk/{}'.format(self.http_mode,
                                     settings.config.api_port,
                                     self.image_id))

        api_vars = {'pool': self.pool, 'size': size_rqst,
                    'owner': local_gw, 'mode': 'resize'}

        self.logger.debug("Issuing resize request")
        api = APIRequest(disk_api, data=api_vars)
        api.put()

        if api.response.status_code == 200:
            # at this point the resize request was successful, so we need to
            # update the ceph pool meta data (%commit etc)
            self._update_pool()
            self.size_h = size_rqst
            self.size = convert_2_bytes(size_rqst)

            self.logger.info('ok')

        else:
            self.logger.error("Failed to resize : "
                              "{}".format(response_message(api.response,
                                                           self.logger)))

    def snapshot(self, action, name):
        self.logger.debug("CMD: /disks/{} snapshot action={} "
                          "name={}".format(self.image_id, action, name))

        valid_actions = ['create', 'delete', 'rollback']
        if action not in valid_actions:
            self.logger.error("you can only create, delete, or rollback - "
                              "{} is invalid ".format(action))
            return

        if action == 'create':
            if name in self.snapshot_names:
                self.logger.error("Snapshot {} already exists".format(name))
                return
            if not valid_snapshot_name(name):
                self.logger.error("Snapshot {} contains invalid characters".format(name))
                return
        else:
            if name not in self.snapshot_names:
                self.logger.error("Snapshot {} does not exist".format(name))
                return

        if action == 'rollback':
            self.logger.warning("Please be patient, rollback might take time")

        self.logger.debug("Issuing snapshot {} request".format(action))
        disk_api = ('{}://127.0.0.1:{}/api/'
                    'disksnap/{}/{}'.format(self.http_mode,
                                            settings.config.api_port,
                                            self.image_id,
                                            name))

        if action == 'delete':
            api = APIRequest(disk_api)
            api.delete()
        else:
            api_vars = {'mode': action}

            api = APIRequest(disk_api, data=api_vars)
            api.put()

        if api.response.status_code == 200:
            if action == 'create' or action == 'delete':
                self._refresh_config()
            self.logger.info('ok')
        else:
            self.logger.error("Failed to {} snapshot: "
                              "{}".format(action,
                                          response_message(api.response,
                                                           self.logger)))

    def _update_pool(self):
        """
        use the object model to track back from the disk to the relevant pool
        in the local ceph cluster and update the commit stats
        """
        root = self.parent.parent
        ceph_group = root.ceph
        cluster = ceph_group.local_ceph
        pool = cluster.pools.pool_lookup.get(self.pool)

        if pool:
            # update the pool commit numbers
            pool._calc_overcommit()

    def ui_command_resize(self, size=None):
        """
        The resize command allows you to increase the size of an
        existing rbd image. Attempting to decrease the size of an
        rbd will be ignored.

        size: new size including unit suffix e.g. 300G

        """

        self.resize(size)

    def ui_command_reconfigure(self, attribute, value):
        """
        The reconfigure command allows you to tune various lun attributes.
        An empty value for an attribute resets the lun attribute to its
        default.

        attribute : attribute to reconfigure. supported attributes:
            - max_data_area_mb : integer, size of kernel data ring buffer (MiB).
        value     : value of the attribute to reconfigure

        e.g.
        set max_data_area_mb
          - reconfigure attribute=max_data_area_mb value=128
        reset max_data_area_mb to default
          - reconfigure attribute=max_data_area_mb value=
        """
        self.reconfigure(attribute, value)

    def ui_command_snapshot(self, action, name):
        """
        The snapshot command allows you create, delete, and rollback
        snapshots on an existing rbd image.

        e.g.
        snapshot create snap1
        snapshot delete snap1
        snapshot rollback snap1

        action: create, delete, or rollback
        name: snapshot name
        """
        self.snapshot(action, name)
