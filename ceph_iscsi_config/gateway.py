#!/usr/bin/env python

import os

from rtslib_fb.target import Target, TPG, NetworkPortal, LUN
from rtslib_fb.fabric import ISCSIFabricModule
from rtslib_fb import root
from rtslib_fb.utils import RTSLibError
from rtslib_fb.alua import ALUATargetPortGroup

import ceph_iscsi_config.settings as settings

from ceph_iscsi_config.utils import (ipv4_addresses, this_host,
                                     format_lio_yes_no)
from ceph_iscsi_config.common import Config

__author__ = 'pcuzner@redhat.com'


class GWTarget(object):
    """
    Class representing the state of the local LIO environment
    """

    @staticmethod
    def get_controls(config):
        all_controls = {}
        controls = config.get('controls', {})
        for k in settings.Settings.GATEWAY_SETTINGS:
            v = controls.get(k, None)
            if v is not None:
                v = settings.Settings.normalize(k, v)
            if v is None:
                v = getattr(settings.config, k)
            all_controls[k] = v
        return all_controls


    def __init__(self, logger, iqn, gateway_ip_list, enable_portal=True):
        """
        Instantiate the class
        :param iqn: iscsi iqn name for the gateway
        :param gateway_ip_list: list of IP addresses to be defined as portals
                to LIO
        :return: gateway object
        """

        self.error = False
        self.error_msg = ''

        self.enable_portal = enable_portal      # boolean to trigger portal
                                                # IP creation

        self.logger = logger                    # logger object

        self.iqn = iqn

        # If the ip list received has data in it, this is a target we need to
        # act on the IP's provided, otherwise just set to null
        if gateway_ip_list:
            # if the ip list provided doesn't match any ip of this host, abort
            # the assumption here is that we'll only have one matching ip in
            # the list!
            matching_ip = set(gateway_ip_list).intersection(ipv4_addresses())
            if len(list(matching_ip)) == 0:
                self.error = True
                self.error_msg = ("gateway IP addresses provided do not match"
                                  " any ip on this host")
                return

            self.active_portal_ip = list(matching_ip)[0]
            self.logger.debug("active portal will use "
                              "{}".format(self.active_portal_ip))

            self.gateway_ip_list = gateway_ip_list
            self.logger.debug("tpg's will be defined in this order"
                              " - {}".format(self.gateway_ip_list))
        else:
            # without gateway_ip_list passed in this is a 'init' or
            # 'clearconfig' request
            self.gateway_ip_list = []
            self.active_portal_ip = []

        self.changes_made = False
        self.config_updated = False

        # self.portal = None
        self.target = None
        self.tpg = None
        self.tpg_list = []

        self.config = Config(self.logger)
        if self.config.error:
            self.error = self.config.error
            self.error_msg = self.config.error_msg

        self.controls = self.config.config.get('controls', {}).copy()
        self._add_properies()

    def _get_control(self, key):
        value = self.controls.get(key, None)
        if value is not None:
            value = settings.Settings.normalize(key, value)
        if value is None:
            return getattr(settings.config, key)
        return value

    def _set_control(self, key, value):
        if value is None or \
                settings.Settings.normalize(key, value) == getattr(settings.config, key):
            self.controls.pop(key, None)
        else:
            self.controls[key] = value

    def _add_properies(self):
        for k in settings.Settings.GATEWAY_SETTINGS:
            setattr(GWTarget, k, property(lambda self, k=k: self._get_control(k),
                                          lambda self, v, k=k: self._set_control(k, v)))

    def exists(self):
        """
        Basic check to see whether this iqn already exists in kernel's
        configFS directory

        :return: boolean
        """

        return os.path.exists('/sys/kernel/config/target/iscsi/'
                              '{}'.format(self.iqn))

    def _get_portals(self, tpg):
        """
        return a list of network portal IPs allocated to a specfic tpg
        :param tpg: tpg to check (object)
        :return: list of IP's this tpg has (list)
        """
        return [portal.ip_address for portal in tpg.network_portals]

    def check_tpgs(self):

        # process the portal IP's in order to preserve the tpg sequence
        # across gateways
        requested_tpg_ips = list(self.gateway_ip_list)
        current_tpgs = list(self.tpg_list)
        for portal_ip in self.gateway_ip_list:

            for tpg in current_tpgs:
                if portal_ip in self._get_portals(tpg):
                    # portal requested is defined, so remove from the list
                    requested_tpg_ips.remove(portal_ip)
                    current_tpgs.remove(tpg)
                    break

        # if the requested_tpg_ips list has entries, we need to add new tpg's
        if requested_tpg_ips:
            self.logger.info("An additional {} tpg's are "
                             "required".format(len(requested_tpg_ips)))

            for ip in requested_tpg_ips:
                self.create_tpg(ip)
        self.update_tpg_controls()


    def update_tpg_controls(self):
        # Build our set of control overrides
        controls = {}
        for k in settings.Settings.GATEWAY_SETTINGS:
            controls[k] = getattr(self, k)

        self.logger.debug("(GWGateway.update_tpg_controls) {}".format(controls))

        try:
            for tpg in self.tpg_list:
                tpg.set_parameter('ImmediateData', format_lio_yes_no(controls['immediate_data']))
                tpg.set_parameter('InitialR2T', format_lio_yes_no(controls['initial_r2t']))
                tpg.set_parameter('MaxOutstandingR2T', str(controls['max_outstanding_r2t']))
                tpg.set_parameter('FirstBurstLength', str(controls['first_burst_length']))
                tpg.set_parameter('MaxBurstLength', str(controls['max_burst_length']))
                tpg.set_parameter('MaxRecvDataSegmentLength', str(controls['max_recv_data_segment_length']))
                tpg.set_parameter('MaxXmitDataSegmentLength', str(controls['max_xmit_data_segment_length']))
        except RTSLibError as err:
            self.error = True
            self.error_msg = "Failed to update TPG control parameters - {}".format(err)

    def enable_active_tpg(self, config):
        """
        Add the relevant ip to the active/enabled tpg within the target
        and bind the tpg's luns to an ALUA group.
        :return: None
        """

        for tpg in self.tpg_list:
            if tpg._get_enable():
                for lun in tpg.luns:
                    self.bind_alua_group_to_lun(config,
                                                lun,
                                                tpg_ip_address=self.active_portal_ip)

                try:
                    NetworkPortal(tpg, self.active_portal_ip)
                except RTSLibError as e:
                    self.error = True
                    self.error_msg = e
                else:
                    break

    def clear_config(self):
        """
        Remove the target definition form LIO
        :return: None
        """
        # check that there aren't any disks or clients in the configuration
        lio_root = root.RTSRoot()

        disk_count = len([disk for disk in lio_root.storage_objects])
        clients = []
        for tpg in self.tpg_list:
            tpg_clients = [node for node in tpg._list_node_acls()]
            clients += tpg_clients
        client_count = len(clients)

        if disk_count > 0 or client_count > 0:
            self.error = True
            self.error_msg = ("Clients({}) and disks({}) must be removed"
                              "before the gateways".format(client_count,
                                                           disk_count))
            return

        self.logger.debug("Clients defined :{}".format(client_count))
        self.logger.debug("Disks defined :{}".format(disk_count))
        self.logger.info("Removing target configuration")

        try:
            self.delete()
        except RTSLibError as err:
            self.error = True
            self.error_msg = "Unable to delete target - {}".format(err)



    def create_tpg(self, ip):

        try:
            tpg = TPG(self.target)

            # Use initiator name based ACL by default.
            tpg.set_attribute('authentication', '0');

            self.logger.debug("(Gateway.create_tpg) Added tpg for portal "
                              "ip {}".format(ip))
            if ip == self.active_portal_ip:
                if self.enable_portal:
                    NetworkPortal(tpg, ip)
                tpg.enable = True
                self.logger.debug("(Gateway.create_tpg) Added tpg for "
                                  "portal ip {} is enabled".format(ip))
            else:
                NetworkPortal(tpg, ip)
                # disable the tpg on this host
                tpg.enable = False
                # by disabling tpg_enabled_sendtargets, discovery to just one
                # node will return all portals (default is 1)
                tpg.set_attribute('tpg_enabled_sendtargets', '0')
                self.logger.debug("(Gateway.create_tpg) Added tpg for "
                                  "portal ip {} as disabled".format(ip))

            self.tpg_list.append(tpg)

        except RTSLibError as err:
            self.error_msg = err
            self.error = True

        else:

            self.changes_made = True
            self.logger.info("(Gateway.create_tpg) created TPG '{}' "
                             "for target iqn '{}'".format(tpg.tag,
                                                          self.iqn))


    def create_target(self):
        """
        Add an iSCSI target to LIO with this objects iqn name, and bind to the
        IP that aligns with the given iscsi_network
        """

        try:
            iscsi_fabric = ISCSIFabricModule()
            self.target = Target(iscsi_fabric, wwn=self.iqn)
            self.logger.debug("(Gateway.create_target) Added iscsi target - "
                              "{}".format(self.iqn))

            # tpg's are defined in the sequence provide by the gateway_ip_list,
            # so across multiple gateways the same tpg number will be
            # associated with the same IP - however, only the tpg with an IP on
            # the host will be in an enabled state. The other tpgs are
            # necessary for systems like ESX who issue a rtpg scsi inquiry
            # only to one of the gateways - so that gateway must provide
            # details for the whole configuration
            self.logger.debug("Creating tpgs")
            for ip in self.gateway_ip_list:
                self.create_tpg(ip)
                if self.error:
                    self.logger.critical("Unable to create the TPG for {} "
                                         "- {}".format(ip, self.error_msg))
            self.update_tpg_controls()

        except RTSLibError as err:
            self.error_msg = err
            self.logger.critical("Unable to create the Target definition "
                                 "- {}".format(self.error_msg))
            self.error = True

        if self.error:
            self.delete()
        else:
            self.changes_made = True
            self.logger.info("(Gateway.create_target) created an iscsi target "
                             "with iqn of '{}'".format(self.iqn))


    def load_config(self):
        """
        Grab the target, tpg and portal objects from LIO and store in this
        Gateway object
        """

        try:

            lio_root = root.RTSRoot()
            self.target = [tgt for tgt in lio_root.targets
                           if tgt.wwn == self.iqn][0]

            # there could/should be multiple tpg's for the target
            for tpg in self.target.tpgs:
                self.tpg_list.append(tpg)

            # self.portal = self.tpg.network_portals.next()

        except RTSLibError as err:
            self.error_msg = err
            self.error = True

        self.logger.info("(Gateway.load_config) successfully loaded existing "
                         "target definition")

    def bind_alua_group_to_lun(self, config, lun, tpg_ip_address=None):
        """
        bind lun to one of the alua groups. Query the config to see who
        'owns' the primary path for this LUN. Then either bind the LUN
        to the ALUA 'AO' group if the host matches, or default to the
        'ANO' alua group

        param config: Config object
        param lun: lun object on the tpg
        param tpg_ip: IP of Network Portal for the lun's tpg.
        """
        # return

        stg_object = lun.storage_object

        owning_gw = config.config['disks'][stg_object.name]['owner']
        tpg = lun.parent_tpg

        if tpg_ip_address is None:
            # just need to check one portal
            for ip in tpg.network_portals:
                tpg_ip_address = ip.ip_address
                break

        if tpg_ip_address is None:
            # this is being run during boot so the NP is not setup yet.
            return

        # TODO: The ports in a alua group must export the same state for a LU
        # group. For different LUs we are exporting different states, so
        # we should be creating different LU groups or creating different
        # alua groups for each LU.
        try:
            if config.config["gateways"][owning_gw]["portal_ip_address"] == tpg_ip_address:
                self.logger.info("setting {} to ALUA/ActiveOptimised "
                                 "group id {}".format(stg_object.name, tpg.tag))
                group_name = "ao"
                alua_tpg = ALUATargetPortGroup(stg_object, group_name, tpg.tag)
                alua_tpg.preferred = 1
            else:
                self.logger.info("setting {} to ALUA/Standby"
                                 "group id {}".format(stg_object.name, tpg.tag))
                group_name = "standby{}".format(tpg.tag)
                alua_tpg = ALUATargetPortGroup(stg_object, group_name, tpg.tag)
        except RTSLibError as err:
                self.logger.info("ALUA group id {} for stg obj {} lun {} "
                                 "already made".format(tpg.tag, stg_object, lun))
                # someone mapped a LU then unmapped it without deleting the
                # stg_object, or we are reloading the config.
                alua_tpg = ALUATargetPortGroup(stg_object, group_name)
                if alua_tpg.tpg_id != tpg.tag:
                    # ports and owner were rearranged. Not sure we support that.
                    raise RTSLibError

                # drop down in case we are restarting due to error and we
                # were not able to bind to a lun last time.

        self.logger.debug("ALUA defined, updating state")
        # Use Explicit but also set the Implicit bit so we can
        # update the kernel from configfs.
        alua_tpg.alua_access_type = 3
        # start ports in Standby, and let the initiator drive the initial
        # transition to AO.
        alua_tpg.alua_access_state = 2

        alua_tpg.alua_support_offline = 0
        alua_tpg.alua_support_unavailable = 0
        alua_tpg.alua_support_standby = 1
        alua_tpg.alua_support_transitioning = 1
        alua_tpg.implicit_trans_secs = 60
        alua_tpg.nonop_delay_msecs = 0


        # alua_tpg.bind_to_lun(lun)
        self.logger.debug("Setting Luns tg_pt_gp to {}".format(group_name))
        lun.alua_tg_pt_gp_name = group_name
        self.logger.debug("Bound {} on tpg{} to {}".format(stg_object.name,
                                                           tpg.tag,
                                                           group_name))

    def map_luns(self, config):
        """
        LIO will have objects already defined by the lun module,
        so this method, brings those objects into the gateways TPG
        """

        lio_root = root.RTSRoot()

        # process each storage object added to the gateway, and map to the tpg
        for stg_object in lio_root.storage_objects:

            for tpg in self.tpg_list:
                self.logger.debug("processing tpg{}".format(tpg.tag))

                if not self.lun_mapped(tpg, stg_object):
                    self.logger.debug("{} needed mapping to "
                                      "tpg{}".format(stg_object.name,
                                                     tpg.tag))

                    lun_id = int(stg_object.path.split('/')[-2].split('_')[1])

                    try:
                        mapped_lun = LUN(tpg, lun=lun_id, storage_object=stg_object)
                        self.changes_made = True
                    except RTSLibError as err:
                        self.logger.error("LUN mapping failed: {}".format(err))
                        self.error = True
                        self.error_msg = err
                        return

                    self.bind_alua_group_to_lun(config, mapped_lun)

    def lun_mapped(self, tpg, storage_object):
        """
        Check to see if a given storage object (i.e. block device) is already
        mapped to the gateway's TPG
        :param storage_object: storage object to look for
        :return: boolean - is the storage object mapped or not
        """

        mapped_state = False
        for l in tpg.luns:
            if l.storage_object.name == storage_object.name:
                mapped_state = True
                break

        return mapped_state

    def delete(self):
        self.target.delete()

    def manage(self, mode):
        """
        Manage the definition of the gateway, given a mode of 'target', 'map',
        'init' or 'clearconfig'. In 'target' mode the LIO TPG is defined,
        whereas in map mode, the required LUNs are added to the existing TPG
        :param mode: run mode - target, map, init or clearconfig (str)
        :return: None - but sets the objects error flags to be checked by
                 the caller
        """
        config = Config(self.logger)
        if config.error:
            self.error = True
            self.error_msg = config.error_msg
            return

        local_gw = this_host()

        if mode == 'target':

            if self.exists():
                self.load_config()
                self.check_tpgs()
            else:
                self.create_target()

            if self.error:
                # return to caller, with error state set
                return

            gateway_group = config.config["gateways"].keys()

            # this action could be carried out by multiple nodes concurrently,
            # but since the value is the same (i.e all gateway nodes use the
            # same iqn) it's not worth worrying about!
            if "iqn" not in gateway_group:
                self.config_updated = True
                config.add_item("gateways",
                                "iqn",
                                initial_value=self.iqn)

            if "ip_list" not in gateway_group:
                self.config_updated = True
                config.add_item("gateways",
                                "ip_list",
                                initial_value=self.gateway_ip_list)

            if self.controls != config.config.get('controls', {}):
                config.set_item('controls', '', self.controls.copy())
                self.config_updated = True

            if local_gw not in gateway_group:
                inactive_portal_ip = list(self.gateway_ip_list)
                inactive_portal_ip.remove(self.active_portal_ip)
                gateway_metadata = {"portal_ip_address": self.active_portal_ip,
                                    "iqn": self.iqn,
                                    "active_luns": 0,
                                    "tpgs": len(self.tpg_list),
                                    "inactive_portal_ips": inactive_portal_ip,
                                    "gateway_ip_list": self.gateway_ip_list}

                config.add_item("gateways", local_gw)
                config.update_item("gateways", local_gw, gateway_metadata)
                config.update_item("gateways", "ip_list", self.gateway_ip_list)
                self.config_updated = True
            else:
                # gateway already defined, so check that the IP list it has
                # matches the current request
                gw_details = config.config['gateways'][local_gw]
                if cmp(gw_details['gateway_ip_list'], self.gateway_ip_list) != 0:
                    inactive_portal_ip = list(self.gateway_ip_list)
                    inactive_portal_ip.remove(self.active_portal_ip)
                    gw_details['tpgs'] = len(self.tpg_list)
                    gw_details['gateway_ip_list'] = self.gateway_ip_list
                    gw_details['inactive_portal_ips'] = inactive_portal_ip
                    config.update_item('gateways', local_gw, gw_details)
                    self.config_updated = True

            if self.config_updated:
                config.commit()

        elif mode == 'map':

            if self.exists():

                self.load_config()

                self.map_luns(config)

            else:
                self.error = True
                self.error_msg = ("Attempted to map to a gateway '{}' that "
                                  "hasn't been defined yet...out of order "
                                  "steps?".format(self.iqn))

        elif mode == 'init':

            # init mode just creates the iscsi target definition and updates
            # the config object. It is used by the CLI only
            if self.exists():
                self.logger.info("GWTarget init request skipped - target "
                                 "already exists")

            else:
                # create the target
                self.create_target()
                current_iqn = config.config['gateways'].get('iqn', '')

                # First gateway asked to create the target will update the
                # config object
                if not current_iqn:

                    config.add_item("gateways", "iqn", initial_value=self.iqn)
                    config.commit()

        elif mode == 'reconfigure':
            if self.controls != config.config.get('controls', {}):
                config.set_item('controls', '', self.controls.copy())
                config.commit()

        elif mode == 'clearconfig':
            # Called by API from CLI clearconfig command
            if self.exists():
                self.load_config()
            else:
                self.error = True
                self.error_msg = "IQN provided does not exist"

            self.clear_config()

            if not self.error:
                gw_ip = config.config['gateways'][local_gw]['portal_ip_address']

                config.del_item('gateways', local_gw)

                ip_list = config.config['gateways']['ip_list']
                ip_list.remove(gw_ip)
                if len(ip_list) > 0:
                    config.update_item('gateways', 'ip_list', ip_list)
                else:
                    # no more gateways in the list, so delete remaining items
                    config.del_item('gateways', 'ip_list')
                    config.del_item('gateways', 'iqn')
                    config.del_item('gateways', 'created')

                config.commit()


