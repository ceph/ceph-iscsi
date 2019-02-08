#!/usr/bin/env python

import os

from rtslib_fb.target import Target, TPG, NetworkPortal, LUN
from rtslib_fb.fabric import ISCSIFabricModule
from rtslib_fb import root
from rtslib_fb.utils import RTSLibError, normalize_wwn
from rtslib_fb.alua import ALUATargetPortGroup

import ceph_iscsi_config.settings as settings

from ceph_iscsi_config.utils import (normalize_ip_address, normalize_ip_literal,
                                     ip_addresses, this_host, format_lio_yes_no,
                                     CephiSCSIError, CephiSCSIInval)
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.discovery import Discovery
from ceph_iscsi_config.alua import alua_create_group, alua_format_group_name
from ceph_iscsi_config.client import GWClient
from ceph_iscsi_config.gateway_object import GWObject

__author__ = 'pcuzner@redhat.com'


class GWTarget(GWObject):
    """
    Class representing the state of the local LIO environment
    """
    # iscsi tpg specific settings.
    TPG_SETTINGS = [
        "dataout_timeout",
        "immediate_data",
        "initial_r2t",
        "max_outstanding_r2t",
        "first_burst_length",
        "max_burst_length",
        "max_recv_data_segment_length",
        "max_xmit_data_segment_length"]

    # Settings for all transport/fabric objects. Using this allows apps like
    # gwcli to get/set all tpgs/clients under the target instead of per obj.
    SETTINGS = TPG_SETTINGS + GWClient.SETTINGS

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

        self.enable_portal = enable_portal  # boolean to trigger portal IP creation
        self.logger = logger                # logger object

        try:
            iqn, iqn_type = normalize_wwn(['iqn'], iqn)
        except RTSLibError as err:
            self.error = True
            self.error_msg = "Invalid iSCSI target name - {}".format(err)
        self.iqn = iqn

        # Ensure IPv6 addresses are in the normalized address (not literal) format
        gateway_ip_list = [normalize_ip_address(x) for x in gateway_ip_list]

        # If the ip list received has data in it, this is a target we need to
        # act on the IP's provided, otherwise just set to null
        if gateway_ip_list:
            # if the ip list provided doesn't match any ip of this host, abort
            # the assumption here is that we'll only have one matching ip in
            # the list!
            matching_ip = set(gateway_ip_list).intersection(ip_addresses())
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

        try:
            super(GWTarget, self).__init__('targets', iqn, logger,
                                           GWTarget.SETTINGS)
        except CephiSCSIError as err:
            self.error = True
            self.error_msg = err

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
        return [normalize_ip_address(portal.ip_address) for portal
                in tpg.network_portals]

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

        try:
            self.update_tpg_controls()
        except RTSLibError as err:
            self.error = True
            self.error_msg = "Failed to update TPG control parameters - {}".format(err)

    def update_tpg_controls(self):
        self.logger.debug("(GWGateway.update_tpg_controls) {}".format(self.controls))
        for tpg in self.tpg_list:
            tpg.set_parameter('ImmediateData',
                              format_lio_yes_no(self.immediate_data))
            tpg.set_parameter('InitialR2T',
                              format_lio_yes_no(self.initial_r2t))
            tpg.set_parameter('MaxOutstandingR2T',
                              str(self.max_outstanding_r2t))
            tpg.set_parameter('FirstBurstLength', str(self.first_burst_length))
            tpg.set_parameter('MaxBurstLength', str(self.max_burst_length))
            tpg.set_parameter('MaxRecvDataSegmentLength',
                              str(self.max_recv_data_segment_length))
            tpg.set_parameter('MaxXmitDataSegmentLength',
                              str(self.max_xmit_data_segment_length))

    def enable_active_tpg(self, config):
        """
        Add the relevant ip to the active/enabled tpg within the target
        and bind the tpg's luns to an ALUA group.
        :return: None
        """

        for tpg in self.tpg_list:
            if tpg._get_enable():
                for lun in tpg.luns:
                    try:
                        self.bind_alua_group_to_lun(config,
                                                    lun,
                                                    tpg_ip_address=self.active_portal_ip)
                    except CephiSCSIInval as err:
                        self.error = True
                        self.error_msg = err
                        return

                try:
                    NetworkPortal(tpg, normalize_ip_literal(self.active_portal_ip))
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
        clients = []
        disks = set()
        for tpg in self.tpg_list:
            tpg_clients = [node for node in tpg._list_node_acls()]
            clients += tpg_clients
            disks.update([lun.storage_object.name for lun in tpg.luns])
        client_count = len(clients)
        disk_count = len(disks)

        if disk_count > 0 or client_count > 0:
            self.error = True
            self.error_msg = ("Clients({}) and disks({}) must be removed "
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

    def update_acl(self, config):
        target_config = config.config["targets"][self.iqn]
        for tpg in self.tpg_list:
            if target_config['acl_enabled']:
                tpg.set_attribute('generate_node_acls', 0)
            else:
                tpg.set_attribute('generate_node_acls', 1)

    def create_tpg(self, ip):

        try:
            tpg = TPG(self.target)

            # Use initiator name based ACL by default.
            tpg.set_attribute('authentication', '0')

            self.logger.debug("(Gateway.create_tpg) Added tpg for portal "
                              "ip {}".format(ip))
            if ip == self.active_portal_ip:
                if self.enable_portal:
                    NetworkPortal(tpg, normalize_ip_literal(ip))
                tpg.enable = True
                self.logger.debug("(Gateway.create_tpg) Added tpg for "
                                  "portal ip {} is enabled".format(ip))
            else:
                NetworkPortal(tpg, normalize_ip_literal(ip))
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
        'ANO'/'Standby' alua group

        param config: Config object
        param lun: lun object on the tpg
        param tpg_ip: IP of Network Portal for the lun's tpg.
        """

        stg_object = lun.storage_object

        owning_gw = config.config['disks'][stg_object.name]['owner']
        tpg = lun.parent_tpg

        if not tpg_ip_address:
            # just need to check one portal
            for ip in tpg.network_portals:
                tpg_ip_address = normalize_ip_address(ip.ip_address)
                break

        if tpg_ip_address is None:
            # this is being run during boot so the NP is not setup yet.
            return

        target_config = config.config["targets"][self.iqn]

        is_owner = False
        if target_config['portals'][owning_gw]["portal_ip_address"] == tpg_ip_address:
            is_owner = True

        try:
            alua_tpg = alua_create_group(settings.config.alua_failover_type,
                                         tpg, stg_object, is_owner)
        except CephiSCSIInval:
            raise
        except RTSLibError:
            self.logger.info("ALUA group id {} for stg obj {} lun {} "
                             "already made".format(tpg.tag, stg_object, lun))
            group_name = alua_format_group_name(tpg,
                                                settings.config.alua_failover_type,
                                                is_owner)
            # someone mapped a LU then unmapped it without deleting the
            # stg_object, or we are reloading the config.
            alua_tpg = ALUATargetPortGroup(stg_object, group_name)
            if alua_tpg.tg_pt_gp_id != tpg.tag:
                # ports and owner were rearranged. Not sure we support that.
                raise CephiSCSIInval("Existing ALUA group tag for group {} "
                                     "in invalid state.\n".format(group_name))

            # drop down in case we are restarting due to error and we
            # were not able to bind to a lun last time.

        self.logger.info("Setup group {} for {} on tpg {} (state {}, owner {}, "
                         "failover type {})".format(alua_tpg.name, stg_object.name,
                                                    tpg.tag, alua_tpg.alua_access_state,
                                                    is_owner, alua_tpg.alua_access_type))

        self.logger.debug("Setting Luns tg_pt_gp to {}".format(alua_tpg.name))
        lun.alua_tg_pt_gp_name = alua_tpg.name
        self.logger.debug("Bound {} on tpg{} to {}".format(stg_object.name,
                                                           tpg.tag,
                                                           alua_tpg.name))

    def map_luns(self, config):
        """
        LIO will have objects already defined by the lun module,
        so this method, brings those objects into the gateways TPG
        """

        lio_root = root.RTSRoot()
        target_config = config.config["targets"][self.iqn]
        target_stg_object = [stg_object for stg_object in lio_root.storage_objects
                             if stg_object.name in target_config['disks']]

        # process each storage object added to the gateway, and map to the tpg
        for stg_object in target_stg_object:

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

                    try:
                        self.bind_alua_group_to_lun(config, mapped_lun)
                    except CephiSCSIInval as err:
                        self.logger.error("Could not bind LUN to ALUA group: "
                                          "{}".format(err))
                        self.error = True
                        self.error_msg = err
                        return

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

            Discovery.set_discovery_auth_lio(config.config['discovery_auth']['chap'],
                                             config.config['discovery_auth']['chap_mutual'])

            target_config = config.config["targets"][self.iqn]
            gateway_group = config.config["gateways"].keys()
            if "ip_list" not in target_config:
                target_config['ip_list'] = self.gateway_ip_list
                config.update_item("targets", self.iqn, target_config)
                self.config_updated = True

            if self.controls != target_config.get('controls', {}):
                target_config['controls'] = self.controls.copy()
                config.update_item("targets", self.iqn, target_config)
                self.config_updated = True

            if local_gw not in gateway_group:
                gateway_metadata = {"active_luns": 0}
                config.add_item("gateways", local_gw)
                config.update_item("gateways", local_gw, gateway_metadata)
                self.config_updated = True

            if local_gw not in target_config['portals']:
                inactive_portal_ip = list(self.gateway_ip_list)
                inactive_portal_ip.remove(self.active_portal_ip)

                portal_metadata = {"tpgs": len(self.tpg_list),
                                   "gateway_ip_list": self.gateway_ip_list,
                                   "portal_ip_address": self.active_portal_ip,
                                   "inactive_portal_ips": inactive_portal_ip}
                target_config['portals'][local_gw] = portal_metadata
                target_config['ip_list'] = self.gateway_ip_list
                config.update_item("targets", self.iqn, target_config)
                self.config_updated = True
            else:
                # gateway already defined, so check that the IP list it has
                # matches the current request
                portal_details = target_config['portals'][local_gw]
                if portal_details['gateway_ip_list'] != self.gateway_ip_list:
                    inactive_portal_ip = list(self.gateway_ip_list)
                    inactive_portal_ip.remove(self.active_portal_ip)
                    portal_details['gateway_ip_list'] = self.gateway_ip_list
                    portal_details['tpgs'] = len(self.tpg_list)
                    portal_details['inactive_portal_ips'] = inactive_portal_ip
                    target_config['portals'][local_gw] = portal_details
                    config.update_item("targets", self.iqn, target_config)
                    self.config_updated = True

            if self.config_updated:
                config.commit()

        elif mode == 'map':

            if self.exists():

                self.load_config()

                self.map_luns(config)

                self.update_acl(config)

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
                seed_target = {
                    'disks': [],
                    'clients': {},
                    'acl_enabled': True,
                    'portals': {},
                    'groups': {},
                    'controls': {}
                }
                config.add_item("targets", self.iqn, seed_target)
                config.commit()

                Discovery.set_discovery_auth_lio(config.config['discovery_auth']['chap'],
                                                 config.config['discovery_auth']['chap_mutual'])

        elif mode == 'clearconfig':
            # Called by API from CLI clearconfig command
            if self.exists():
                self.load_config()
            else:
                self.error = True
                self.error_msg = "Target {} does not exist on {}".format(self.iqn, local_gw)
                return

            target_config = config.config["targets"][self.iqn]
            self.clear_config()

            if not self.error:
                if len(target_config['portals']) == 0:
                    config.del_item('targets', self.iqn)
                else:
                    gw_ip = target_config['portals'][local_gw]['portal_ip_address']

                    target_config['portals'].pop(local_gw)

                    ip_list = target_config['ip_list']
                    ip_list.remove(gw_ip)
                    if len(ip_list) > 0 and len(target_config['portals'].keys()) > 0:
                        config.update_item('targets', self.iqn, target_config)
                    else:
                        # no more portals in the list, so delete the target
                        config.del_item('targets', self.iqn)

                    remove_gateway = True
                    for _, target in config.config["targets"].items():
                        if local_gw in target['portals']:
                            remove_gateway = False
                            break

                    if remove_gateway:
                        # gateway is no longer used, so delete it
                        config.del_item('gateways', local_gw)

                config.commit()
