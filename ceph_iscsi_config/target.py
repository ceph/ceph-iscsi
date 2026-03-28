import os

from rtslib_fb.target import Target, TPG, NetworkPortal, LUN
from rtslib_fb.fabric import ISCSIFabricModule
from rtslib_fb.utils import RTSLibError, normalize_wwn
from rtslib_fb.alua import ALUATargetPortGroup

import ceph_iscsi_config.settings as settings

from ceph_iscsi_config.gateway_setting import TGT_SETTINGS
from ceph_iscsi_config.utils import (normalize_ip_address, normalize_ip_literal,
                                     ip_addresses, this_host, format_lio_yes_no,
                                     CephiSCSIError, CephiSCSIInval)
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.discovery import Discovery
from ceph_iscsi_config.alua import alua_create_group, alua_format_group_name
from ceph_iscsi_config.client import GWClient, CHAP
from ceph_iscsi_config.gateway_object import GWObject
from ceph_iscsi_config.backstore import lookup_storage_object_by_disk

__author__ = 'pcuzner@redhat.com'


class GWTarget(GWObject):
    """
    Class representing the state of the local LIO environment
    """

    # Settings for all transport/fabric objects. Using this allows apps like
    # gwcli to get/set all tpgs/clients under the target instead of per obj.
    SETTINGS = TGT_SETTINGS

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

            self.active_portal_ips = list(matching_ip)
            self.logger.debug("active portal will use "
                              "{}".format(self.active_portal_ips))

            self.gateway_ip_list = gateway_ip_list
            self.logger.debug("tpg's will be defined in this order"
                              " - {}".format(self.gateway_ip_list))
        else:
            # without gateway_ip_list passed in this is a 'init' or
            # 'clearconfig' request
            self.gateway_ip_list = []
            self.active_portal_ips = []

        self.changes_made = False
        self.config_updated = False

        # self.portal = None
        self.target = None
        self.tpg = None
        self.tpg_list = []
        self.tpg_tag_by_gateway_name = {}

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

        return GWTarget._exists(self.iqn)

    @staticmethod
    def _exists(target_iqn):
        return os.path.exists('/sys/kernel/config/target/iscsi/'
                              '{}'.format(target_iqn))

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

        index = 0
        for tpg in self.tpg_list:
            if tpg._get_enable():
                for lun in tpg.luns:
                    try:
                        self.bind_alua_group_to_lun(config,
                                                    lun,
                                                    tpg_ip_address=self.active_portal_ips[index])
                    except CephiSCSIInval as err:
                        self.error = True
                        self.error_msg = err
                        return

                try:
                    NetworkPortal(tpg, normalize_ip_literal(self.active_portal_ips[index]))
                except RTSLibError as e:
                    self.error = True
                    self.error_msg = e
                index += 1

    def clear_config(self, config):
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
            self.delete(config)
        except RTSLibError as err:
            self.error = True
            self.error_msg = "Unable to delete target - {}".format(err)

    def update_acl(self, acl_enabled):
        for tpg in self.tpg_list:
            if acl_enabled:
                tpg.set_attribute('generate_node_acls', 0)
                tpg.set_attribute('demo_mode_write_protect', 1)
            else:
                tpg.set_attribute('generate_node_acls', 1)
                tpg.set_attribute('demo_mode_write_protect', 0)

    def _get_gateway_name(self, ip):
        if ip in self.active_portal_ips:
            return this_host()
        target_config = self.config.config['targets'][self.iqn]
        for portal_name, portal_config in target_config['portals'].items():
            if ip in portal_config['portal_ip_addresses']:
                return portal_name
        return None

    def get_tpg_by_gateway_name(self, gateway_name):
        tpg_tag = self.tpg_tag_by_gateway_name.get(gateway_name)
        if tpg_tag:
            for tpg_item in self.tpg_list:
                if tpg_item.tag == tpg_tag:
                    return tpg_item
        return None

    def update_auth(self, tpg, username=None, password=None,
                    mutual_username=None, mutual_password=None):
        tpg.chap_userid = username
        tpg.chap_password = password
        tpg.chap_mutual_userid = mutual_username
        tpg.chap_mutual_password = mutual_password

        auth_enabled = (username and password)
        if auth_enabled:
            tpg.set_attribute('authentication', '1')
        else:
            GWClient.try_disable_auth(tpg)

    def create_tpg(self, ip):

        try:
            gateway_name = self._get_gateway_name(ip)
            tpg = self.get_tpg_by_gateway_name(gateway_name)
            if not tpg:
                tpg = TPG(self.target)

            # Use initiator name based ACL by default.
            tpg.set_attribute('authentication', '0')

            self.logger.debug("(Gateway.create_tpg) Added tpg for portal "
                              "ip {}".format(ip))
            if ip in self.active_portal_ips:
                target_config = self.config.config['targets'][self.iqn]
                auth_config = target_config['auth']
                config_chap = CHAP(auth_config['username'],
                                   auth_config['password'],
                                   auth_config['password_encryption_enabled'])
                if config_chap.error:
                    self.error = True
                    self.error_msg = config_chap.error_msg
                    return
                config_chap_mutual = CHAP(auth_config['mutual_username'],
                                          auth_config['mutual_password'],
                                          auth_config['mutual_password_encryption_enabled'])
                if config_chap_mutual.error:
                    self.error = True
                    self.error_msg = config_chap_mutual.error_msg
                    return
                self.update_auth(tpg, config_chap.user, config_chap.password,
                                 config_chap_mutual.user, config_chap_mutual.password)
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
            self.tpg_tag_by_gateway_name[gateway_name] = tpg.tag

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
            if self.target:
                self.target.delete()
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
            self.target = Target(ISCSIFabricModule(), self.iqn, "lookup")

            # clear list so we can rebuild with the current values below
            if self.tpg_list:
                del self.tpg_list[:]
            if self.tpg_tag_by_gateway_name:
                self.tpg_tag_by_gateway_name = {}

            # there could/should be multiple tpg's for the target
            for tpg in self.target.tpgs:
                self.tpg_list.append(tpg)
                network_portals = list(tpg.network_portals)
                if network_portals:
                    ip_address = network_portals[0].ip_address
                    gateway_name = self._get_gateway_name(ip_address)
                    if gateway_name:
                        self.tpg_tag_by_gateway_name[gateway_name] = tpg.tag
                else:
                    self.logger.info("No available network portal for target "
                                     "with iqn of '{}'".format(self.iqn))

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

        disk_config = [disk for _, disk in config.config['disks'].items()
                       if disk['backstore_object_name'] == stg_object.name][0]
        owning_gw = disk_config['owner']
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
        gw_config = target_config['portals'].get(owning_gw, None)
        # If the user has exported a disk through multiple targets but
        # they do not have a common gw the owning gw may not exist here.
        # The LUN will just have all ANO paths then.
        if gw_config:
            if tpg_ip_address in gw_config["portal_ip_addresses"]:
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

    def _map_lun(self, config, stg_object, target_disk_config):
        for tpg in self.tpg_list:
            self.logger.debug("processing tpg{}".format(tpg.tag))

            lun_id = target_disk_config['lun_id']

            try:
                mapped_lun = LUN(tpg, lun=lun_id, storage_object=stg_object)
                self.changes_made = True
            except RTSLibError as err:
                if "already exists in configFS" not in str(err):
                    self.logger.error("LUN mapping failed: {}".format(err))
                    self.error = True
                    self.error_msg = err
                    return

                # Already created. Ignore and loop to the next tpg.
                continue

            try:
                self.bind_alua_group_to_lun(config, mapped_lun)
            except CephiSCSIInval as err:
                self.logger.error("Could not bind LUN to ALUA group: "
                                  "{}".format(err))
                self.error = True
                self.error_msg = err
                return

    def map_lun(self, config, stg_object, target_disk_config):
        self.load_config()
        self._map_lun(config, stg_object, target_disk_config)

    def map_luns(self, config):
        """
        LIO will have objects already defined by the lun module,
        so this method, brings those objects into the gateways TPG
        """

        target_config = config.config["targets"][self.iqn]

        for disk_id, disk in target_config['disks'].items():
            stg_object = lookup_storage_object_by_disk(config, disk_id)
            if stg_object is None:
                err_msg = "Could not map {} to LUN. Disk not found".format(disk_id)
                self.logger.error(err_msg)
                self.error = True
                self.error_msg = err_msg
                return

            self._map_lun(config, stg_object, disk)
            if self.error:
                return

    def delete(self, config):

        saved_err = None

        if self.target is None:
            self.load_config()
            # Ignore errors. Target was probably not setup. Try to clean up
            # disks.

        if self.target:
            try:
                self.target.delete()
            except RTSLibError as err:
                self.logger.error("lio target deletion failed {}".format(err))
                saved_err = err
                # drop down and try to delete disks

        for disk in config.config['targets'][self.iqn]['disks'].keys():
            so = lookup_storage_object_by_disk(config, disk)
            if so is None:
                self.logger.debug("lio disk lookup failed {}")
                # SO may not have got setup. Ignore.
                continue
            if so.status == 'activated':
                # Still mapped so ignore.
                continue

            try:
                so.delete()
            except RTSLibError as err:
                self.logger.error("lio disk deletion failed {}".format(err))
                if saved_err is None:
                    saved_err = err
                # Try the other disks.

        if saved_err:
            raise RTSLibError(saved_err)

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

            target_config = config.config["targets"][self.iqn]
            self.update_acl(target_config['acl_enabled'])

            discovery_auth_config = config.config['discovery_auth']
            Discovery.set_discovery_auth_lio(discovery_auth_config['username'],
                                             discovery_auth_config['password'],
                                             discovery_auth_config['password_encryption_enabled'],
                                             discovery_auth_config['mutual_username'],
                                             discovery_auth_config['mutual_password'],
                                             discovery_auth_config[
                                                 'mutual_password_encryption_enabled'])

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
                # Update existing gws with the new gw
                for remote_gw, remote_gw_config in target_config['portals'].items():
                    if remote_gw_config['gateway_ip_list'] == self.gateway_ip_list:
                        continue

                    inactive_portal_ip = list(self.gateway_ip_list)
                    for portal_ip_address in remote_gw_config["portal_ip_addresses"]:
                        inactive_portal_ip.remove(portal_ip_address)
                    remote_gw_config['gateway_ip_list'] = self.gateway_ip_list
                    remote_gw_config['tpgs'] = len(self.tpg_list)
                    remote_gw_config['inactive_portal_ips'] = inactive_portal_ip
                    target_config['portals'][remote_gw] = remote_gw_config

                # Add the new gw
                inactive_portal_ip = list(self.gateway_ip_list)
                for active_portal_ip in self.active_portal_ips:
                    inactive_portal_ip.remove(active_portal_ip)

                portal_metadata = {"tpgs": len(self.tpg_list),
                                   "gateway_ip_list": self.gateway_ip_list,
                                   "portal_ip_addresses": self.active_portal_ips,
                                   "inactive_portal_ips": inactive_portal_ip}
                target_config['portals'][local_gw] = portal_metadata
                target_config['ip_list'] = self.gateway_ip_list

                config.update_item("targets", self.iqn, target_config)
                self.config_updated = True

            if self.config_updated:
                config.commit()
                if config.error:
                    self.error = True
                    self.error_msg = config.error_msg

        elif mode == 'map':

            if self.exists():

                self.load_config()

                self.map_luns(config)

                target_config = config.config["targets"][self.iqn]
                self.update_acl(target_config['acl_enabled'])

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
                # if error happens, we should never store this target to config
                if self.error:
                    return
                seed_target = {
                    'disks': {},
                    'clients': {},
                    'acl_enabled': True,
                    'auth': {
                        'username': '',
                        'password': '',
                        'password_encryption_enabled': False,
                        'mutual_username': '',
                        'mutual_password': '',
                        'mutual_password_encryption_enabled': False},
                    'portals': {},
                    'groups': {},
                    'controls': {}
                }
                config.add_item("targets", self.iqn, seed_target)
                config.commit()
                if config.error:
                    self.error = True
                    self.error_msg = config.error_msg

                discovery_auth_config = config.config['discovery_auth']
                Discovery.set_discovery_auth_lio(discovery_auth_config['username'],
                                                 discovery_auth_config['password'],
                                                 discovery_auth_config[
                                                     'password_encryption_enabled'],
                                                 discovery_auth_config['mutual_username'],
                                                 discovery_auth_config['mutual_password'],
                                                 discovery_auth_config[
                                                     'mutual_password_encryption_enabled'])

        elif mode == 'clearconfig':
            # Called by API from CLI clearconfig command
            if self.exists():
                self.load_config()
                self.clear_config(config)
                if self.error:
                    return
            target_config = config.config["targets"][self.iqn]
            if len(target_config['portals']) == 0:
                config.del_item('targets', self.iqn)
            else:
                gw_ips = target_config['portals'][local_gw]['portal_ip_addresses']

                target_config['portals'].pop(local_gw)

                ip_list = target_config['ip_list']
                for gw_ip in gw_ips:
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
            if config.error:
                self.error = True
                self.error_msg = config.error_msg

    @staticmethod
    def get_num_sessions(target_iqn):
        if not GWTarget._exists(target_iqn):
            return 0
        with open('/sys/kernel/config/target/iscsi/{}/fabric_statistics/iscsi_instance'
                  '/sessions'.format(target_iqn)) as sessions_file:
            return int(sessions_file.read().rstrip('\n'))
