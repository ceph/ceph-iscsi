import subprocess
import netifaces

from rtslib_fb.utils import RTSLibError
from rtslib_fb.fabric import ISCSIFabricModule
from rtslib_fb.target import Target

import ceph_iscsi_config.settings as settings

from ceph_iscsi_config.target import GWTarget
from ceph_iscsi_config.lun import LUN
from ceph_iscsi_config.client import GWClient
from ceph_iscsi_config.lio import LIO
from ceph_iscsi_config.utils import this_host, CephiSCSIError

__author__ = 'pcuzner@redhat.com'


class CephiSCSIGateway(object):

    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.hostname = this_host()

    def ceph_rm_blacklist(self, blacklisted_ip):
        """
        Issue a ceph osd blacklist rm command for a given IP on this host
        :param blacklisted_ip: IP address (str - dotted quad)
        :return: boolean for success of the rm operation
        """

        self.logger.info("Removing blacklisted entry for this host : "
                         "{}".format(blacklisted_ip))

        conf = settings.config
        result = subprocess.check_output("ceph -n {client_name} --conf {cephconf} "
                                         "osd blacklist rm {blacklisted_ip}".
                                         format(blacklisted_ip=blacklisted_ip,
                                                client_name=conf.cluster_client_name,
                                                cephconf=conf.cephconf),
                                         stderr=subprocess.STDOUT, shell=True)
        if "un-blacklisting" in result:
            self.logger.info("Successfully removed blacklist entry")
            return True
        else:
            self.logger.critical("blacklist removal failed. Run"
                                 " 'ceph -n {client_name} --conf {cephconf} "
                                 "osd blacklist rm {blacklisted_ip}'".
                                 format(blacklisted_ip=blacklisted_ip,
                                        client_name=conf.cluster_client_name,
                                        cephconf=conf.cephconf))
            return False

    def osd_blacklist_cleanup(self):
        """
        Process the osd's to see if there are any blacklist entries for this
        node
        :return: True, blacklist entries removed OK, False - problems removing
        a blacklist
        """

        self.logger.info("Processing osd blacklist entries for this node")

        cleanup_state = True
        conf = settings.config

        try:

            # NB. Need to use the stderr override to catch the output from
            # the command
            blacklist = subprocess.check_output("ceph -n {client_name} --conf {cephconf} "
                                                "osd blacklist ls"
                                                .format(client_name=conf.cluster_client_name,
                                                        cephconf=conf.cephconf),
                                                shell=True,
                                                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            self.logger.critical("Failed to run 'ceph -n {client_name} --conf {cephconf} "
                                 "osd blacklist ls'. Please resolve manually..."
                                 .format(client_name=conf.cluster_client_name,
                                         cephconf=conf.cephconf))
            cleanup_state = False
        else:

            blacklist_output = blacklist.decode('utf-8').split('\n')[:-1]
            if len(blacklist_output) > 1:

                # We have entries to look for, so first build a list of ipv4
                # addresses on this node
                ipv4_list = []
                for iface in netifaces.interfaces():
                    dev_info = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                    ipv4_list += [dev['addr'] for dev in dev_info]

                # process the entries (first entry just says "Listed X entries,
                # last entry is just null)
                for blacklist_entry in blacklist_output[1:]:

                    # valid entries to process look like -
                    # 192.168.122.101:0/3258528596 2016-09-28 18:23:15.307227
                    blacklisted_ip = blacklist_entry.split(':')[0]
                    # Look for this hosts ipv4 address in the blacklist

                    if blacklisted_ip in ipv4_list:
                        # pass in the ip:port/nonce
                        rm_ok = self.ceph_rm_blacklist(blacklist_entry.split(' ')[0])
                        if not rm_ok:
                            cleanup_state = False
                            break
            else:
                self.logger.info("No OSD blacklist entries found")

        return cleanup_state

    def get_tpgs(self, target_iqn):
        """
        determine the number of tpgs in the current target
        :return: count of the defined tpgs
        """

        try:
            target = Target(ISCSIFabricModule(), target_iqn, "lookup")

            return len([tpg.tag for tpg in target.tpgs])
        except RTSLibError:
            return 0

    def portals_active(self, target_iqn):
        """
        use the get_tpgs function to determine whether there are tpg's defined
        :return: (bool) indicating whether there are tpgs defined
        """
        return self.get_tpgs(target_iqn) > 0

    def define_target(self, target_iqn, gw_ip_list):
        """
        define the iSCSI target and tpgs
        :param target_iqn: (str) target iqn
        :param gw_ip_list: (list) gateway ip list
        :return: (object) GWTarget object
        """

        # GWTarget Definition : Handle the creation of the Target/TPG(s) and
        # Portals. Although we create the tpgs, we flick the enable_portal flag
        # off so the enabled tpg will not have an outside IP address. This
        # prevents clients from logging in too early, failing and giving up
        # because the nodeACL hasn't been defined yet (yes Windows I'm looking
        # at you!)

        # first check if there are tpgs already in LIO (True) - this would
        # indicate a restart or reload call has been made. If the tpg count is
        # 0, this is a boot time request

        target = GWTarget(self.logger, target_iqn, gw_ip_list,
                          enable_portal=self.portals_active(target_iqn))
        if target.error:
            raise CephiSCSIError("Error initializing iSCSI target: "
                                 "{}".format(target.error_msg))

        target.manage('target')
        if target.error:
            raise CephiSCSIError("Error creating the iSCSI target (target, "
                                 "TPGs, Portals): {}".format(target.error_msg))

        return target

    def define_targets(self):
        """
        define the list of iSCSI targets and tpgs
        :return: (list) GWTarget objects
        """
        targets = []
        for iqn, target in self.config.config['targets'].items():
            if self.hostname in target['portals']:
                target = self.define_target(iqn, target.get('ip_list', {}))
                targets.append(target)
        return targets

    def define(self):
        """
        procesing logic that orchestrates the creation of the iSCSI gateway
        to LIO.
        """

        self.logger.info("Reading the configuration object to update local LIO "
                         "configuration")

        # first check to see if we have any entries to handle - if not, there is
        # no work to do..
        if "targets" not in self.config.config:
            self.logger.info("Configuration is empty - nothing to define to LIO")
            return

        if self.hostname not in self.config.config['gateways']:
            self.logger.info("Configuration does not have an entry for this host({}) - "
                             "nothing to define to LIO".format(self.hostname))
            return

        # at this point we have a gateway entry that applies to the running host

        self.logger.info("Processing Gateway configuration")
        targets = self.define_targets()

        self.logger.info("Processing LUN configuration")
        for target in targets:

            try:
                LUN.define_luns(self.logger, self.config, target)
            except CephiSCSIError as err:
                self.logger.error("{} - Could not define LUNs: "
                                  "{}".format(target.iqn, err))
                raise

            self.logger.info("{} - Processing client configuration".format(target.iqn))
            try:
                GWClient.define_clients(self.logger, self.config, target.iqn)
            except CephiSCSIError as err:
                self.logger.error("Could not define clients: {}".format(err))
                raise

            if not target.enable_portal:
                # The tpgs, luns and clients are all defined, but the active tpg
                # doesn't have an IP bound to it yet (due to the
                # enable_portals=False setting above)
                self.logger.info("{} - Adding the IP to the enabled tpg, "
                                 "allowing iSCSI logins".format(target.iqn))
                target.enable_active_tpg(self.config)
                if target.error:
                    raise CephiSCSIError("{} - Error enabling the IP with the "
                                         "active TPG: {}".
                                         format(target.iqn, target.error_msg))

        self.logger.info("Ceph iSCSI Gateway configuration load complete")

    def delete_target(self, target_iqn):

        target = GWTarget(self.logger, target_iqn, {})
        if target.error:
            raise CephiSCSIError("Could not initialize target: {}".
                                 format(target.error_msg))

        target.load_config()
        if target.error:
            self.logger.debug("Could not find target {}: {}".
                              format(target_iqn, target.error_msg))
            # Target might not be setup on this node. Ignore.
            return

        try:
            target.delete(self.config)
        except RTSLibError as err:
            err_msg = "Could not remove target {}: {}".format(target_iqn, err)
            raise CephiSCSIError(err_msg)

    def delete_targets(self):

        err_msg = None

        if self.hostname not in self.config.config['gateways']:
            return

        # Clear the current config, based on the config objects settings.
        # This will fail incoming IO, but wait on outstanding IO to
        # complete normally. We rely on the initiator multipath layer
        # to handle retries like a normal path failure.
        self.logger.info("Removing iSCSI target from LIO")

        for target_iqn, target_config in self.config.config['targets'].items():
            try:
                self.delete_target(target_iqn)
            except CephiSCSIError as err:
                if err_msg is None:
                    err_msg = err
                continue

        if err_msg:
            raise CephiSCSIError(err_msg)

    def delete(self):
        """
        Clear the LIO configuration of the settings defined by the config object
        We could simply call the clear_existing method of rtsroot - but if the
        admin has defined additional non ceph iscsi exports they'd loose
        everything

        :return: (int) 0 = LIO configuration removed/not-required
                       4 = LUN removal problem encountered
                       8 = Gateway (target/tpgs) removal failed
        """

        self.logger.debug("delete received, refreshing local state")
        self.config.refresh()
        if self.config.error:
            self.logger.critical("Problems accessing config object"
                                 " - {}".format(self.config.error_msg))
            return 8

        if "gateways" in self.config.config:
            if self.hostname not in self.config.config["gateways"]:
                self.logger.info("No gateway configuration to remove on this "
                                 "host ({})".format(self.hostname))
                return 0
        else:
            self.logger.info("Configuration object does not hold any gateway "
                             "metadata - nothing to do")
            return 0

        ret = 0

        try:
            self.delete_targets()
        except CephiSCSIError:
            ret = 8

        # unload disks not yet added to targets
        lio = LIO()
        lio.drop_lun_maps(self.config, False)
        if lio.error:
            self.logger.error("failed to remove LUN objects")
            if ret != 0:
                ret = 4

        if ret == 0:
            self.logger.info("Active Ceph iSCSI gateway configuration removed")
        return ret
