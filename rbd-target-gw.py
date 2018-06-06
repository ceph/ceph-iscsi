#!/usr/bin/python -u
# NB the python environment is using unbuffered mode (-u), so any "print"
# statements will appear in the syslog 'immediately'

import signal
import logging
import logging.handlers
import netifaces
import subprocess
import time
import sys

import rados
import rbd
from flask import Flask, Response

from rtslib_fb.root import RTSRoot

from ceph_iscsi_config.metrics import GatewayStats

import ceph_iscsi_config.settings as settings

from ceph_iscsi_config.gateway import GWTarget
from ceph_iscsi_config.lun import LUN
from ceph_iscsi_config.client import GWClient
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.lio import LIO, Gateway
from ceph_iscsi_config.utils import this_host, human_size, CephiSCSIError

# Create a flask instance
app = Flask(__name__)

def exception_handler(exception_type, exception, traceback,
                      debug_hook=sys.excepthook):

    # attempt to clear the LIO config, returning it to an uninitialised state
    clearconfig()

    debug_hook(exception_type, exception, traceback)


def ceph_rm_blacklist(blacklisted_ip):
    """
    Issue a ceph osd blacklist rm command for a given IP on this host
    :param blacklisted_ip: IP address (str - dotted quad)
    :return: boolean for success of the rm operation
    """

    logger.info("Removing blacklisted entry for this host : "
                "{}".format(blacklisted_ip))

    result = subprocess.check_output("ceph --conf {cephconf} osd blacklist rm {blacklisted_ip}".
                                     format(blacklisted_ip=blacklisted_ip,
                                            cephconf=settings.config.cephconf),
                                     stderr=subprocess.STDOUT, shell=True)
    if "un-blacklisting" in result:
        logger.info("Successfully removed blacklist entry")
        return True
    else:
        logger.critical("blacklist removal failed. Run"
                        " 'ceph --conf {cephconf} osd blacklist rm {blacklisted_ip}'".
                        format(blacklisted_ip=blacklisted_ip,
                               cephconf=settings.config.cephconf))
        return False


def clearconfig():
    """
    Clear the LIO configuration of the settings defined by the config object
    We could simply call the clear_existing method of rtsroot - but if the
    admin has defined additional non ceph iscsi exports they'd loose everything

    :param local_gw: (str) gateway name
    :return: (int) 0 = LIO configuration removed/not-required
                   4 = LUN removal problem encountered
                   8 = Gateway (target/tpgs) removal failed
    """

    local_gw = this_host()

    # clear the current config, based on the config objects settings
    lio = LIO()
    gw = Gateway(config)

    # This will fail incoming IO, but wait on outstanding IO to
    # complete normally. We rely on the initiator multipath layer
    # to handle retries like a normal path failure.
    logger.info("Removing iSCSI target from LIO")
    gw.drop_target(local_gw)
    if gw.error:
        logger.error("rbd-target-gw failed to remove target objects")
        return 8

    logger.info("Removing LUNs from LIO")
    lio.drop_lun_maps(config, False)
    if lio.error:
        logger.error("rbd-target-gw failed to remove LUN objects")
        return 4

    logger.info("Active Ceph iSCSI gateway configuration removed")
    return 0


def signal_stop(*args):
    """
    Handler to shutdown the service when systemd sends SIGTERM
    NB - args has to be specified since python will pass two parms into the
    handler by default
    :param args: ignored/unused
    """
    logger.info("rbd-target-gw stop received, refreshing local state")
    config.refresh()
    if config.error:
        logger.critical("Problems accessing config object"
                        " - {}".format(config.error_msg))
        sys.exit(16)

    local_gw = this_host()

    if "gateways" in config.config:
        if local_gw not in config.config["gateways"]:
            logger.info("No gateway configuration to remove on this host "
                        "({})".format(local_gw))
            sys.exit(0)
    else:
        logger.info("Configuration object does not hold any gateway metadata"
                    " - nothing to do")
        sys.exit(0)

    rc = clearconfig()

    sys.exit(rc)


def signal_reload(*args):
    """
    Handler to invoke an refresh of the config, when systemd issues a SIGHUP
    NB - args has to be specified since python will pass two parms into the
    handler by default
    :param args: unused
    :return: runs the apply_config function
    """
    if not config_loading:
        logger.info("Reloading configuration from rados configuration object")

        config.refresh()
        if config.error:
            halt("Unable to read the configuration object - "
                 "{}".format(config.error_msg))

        apply_config()

    else:
        logger.warning("Admin attempted to reload the config during an active "
                       "reload process - skipped, try later")


def osd_blacklist_cleanup():
    """
    Process the osd's to see if there are any blacklist entries for this node
    :return: True, blacklist entries removed OK, False - problems removing
    a blacklist
    """

    logger.info("Processing osd blacklist entries for this node")

    cleanup_state = True

    try:

        # NB. Need to use the stderr override to catch the output from
        # the command
        blacklist = subprocess.check_output("ceph --conf {cephconf} osd blacklist ls".
                                            format(cephconf=settings.config.cephconf),
                                            shell=True,
                                            stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError:
        logger.critical("Failed to run 'ceph --conf {cephconf} osd blacklist ls'. "
                        "Please resolve manually...".format(cephconf=settings.config.cephconf))
        cleanup_state = False
    else:

        blacklist_output = blacklist.split('\n')[:-1]
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
                    rm_ok = ceph_rm_blacklist(blacklist_entry.split(' ')[0])
                    if not rm_ok:
                        cleanup_state = False
                        break
        else:
            logger.info("No OSD blacklist entries found")

    return cleanup_state


def halt(message):
    logger.critical(message)
    logger.critical("Removing Ceph iSCSI configuration from LIO")
    clearconfig()
    sys.exit(16)


def get_tpgs():
    """
    determine the number of tpgs in the current LIO environment
    :return: count of the defined tpgs
    """

    return len([tpg.tag for tpg in RTSRoot().tpgs])


def portals_active():
    """
    use the get_tpgs function to determine whether there are tpg's defined
    :return: (bool) indicating whether there are tpgs defined
    """
    return get_tpgs() > 0


def define_gateway():
    """
    define the iSCSI target and tpgs
    :return: (object) gateway object
    """

    gw_ip_list = config.config['gateways'].get('ip_list', None)
    gw_iqn = config.config['gateways'].get('iqn', None)

    # Gateway Definition : Handle the creation of the Target/TPG(s) and Portals
    # Although we create the tpgs, we flick the enable_portal flag off so the
    # enabled tpg will not have an outside IP address. This prevents clients
    # from logging in too early, failing and giving up because the nodeACL
    # hasn't been defined yet (yes Windows I'm looking at you!)

    # first check if there are tpgs already in LIO (True) - this would indicate
    # a restart or reload call has been made. If the tpg count is 0, this is a
    # boot time request

    gateway = GWTarget(logger,
                       gw_iqn,
                       gw_ip_list,
                       enable_portal=portals_active())

    gateway.manage('target')
    if gateway.error:
        halt("Error creating the iSCSI target (target, TPGs, Portals)")

    return gateway


def apply_config():
    """
    procesing logic that orchestrates the creation of the iSCSI gateway
    to LIO.
    """

    # access config_loading from the outer scope, for r/w
    global config_loading
    config_loading = True

    local_gw = this_host()

    logger.info("Reading the configuration object to update local LIO "
                "configuration")

    # first check to see if we have any entries to handle - if not, there is
    # no work to do..
    if "gateways" not in config.config:
        logger.info("Configuration is empty - nothing to define to LIO")
        config_loading = False
        return
    if local_gw not in config.config['gateways']:
        logger.info("Configuration does not have an entry for this host({}) - "
                    "nothing to define to LIO".format(local_gw))
        config_loading = False
        return

    # at this point we have a gateway entry that applies to the running host
    portals_already_active = portals_active()

    logger.info("Processing Gateway configuration")
    gateway = define_gateway()

    logger.info("Processing LUN configuration")
    try:
        LUN.define_luns(logger, config, gateway)
    except CephiSCSIError as err:
            halt("Could not define LUNs: {}".format(err))

    logger.info("Processing client configuration")
    try:
        GWClient.define_clients(logger, config)
    except CephiSCSIError as err:
        halt("Could not define clients: {}".format(err))

    if not portals_already_active:
        # The tpgs, luns and clients are all defined, but the active tpg
        # doesn't have an IP bound to it yet (due to the enable_portals=False
        # setting above)
        logger.info("Adding the IP to the enabled tpg, allowing iSCSI logins")
        gateway.enable_active_tpg(config)
        if gateway.error:
            halt("Error enabling the IP with the active TPG")

    config_loading = False

    logger.info("iSCSI configuration load complete")


@app.route("/", methods=["GET"])
def prom_root():
    """ handle the '/' endpoint - just redirect point the user at /metrics"""
    return '''<!DOCTYPE html>
    <html>
    	<head><title>Ceph/iSCSI Prometheus Exporter</title></head>
    	<body>
    		<h1>Ceph/iSCSI Prometheus Exporter</h1>
    		<p><a href='/metrics'>Metrics</a></p>
    	</body>
    </html>'''


@app.route("/metrics", methods=["GET"])
def prom_metrics():
    """ Collect the stats and send back to the caller"""

    stats = GatewayStats()
    stats.collect()

    return Response(stats.formatted(),
                    content_type="text/plain")


def main():

    # only look for osd blacklist entries when the service starts
    osd_state_ok = osd_blacklist_cleanup()
    if not osd_state_ok:
        sys.exit(16)

    # Read the configuration object and apply to the local LIO instance
    if not config_loading:
        apply_config()

    if settings.config.prometheus_exporter:

        logger.info("Integrated Prometheus exporter is enabled")
        # starting a flask instance will occupy the main thread

        # Attach the werkzeug log to the handlers defined in the outer scope
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.DEBUG)
        log.addHandler(file_handler)
        log.addHandler(syslog_handler)

        app.run(host=settings.config.prometheus_host,
                port=settings.config.prometheus_port,
                debug=False,
                threaded=True)

    else:
        logger.info("Integrated Prometheus exporter is disabled")
        # Just keep the 'lights on' to receive SIGHUP/SIGTERM
        while True:
            time.sleep(1)


if __name__ == '__main__':

    # Setup an exception handler, so any uncaught exception can trigger a
    # clean up process
    sys.excepthook = exception_handler

    # Setup signal handlers for stop and reload actions from systemd
    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGHUP, signal_reload)

    # setup syslog handler to help diagnostics
    logger = logging.getLogger('rbd-target-gw')
    logger.setLevel(logging.DEBUG)

    # syslog (systemctl/journalctl messages)
    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    syslog_handler.setLevel(logging.INFO)
    syslog_format = logging.Formatter("%(message)s")
    syslog_handler.setFormatter(syslog_format)

    # file target - more verbose logging for diagnostics
    file_handler = logging.FileHandler('/var/log/rbd-target-gw.log', mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter("%(asctime)s [%(levelname)8s] - %(message)s")
    file_handler.setFormatter(file_format)

    logger.addHandler(syslog_handler)
    logger.addHandler(file_handler)

    # config_loading is defined in the outer-scope allowing it to be used as
    # a flag to indicate when the apply_config function is running to prevent
    # multiple reloads from being triggered concurrently
    config_loading = False

    settings.init()

    # config is set in the outer scope, so it's easily accessible to the
    # api classes
    config = Config(logger)
    if config.error:
        halt("Unable to open/read the configuration object")
    else:
        main()
