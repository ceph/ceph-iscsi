#!/usr/bin/env python

import sys
import os
import signal
import logging
import logging.handlers
import ssl
import OpenSSL
import threading
import time
import inspect

from functools import wraps
from rpm import labelCompare
import rados

import werkzeug
from flask import Flask, jsonify, make_response, request, abort
from rtslib_fb.utils import RTSLibError, normalize_wwn

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.gateway import GWTarget
from ceph_iscsi_config.lun import LUN
from ceph_iscsi_config.client import GWClient
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.utils import (get_ip, this_host, ipv4_addresses,
                                     gen_file_hash, valid_rpm,
                                     ConfFile)

__author__ = "pcuzner@redhat.com"

app = Flask(__name__)


def requires_basic_auth(f):
    """
    wrapper function to check authentication credentials are valid
    """

    @wraps(f)
    def decorated(*args, **kwargs):

        # check credentials supplied in the http request are valid
        auth = request.authorization
        if not auth:
            abort(401)

        if (auth.username != settings.config.api_user or
           auth.password != settings.config.api_password):
            abort(401)

        return f(*args, **kwargs)

    return decorated


def requires_restricted_auth(f):
    """
    Wrapper function which checks both auth credentials and source IP
    address to validate the request
    """

    @wraps(f)
    def decorated(*args, **kwargs):

        # First check that the source of the request is actually valid
        local_gw = ['127.0.0.1']
        gw_names = [gw for gw in config.config['gateways']
                    if isinstance(config.config['gateways'][gw], dict)]
        gw_ips = [get_ip(gw_name) for gw_name in gw_names] + \
                  local_gw + settings.config.trusted_ip_list

        if request.remote_addr not in gw_ips:
            abort(403)

        # check credentials supplied in the http request are valid
        auth = request.authorization
        if not auth:
            abort(401)

        if (auth.username != settings.config.api_user or
           auth.password != settings.config.api_password):
            abort(401)

        return f(*args, **kwargs)

    return decorated


@app.route('/api')
def get_api_info():
    """
    Display the available API endpoints
    :return:
    """
    links = []
    for rule in app.url_map.iter_rules():
        url = rule.rule
        if rule.endpoint == 'static':
            continue
        else:
            func_doc = inspect.getdoc(globals()[rule.endpoint])
            if func_doc:
                doc = func_doc.split('\n')[0]
            else:
                doc = ''
        links.append((url, doc))

    return make_response(jsonify(api=links), 200)


@app.route('/api/sysinfo/<query_type>')
@requires_basic_auth
def sys_info(query_type=None):
    """
    Provide system information based on the query_type
    """

    if query_type == 'ipv4_addresses':

        return make_response(jsonify(data=ipv4_addresses()), 200)

    elif query_type == 'checkconf':

        local_hash = gen_file_hash('/etc/ceph/iscsi-gateway.conf')
        return make_response(jsonify(data=local_hash), 200)

    elif query_type == 'checkversions':

        config_errors = pre_reqs_errors()
        if config_errors:
            return make_response(jsonify(data=config_errors), 500)
        else:
            return make_response(jsonify(data='checks passed'), 200)

    else:
        # Request Unknown
        abort(404,
              "Unknown query")


@app.route('/api/target/<target_iqn>', methods=['PUT'])
@requires_restricted_auth
def target(target_iqn=None):
    """
    Handle the definition of the iscsi target name

    The target is added to the configuration object, seeding the configuration
    for ALL gateways
    :param target_iqn: IQN of the target each gateway will use
    :return: None
    """
    if request.method == 'PUT':

        gateway_ip_list = []

        target = GWTarget(logger,
                          str(target_iqn),
                          gateway_ip_list)

        if target.error:
            logger.error("Unable to create an instance of the GWTarget class")
            abort(418,
                  "GWTarget problem - {}".format(target.error_msg))

        target.manage('init')
        if target.error:
            logger.error("Failure during gateway 'init' processing")
            abort(418,
                  "iscsi target 'init' process failed for {} - "
                  "{}".format(target_iqn, target.error_msg))

        return make_response(jsonify(
                             {"message": "Target defined successfully"}), 200)
        pass
    else:
        # return unrecognised request
        abort(405)


@app.route('/api/config')
@requires_restricted_auth
def get_config():
    """
    Return the complete config object to the caller - must be authenticated

    Contents will include any defined CHAP credentials
    :return:
    """
    if request.method == 'GET':
        return make_response(jsonify(config.config), 200)
    else:
        abort(403)


@app.route('/api/gateways')
@requires_restricted_auth
def get_gateways():
    """
    Return the gateway subsection of the config object to the caller
    """
    if request.method == 'GET':
        return make_response(jsonify(config.config['gateways']), 200)
    else:
        abort(403)


@app.route('/api/gateway/<gateway_name>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def manage_gateway(gateway_name=None):
    """
    Manage the gateway definition lifecycle

    Gateways maye be added(PUT), queried (GET) or deleted (DELETE) from
    the configuration
    :param gateway_name: (str) gateway name, normally the DNS name
    :return:
    """

    if request.method == 'GET':

        if gateway_name in config.config['gateways']:

            return make_response(jsonify(
                                 config.config['gateways'][gateway_name]), 200)
        else:
            abort(404,
                  "this isn't the droid you're looking for")
    elif request.method == 'PUT':
        # the parameters need to be cast to str for compatibility
        # with the comparison logic in common.config.add_item
        gateway_ips = str(request.form['gateway_ip_list'])
        target_iqn = str(request.form['target_iqn'])
        target_mode = str(request.form.get('mode', 'target'))

        gateway_ip_list = gateway_ips.split(',')

        gateway = GWTarget(logger,
                           target_iqn,
                           gateway_ip_list)

        if gateway.error:
            logger.error("Unable to create an instance of the GWTarget class")
            abort(418,
                  "Error initialising an instance of GWTarget "
                  "for {}: {}".format(gateway_name,
                                      gateway.error_msg))

        gateway.manage(target_mode)
        if gateway.error:
            logger.error("manage({}) logic failed for {}".format(target_mode,
                                                                 gateway_name))
            abort(418,
                  "Error defining the {} gateway: "
                  "{}".format(gateway_name,
                              gateway.error_msg))

        logger.info("created the gateway")

        if target_mode == 'target':
            # refresh only for target definitions, since that's when the config
            # will actually change
            logger.info("refreshing the configuration after the gateway "
                        "creation")
            config.refresh()

        return make_response(jsonify(
                             {"message": "Gateway defined/mapped"}), 200)
    else:
        # DELETE gateway request
        gateway = GWTarget(logger,
                           config.config['gateways']['iqn'],
                           '')
        if gateway.error:
            abort(418,
                  "Unable to create an instance of GWTarget")

        gateway.manage('clearconfig')
        if gateway.error:
            abort(400,
                  gateway.error_msg)
        else:

            config.refresh()

            return make_response(jsonify(
                {"message": "Gateway removed successfully"}), 200)


@app.route('/api/disks')
@requires_restricted_auth
def get_disks():
    """
    Show the rbd disks defined to the gateways
    """

    disk_names = config.config['disks'].keys()
    response = {"disks": disk_names}

    return make_response(jsonify(response), 200)


@app.route('/api/disk/<image_id>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def manage_disk(image_id):
    """
    Manage a disk definition across the gateways

    Disks can be created and added to each gateway, or deleted through this
    call
    :param image_id: (str) of the form pool.image_name
    :return:
    """

    if request.method == 'GET':

        if image_id in config.config['disks']:
            return make_response(jsonify(config.config["disks"][image_id]),
                                 200)
        else:
            abort(404,
                  "rbd image {} not found".format(image_id))

    elif request.method == 'PUT':
        # A put is for either a create or a resize
        # put('http://127.0.0.1:5000/api/disk/rbd.ansible3',data={'pool': 'rbd','size': '3G','owner':'ceph-1'})

        rqst_fields = set(request.form.keys())
        if rqst_fields.issuperset(("pool", "size", "owner", "mode")):

            image_name = str(image_id.split('.', 1)[1])
            lun = LUN(logger,
                      str(request.form['pool']),
                      image_name,
                      str(request.form['size']),
                      str(request.form['owner']))
            if lun.error:
                logger.error("Unable to create a LUN instance")
                abort(418, lun.error_msg)

            lun.allocate()
            if lun.error:
                logger.error("LUN alloc problem - {}".format(lun.error_msg))
                abort(418,
                      lun.error_msg)


            if request.form['mode'] == 'create':
                # new disk is allocated, so refresh the local config object
                config.refresh()

                iqn = config.config['gateways']['iqn']
                ip_list = config.config['gateways']['ip_list']

                # Add the mapping for the lun to ensure the block device is
                # present on all TPG's
                gateway = GWTarget(logger,
                                   iqn,
                                   ip_list)

                gateway.manage('map')
                if gateway.error:
                    abort(418,
                          "LUN mapping failed - {}".format(gateway.error_msg))

                return make_response(jsonify({"message": "LUN created"}), 200)

            elif request.form['mode'] == 'resize':

                return make_response(jsonify(
                                     {"message": "LUN resized"}), 200)

        else:

            # this is an invalid request
            abort(400,
                  "Invalid Request - need to provide pool, size and owner")

    else:
        # DELETE request
        # let's assume that the request has been validated by the caller

        # if valid_request(request.remote_addr):
        purge_host = request.form['purge_host']

        pool, image = image_id.split('.', 1)

        lun = LUN(logger,
                  pool,
                  image,
                  '0G',
                  purge_host)

        if lun.error:
            # problem defining the LUN instance
            abort(500,
                  "Error initialising the LUN ({})".format(lun.error_msg))

        lun.remove_lun()
        if lun.error:
            if 'allocated to' in lun.error_msg:
                # attempted to remove rbd that is still allocated to a client
                status_code = 400
            else:
                status_code = 500

            abort(status_code,
                  "Error removing the LUN ({})".format(lun.error_msg))

        config.refresh()

        return make_response(jsonify(
                             {"message": "LUN removed".format(lun.error_msg)}), 200)


@app.route('/api/clients')
@requires_restricted_auth
def get_clients():
    """
    List clients defined to the configuration.

    This information will include auth information, hence the
    restricted_auth wrapper
    :return:
    """

    client_list = config.config['clients'].keys()
    response = {"clients": client_list}

    return make_response(jsonify(response), 200)


def _update_client(**kwargs):
    """
    Handler function to apply the changes to a specific client definition
    :param args:
    :return:
    """
    # convert the comma separated image_list string into a list for GWClient
    if kwargs['images']:
        image_list = str(kwargs['images']).split(',')
    else:
        image_list = []

    client = GWClient(logger,
                      kwargs['client_iqn'],
                      image_list,
                      kwargs['chap'])

    if client.error:
        return 500, "GWClient create failed : {}".format(client.error_msg)

    client.manage('present', committer=kwargs['committing_host'])
    if client.error:
        return 500, "Client update failed: {}".format(client.error_msg)
    else:
        config.refresh()
        return 200, "Client configured successfully"


@app.route('/api/clientauth/<client_iqn>', methods=['GET', 'PUT'])
@requires_restricted_auth
def manage_client_auth(client_iqn):
    """
    Manage client authentication credentials

    :param client_iqn: IQN of the client
    :return:
    """

    if request.method == 'GET':
        abort(403)
    else:
        # PUT request to define/change authentication
        image_list = request.form['image_list']
        chap = request.form['chap']
        committing_host = request.form['committing_host']

        status_code, status_text = _update_client(client_iqn=client_iqn,
                                                  images=image_list,
                                                  chap=chap,
                                                  committing_host=committing_host)


        return make_response(jsonify({"message": status_text}), status_code)


@app.route('/api/clientlun/<client_iqn>', methods=['GET', 'PUT'])
@requires_restricted_auth
def manage_client_luns(client_iqn):
    """
    Manage the addition/removal of disks from a client
    """

    if request.method == 'GET':

        if client_iqn in config.config['clients']:
            lun_config = config.config['clients'][client_iqn]['luns']

            return make_response(jsonify({"message": lun_config}), 200)
        else:
            abort(404, "Client does not exist")
    else:
        # PUT request = new/updated disks for this client

        image_list = request.form['image_list']

        chap = request.form['chap']
        committing_host = request.form['committing_host']

        status_code, status_text = _update_client(client_iqn=client_iqn,
                                                  images=image_list,
                                                  chap=chap,
                                                  committing_host=committing_host)

        return make_response(jsonify({"message": status_text}), status_code)


@app.route('/api/client/<client_iqn>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def manage_client(client_iqn):
    """
    Manage a client definition to this node's LIO

    :param client_iqn: iscsi name for the client
    :return:
    """

    if request.method == 'GET':

        if client_iqn in config.config['clients']:
            return make_response(jsonify(
                                 config.config["clients"][client_iqn]), 200)
        else:
            abort(404,
                  "Client '{}' does not exist".format(client_iqn))
    elif request.method == 'PUT':

        try:
            valid_iqn = normalize_wwn(['iqn'], client_iqn)
        except RTSLibError:
            abort(400,
                  "'{}' is not a valid name for iSCSI".format(client_iqn))

        committing_host = request.form['committing_host']

        image_list = request.form.get('image_list', '')

        chap = request.form.get('chap', '')

        status_code, status_text = _update_client(client_iqn=client_iqn,
                                                  images=image_list,
                                                  chap=chap,
                                                  committing_host=committing_host)

        return make_response(jsonify({"message": status_text}), status_code)

    else:
        # DELETE request
        committing_host = request.form['committing_host']

        # Make sure the delete request is for a client we have defined
        if client_iqn in config.config['clients'].keys():
            client = GWClient(logger, client_iqn, '', '')
            client.manage('absent', committer=committing_host)

            if client.error:

                abort(500,
                      client.error_msg)

            else:
                if committing_host == this_host():
                    config.refresh()

                return make_response(jsonify(
                                     {"message": "client deleted"}), 200)
        else:
            abort(404,
                  "Client does not exist")


def pre_reqs_errors():
    """
    function to check pre-req rpms are installed and at the relevant versions
    and also check that multipath.conf and lvm.conf have the required
    changes applied
    :return: list of configuration errors detected
    """

    required_rpms = [
        # {"name": "device-mapper-multipath",
        #  "version": "0.4.9",
        #  "release": "99.el7"},
        {"name": "python-rtslib",
         "version": "2.1.fb57",
         "release": "5.el7"}
    ]

    k_vers = '3.10.0'
    k_rel = '503.el7'

    errors_found = []
    # first check rpm versions are OK
    for rpm in required_rpms:
        if not valid_rpm(rpm):
            logger.error("RPM check for {} failed")
            errors_found.append("{} rpm must be installed at >= "
                                "{}-{}".format(rpm['name'],
                                              rpm['version'],
                                              rpm['release']))


    # check the running kernel is OK (required kernel has patches to rbd.ko)
    os_info = os.uname()
    this_arch = os_info[-1]
    this_kernel = os_info[2].replace(".{}".format(this_arch), '')
    this_ver, this_rel = this_kernel.split('-')

    # use labelCompare from the rpm module to handle the comparison
    if labelCompare(('1', this_ver, this_rel), ('1', k_vers, k_rel)) < 0:
        logger.error("Kernel version check failed")
        errors_found.append("Kernel version too old - {}-{} "
                            "or above needed".format(k_vers,
                                                     k_rel))

    # # now check configuration files have the right settings in place
    # conf = ConfFile('/etc/multipath.conf')
    # if conf.defaults.skip_kpartx != "yes" or \
    #       conf.defaults.user_friendly_names != 'no' or \
    #       conf.defaults.find_multipaths != 'no':
    #     logger.error("/etc/multipath.conf 'defaults' settings are incorrect")
    #     errors_found.append('multipath.conf defaults section is incorrect')
    #
    #
    # conf = ConfFile('/etc/lvm/lvm.conf')
    # if conf.devices.global_filter != '[ "r|^/dev/mapper/[0-255]-.*|" ]':
    #     logger.error("/etc/lvm/lvm.conf global_filter is missing/invalid")
    #     errors_found.append('lvm.conf is missing global_filter settings')

    return errors_found




def halt(message):
    logger.critical(message)
    sys.exit(16)


class ConfigWatcher(threading.Thread):
    """
    A ConfigWatcher checks the epoc attribute of the rados object every 'n'
    seconds to determine if a change has been made. If a change has been made
    the local copy of the config object is refreshed
    """

    def __init__(self, interval=1):
        threading.Thread.__init__(self)
        self.interval = interval
        self.daemon = True

    def run(self):

        logger.info("Started the configuration object watcher")
        logger.info("Checking for changes every {}s".format(self.interval))

        cluster = rados.Rados(conffile=settings.config.cephconf)
        cluster.connect()
        ioctx = cluster.open_ioctx('rbd')
        while True:
            time.sleep(self.interval)

            # look at the internal config object epoch (it could be refreshed
            # within an api call)
            current_epoch = config.config['epoch']

            # get the epoch from the xattr of the config object
            try:
                obj_epoch = int(ioctx.get_xattr('gateway.conf', 'epoch'))
            except rados.ObjectNotFound:
                # daemon is running prior to any config being created or it has
                # skip the error, and
                logger.warning("config object missing, recreating")
                config.refresh()

            else:
                # if it's changed, refresh the local config to ensure a query
                # to this node will return current state
                if obj_epoch != current_epoch:
                    logger.info("Change detected - internal {} / xattr {} "
                                "refreshing".format(current_epoch,
                                                    obj_epoch))
                    config.refresh()

def get_ssl_context():

    # Use these self-signed crt and key files
    cert_files = ['/etc/ceph/iscsi-gateway.crt',
                  '/etc/ceph/iscsi-gateway.key']

    if not all([os.path.exists(crt_file) for crt_file in cert_files]):
        return None

    ver, rel, mod = werkzeug.__version__.split('.')
    if int(rel) > 9:
        logger.info("API server using TLSv1.2")

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(cert_files[0],
                                cert_files[1])

    else:
        logger.info("API server using TLSv1 (older version of werkzeug)")

        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        try:
            context.use_certificate_file(cert_files[0])
            context.use_privatekey_file(cert_files[1])
        except OpenSSL.SSL.Error as err:
            logger.critical("SSL Error : {}".format(err))
            return None

    return context


def main():

    config_watcher = ConfigWatcher()
    config_watcher.start()

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.DEBUG)

    # Attach the werkzeug log to the handlers defined in the outer scope
    log.addHandler(file_handler)
    log.addHandler(syslog_handler)

    if settings.config.api_secure:

        context = get_ssl_context()
        if context is None:
            logger.critical(
                "Secure API requested but the crt/key files "
                "missing/incompatible?")
            logger.critical("Unable to start")
            sys.exit(16)

    else:
        context = None

    # Start the API server
    app.run(host='0.0.0.0',
            port=settings.config.api_port,
            debug=True,
            use_reloader=False,
            ssl_context=context)


def signal_stop(*args):
    logger.info("Shutdown received")
    sys.exit(0)


def signal_reload(*args):
    logger.info("Refreshing local copy of the Gateway configuration")
    config.refresh()


if __name__ == '__main__':

    # Setup signal handlers for interaction with systemd
    signal.signal(signal.SIGTERM, signal_stop)
    signal.signal(signal.SIGHUP, signal_reload)

    # setup syslog handler to help diagnostics
    logger = logging.getLogger('rbd-target-api')
    logger.setLevel(logging.DEBUG)

    # syslog (systemctl/journalctl messages)
    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    syslog_handler.setLevel(logging.INFO)
    syslog_format = logging.Formatter("%(message)s")
    syslog_handler.setFormatter(syslog_format)

    # file target - more verbose logging for diagnostics
    file_handler = logging.FileHandler('/var/log/rbd-target-api.log', mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter("%(asctime)s [%(levelname)8s] - %(message)s")
    file_handler.setFormatter(file_format)

    logger.addHandler(syslog_handler)
    logger.addHandler(file_handler)

    settings.init()

    # config is set in the outer scope, so it's easily accessible to all
    # api functions
    config = Config(logger)
    if config.error:
        logger.error(config.error_msg)
        halt("Unable to open/read the configuration object")
    else:
        main()
