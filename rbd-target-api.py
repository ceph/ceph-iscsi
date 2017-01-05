#!/usr/bin/env python

import sys
import os
import signal
import logging
import logging.handlers
from OpenSSL import SSL
import threading
import time
from rpm import labelCompare

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.gateway import GWTarget
from ceph_iscsi_config.lun import LUN
from ceph_iscsi_config.client import GWClient
from ceph_iscsi_config.common import Config
# from ceph_iscsi_config.lio import LIO, Gateway
from ceph_iscsi_config.utils import (get_ip, this_host, ipv4_addresses,
                                     gen_file_hash, valid_rpm,
                                     ConfFile)

# from rtslib_fb import root
from rtslib_fb.utils import RTSLibError, normalize_wwn

from functools import wraps

# requires - python-flask-restful
# flask is in RHEL7 repos
from flask import Flask, jsonify, make_response, request, abort

# flask_restful is NOT! Install with pip from EPEL
# (i.e. yum install python-pip && pip install flask-restful)
from flask_restful import Resource, Api

import rados


def requires_basic_auth(f):
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


class APISysInfo(Resource):

    @requires_basic_auth
    def get(self, query_type):

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


class APITarget(Resource):

    @requires_restricted_auth
    def put(self, target_iqn):

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


class APIGatewayConfig(Resource):

    @requires_restricted_auth
    def get(self):

        return make_response(jsonify(config.config), 200)


class APIGateways(Resource):
    @requires_restricted_auth
    def get(self):
        return make_response(jsonify(config.config['gateways']), 200)


class APIGateway(Resource):
    @requires_restricted_auth
    def get(self, gateway_name):

        if gateway_name in config.config['gateways']:

            return make_response(jsonify(
                                 config.config['gateways'][gateway_name]), 200)
        else:
            abort(404,
                  "this isn't the droid you're looking for")

    @requires_restricted_auth
    def put(self, gateway_name):

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

    @requires_restricted_auth
    def delete(self, gateway_name):

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


class APIDisks(Resource):
    @requires_restricted_auth
    def get(self):
        # if valid_request(request.remote_addr):
        disk_names = config.config['disks'].keys()
        response = {"disks": disk_names}

        return make_response(jsonify(response), 200)



class APIDisk(Resource):

    @requires_restricted_auth
    def delete(self, image_id):

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

    @requires_restricted_auth
    def get(self, image_id):


        if image_id in config.config['disks']:
            return make_response(jsonify(config.config["disks"][image_id]), 200)
        else:
            abort(404,
                  "rbd image {} not found in the configuration".format(image_id))


    @requires_restricted_auth
    def put(self, image_id):
        # A put is for either a create or a resize
        # put('http://127.0.0.1:5000/api/disk/rbd.ansible3',data={'pool': 'rbd','size': '3G','owner':'ceph-1'})

        # FIXME - MUST have a gateway before luns can be created
        # the gateway must exist, since the workflow for mapping a lun will
        # map the lun to TPG's and perform alua setup

        # if valid_request(request.remote_addr):

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
                logger.error("LUN allocation problem - {}".format(lun.error_msg))
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


class APIClients(Resource):
    @requires_restricted_auth
    def get(self):
        # if valid_request(request.remote_addr):
        client_list = config.config['clients'].keys()
        response = {"clients": client_list}

        return make_response(jsonify(response), 200)


class APIClientHandler(Resource):
    def update(self, client_iqn, images, chap, committing_host):

        # convert the comma separated image_list string into a list for GWClient
        if images:
            image_list = str(images).split(',')
        else:
            image_list = []

        client = GWClient(logger, client_iqn, image_list, chap)

        if client.error:
            return 500, "GWClient create failed : {}".format(client.error_msg)

        client.manage('present', committer=committing_host)
        if client.error:
            return 500, "Client update failed: {}".format(client.error_msg)
        else:
            config.refresh()
            return 200, "Client configured successfully"


class APIClientAuth(APIClientHandler):
    @requires_restricted_auth
    def get(self, client_iqn):

        abort(403)


    @requires_restricted_auth
    def put(self, client_iqn):
        """
        Handle auth request
        """

        image_list = request.form['image_list']
        chap = request.form['chap']
        committing_host = request.form['committing_host']

        status_code, status_text = self.update(client_iqn,
                                               image_list,
                                               chap,
                                               committing_host)

        return make_response(jsonify({"message": status_text}), status_code)

    @requires_restricted_auth
    def delete(self, client_iqn):
        abort(405)


class APIClientLUN(APIClientHandler):

    @requires_restricted_auth
    def get(self, client_iqn):
        """
        return the LUNs allocated to this client, straight from the config
        object
        """

        disk = request.form['disk']
        if client_iqn in config.config['clients']:
            lun_config = config.config['clients'][client_iqn]['luns']

            return make_response(jsonify({"message": lun_config}), 200)
        else:
            abort(404, "client does not exist")

    @requires_restricted_auth
    def put(self, client_iqn):
        """
        handle the addition or removal of a lun for a given client
        the image_list provided is used by the GWClient code to determine the
        action to take rather than any specific logic here
        """

        # convert the comma separated image_list string into a list for GWClient
        image_list = request.form['image_list']

        chap = request.form['chap']
        committing_host = request.form['committing_host']

        status_code, status_text = self.update(client_iqn,
                                               image_list,
                                               chap,
                                               committing_host)

        return make_response(jsonify({"message": status_text}), status_code)


class APIClient(APIClientHandler):
    '''
    Handle the definition of a client to the local LIO instance
    '''

    @requires_restricted_auth
    def get(self, client_iqn):

        if client_iqn in config.config['clients']:
            return make_response(jsonify(
                                 config.config["clients"][client_iqn]), 200)
        else:
            abort(404,
                  "Client '{}' does not exist".format(client_iqn))

    @requires_restricted_auth
    def put(self, client_iqn):
        """
        The put request needs the client_iqn as a minimum to get
        the client defined. However, image_list and chap can also
        be provided to define the client fully in one pass
        """

        try:
            valid_iqn = normalize_wwn(['iqn'], client_iqn)
        except RTSLibError:
            abort(400,
                  "'{}' is not a valid name for iSCSI".format(client_iqn))

        committing_host = request.form['committing_host']

        image_list = request.form.get('image_list', '')

        chap = request.form.get('chap', '')

        status_code, status_text = self.update(client_iqn,
                                               image_list,
                                               chap,
                                               committing_host)

        return make_response(jsonify({"message": status_text}), status_code)

    @requires_restricted_auth
    def delete(self, client_iqn):

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
            abort(405,
                  "Invalid Request - client does not exist")


def pre_reqs_errors():
    """
    function to check pre-req rpms are installed and at the relevant versions
    and also check that multipath.conf and lvm.conf have the required
    changes applied
    :return: list of configuration errors detected
    """

    required_rpms = [
        {"name": "device-mapper-multipath",
         "version": "0.4.9",
         "release": "99.el7"},
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

    # now check configuration files have the right settings in place
    conf = ConfFile('/etc/multipath.conf')
    if conf.defaults.skip_kpartx != "yes" or \
          conf.defaults.user_friendly_names != 'no' or \
          conf.defaults.find_multipaths != 'no':
        logger.error("/etc/multipath.conf 'defaults' settings are incorrect")
        errors_found.append('multipath.conf defaults section is incorrect')


    conf = ConfFile('/etc/lvm/lvm.conf')
    if conf.devices.global_filter != '[ "r|^/dev/mapper/[0-255]-.*|" ]':
        logger.error("/etc/lvm/lvm.conf global_filter is missing/invalid")
        errors_found.append('lvm.conf is missing global_filter settings')

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


def main():

    config_watcher = ConfigWatcher()
    config_watcher.start()

    app = Flask(__name__)
    api = Api(app)

    api.add_resource(APIGatewayConfig, '/api/config')
    api.add_resource(APIGateways, '/api/gateways')
    api.add_resource(APIGateway, '/api/gateway/<gateway_name>')
    api.add_resource(APIDisks, '/api/disks')
    api.add_resource(APIDisk, '/api/disk/<image_id>')
    api.add_resource(APIClients, '/api/clients')
    api.add_resource(APIClient, '/api/client/<client_iqn>')
    api.add_resource(APIClientAuth, '/api/clientauth/<client_iqn>')
    api.add_resource(APIClientLUN, '/api/clientlun/<client_iqn>')
    api.add_resource(APITarget, '/api/target/<target_iqn>')
    api.add_resource(APISysInfo, '/api/sysinfo/<query_type>')

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.DEBUG)

    # Attach the werkzeug log to the handlers defined in the outer scope
    log.addHandler(file_handler)
    log.addHandler(syslog_handler)

    if settings.config.api_secure:

        # FIXME - ideally this should be TLSv1_2 !
        context = SSL.Context(SSL.TLSv1_METHOD)

        # Use these self-signed crt and key files
        context.use_privatekey_file('/etc/ceph/iscsi-gateway.key')
        context.use_certificate_file('/etc/ceph/iscsi-gateway.crt')

        # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # context.load_cert_chain('/etc/ceph/iscsi-gateway.crt',
        # '/etc/ceph/iscsi-gateway.key')

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


if __name__ == '__main__':

    # Setup signal handlers for interaction with systemd
    signal.signal(signal.SIGTERM, signal_stop)
    # signal.signal(signal.SIGHUP, signal_reload)

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

    # config is set in the outer scope, so it's easily accessible to the
    # api classes
    config = Config(logger)
    if config.error:
        halt("Unable to open/read the configuration object")
    else:
        main()
