#!/usr/bin/env python

import sys
import os
import signal
import json
import logging
import logging.handlers
from logging.handlers import RotatingFileHandler
import ssl
import operator
import OpenSSL
import threading
import time
import inspect
import copy

from functools import (reduce, wraps)
from rpm import labelCompare
import rados
import rbd

import werkzeug
from flask import Flask, jsonify, request
from rtslib_fb.utils import RTSLibError, normalize_wwn

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.gateway import CephiSCSIGateway
from ceph_iscsi_config.discovery import Discovery
from ceph_iscsi_config.target import GWTarget
from ceph_iscsi_config.group import Group
from ceph_iscsi_config.lun import RBDDev, LUN
from ceph_iscsi_config.client import GWClient, CHAP
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.utils import (normalize_ip_literal, resolve_ip_addresses,
                                     ip_addresses, read_os_release,
                                     format_lio_yes_no, CephiSCSIError, this_host)

from gwcli.utils import (APIRequest, valid_gateway, valid_client,
                         valid_credentials, get_remote_gateways, valid_snapshot_name,
                         GatewayAPIError)

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
            return jsonify(message="Missing credentials"), 401

        if auth.username != settings.config.api_user or \
           auth.password != settings.config.api_password:
            return jsonify(message="username/password mismatch with the "
                                   "configuration file"), 401

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
        gw_names = [gw for gw in config.config['gateways']
                    if isinstance(config.config['gateways'][gw], dict)]
        gw_names.append('localhost')
        for _, target in config.config['targets'].items():
            gw_names += target.get('ip_list', [])
        gw_ips = reduce(operator.concat,
                        [resolve_ip_addresses(gw_name) for gw_name in gw_names]) + \
            settings.config.trusted_ip_list

        # remove interface scope suffix and IPv4-over-IPv6 prefix
        remote_addr = request.remote_addr.rsplit('%', 1)[0]
        remote_addr = remote_addr.split('::ffff:', 1)[-1]

        if remote_addr not in gw_ips:
            return jsonify(message="API access not available to "
                                   "{}".format(remote_addr)), 403

        # check credentials supplied in the http request are valid
        auth = request.authorization
        if not auth:
            return jsonify(message="Missing credentials"), 401

        if auth.username != settings.config.api_user or \
           auth.password != settings.config.api_password:
            return jsonify(message="username/password mismatch with the "
                                   "configuration file"), 401

        return f(*args, **kwargs)

    return decorated


@app.errorhandler(Exception)
def unhandled_exception(e):
    logger.exception("Unhandled Exception")
    return jsonify(message="Unhandled exception: {}".format(e)), 500


@app.route('/api', methods=['GET'])
def get_api_info():
    """
    Display all the available API endpoints
    **UNRESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET http://192.168.122.69:5000/api
    """

    links = []
    sorted_rules = sorted(app.url_map.iter_rules(),
                          key=lambda x: x.rule, reverse=False)

    for rule in sorted_rules:
        url = rule.rule
        if rule.endpoint == 'static':
            continue
        else:
            func_doc = inspect.getdoc(globals()[rule.endpoint])
            if func_doc:

                doc = func_doc.split('\n')

                if any(path_entry.startswith('_')
                       for path_entry in url.split('/')):
                    continue

                else:
                    url_desc = "{} : {}".format(url,
                                                doc[0])
                    doc = doc[1:]

            else:
                url_desc = "{} : {}".format(url,
                                            "Missing description - FIXME!")
                doc = []

        callable_methods = [method for method in rule.methods
                            if method not in ['OPTIONS', 'HEAD']]
        api_methods = "Methods: {}".format(','.join(callable_methods))

        links.append((url_desc, api_methods, doc))

    return jsonify(api=links), 200


@app.route('/api/sysinfo/<query_type>', methods=['GET'])
@requires_basic_auth
def get_sys_info(query_type=None):
    """
    Provide system information based on the query_type
    Valid query types are: ip_addresses, checkconf and checkversions
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET http://192.168.122.69:5000/api/sysinfo/ip_addresses
    """

    if query_type == 'ip_addresses':

        return jsonify(data=ip_addresses()), 200

    if query_type == 'hostname':

        return jsonify(data=this_host()), 200

    elif query_type == 'checkconf':

        local_hash = settings.config.hash()
        return jsonify(data=local_hash), 200

    elif query_type == 'checkversions':

        config_errors = pre_reqs_errors()
        if config_errors:
            return jsonify(data=config_errors), 500
        else:
            return jsonify(data='checks passed'), 200

    else:
        # Request Unknown
        return jsonify(message="Unknown /sysinfo query"), 404


def _parse_controls(controls_json, settings_list):
    return settings.Settings.normalize_controls(json.loads(controls_json),
                                                settings_list)


def parse_target_controls(request):
    tpg_controls = {}
    client_controls = {}

    if 'controls' not in request.form:
        return tpg_controls, client_controls

    controls = _parse_controls(request.form['controls'], GWTarget.SETTINGS)
    for k, v in controls.items():
        if k in GWClient.SETTINGS:
            client_controls[k] = v
        else:
            tpg_controls[k] = v

    logger.debug("controls tpg {} acl {}".format(tpg_controls, client_controls))
    return tpg_controls, client_controls


@app.route('/api/targets', methods=['GET'])
@requires_restricted_auth
def get_targets():
    """
    List targets defined in the configuration.
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET https://192.168.122.69:5000/api/targets
    """

    return jsonify({'targets': config.config['targets'].keys()}), 200


@app.route('/api/target/<target_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def target(target_iqn=None):
    """
    Handle the definition of the iscsi target name
    The target is added to the configuration object, seeding the configuration
    for ALL gateways
    :param target_iqn: IQN of the target each gateway will use
    :param mode: (str) 'reconfigure'
    :param controls: (JSON dict) valid control overrides
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin
        -X PUT http://192.168.122.69:5000/api/target/iqn.2003-01.com.redhat.iscsi-gw0
    curl --insecure --user admin:admin -d mode=reconfigure -d controls='{cmdsn_depth=128}'
        -X PUT http://192.168.122.69:5000/api/target/iqn.2003-01.com.redhat.iscsi-gw0
    """

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    if request.method == 'PUT':
        mode = request.form.get('mode', None)
        if mode not in [None, 'reconfigure']:
            logger.error("Unexpected mode provided")
            return jsonify(message="Unexpected mode provided for {} - "
                                   "{}".format(target_iqn, mode)), 500

        try:
            tpg_controls, client_controls = parse_target_controls(request)
        except ValueError as err:
            logger.error("Unexpected or invalid controls")
            return jsonify(message="Unexpected or invalid controls - "
                                   "{}".format(err)), 500

        if mode == 'reconfigure':
            target_config = config.config['targets'].get(target_iqn, None)
            if target_config is None:
                return jsonify(message="Target: {} is not defined."
                                       "".format(target_iqn)), 400

            if client_controls and not target_config['clients']:
                return jsonify(message="No clients found. Create clients then "
                                       "rerun reconfigure command."), 400

        gateway_ip_list = []
        target = GWTarget(logger,
                          str(target_iqn),
                          gateway_ip_list)

        if target.error:
            logger.error("Unable to create an instance of the GWTarget class")
            return jsonify(message="GWTarget problem - "
                                   "{}".format(target.error_msg)), 500

        orig_tpg_controls = {}
        orig_client_controls = {}
        for k, v in tpg_controls.items():
            orig_tpg_controls[k] = getattr(target, k)
            setattr(target, k, v)

        for k, v in client_controls.items():
            orig_client_controls[k] = getattr(target, k)
            setattr(target, k, v)

        target.manage('init')
        if target.error:
            logger.error("Failure during gateway 'init' processing")
            return jsonify(message="iscsi target 'init' process failed "
                                   "for {} - {}".format(target_iqn,
                                                        target.error_msg)), 500

        if mode is None:
            config.refresh()
            return jsonify(message="Target defined successfully"), 200

        if not tpg_controls and not client_controls:
            return jsonify(message="Target reconfigured."), 200

        # This is a reconfigure operation, so first confirm the gateways
        # are in place (we need defined gateways)
        target_config = config.config['targets'][target_iqn]
        try:
            gateways = get_remote_gateways(target_config['portals'], logger)
        except CephiSCSIError as err:
            logger.warning("target operation request failed: {}".format(err))
            return jsonify(message="{}".format(err)), 400

        # We perform the reconfigure locally here to make sure the values are valid
        # and simplify error cleanup
        resp_text = local_target_reconfigure(target_iqn, tpg_controls,
                                             client_controls)
        if "ok" != resp_text:
            reset_resp = local_target_reconfigure(target_iqn, orig_tpg_controls,
                                                  orig_client_controls)
            if "ok" != reset_resp:
                logger.error("Failed to reset target controls - "
                             "{}".format(reset_resp))

            return jsonify(message="{}".format(resp_text)), 500

        resp_text, resp_code = call_api(gateways, '_target', target_iqn,
                                        http_method='put',
                                        api_vars=request.form)
        if resp_code != 200:
            return jsonify(message="{}".format(resp_text)), resp_code

        try:
            target.commit_controls()
        except CephiSCSIError as err:
            logger.error("Control commit failed during gateway 'reconfigure'")
            return jsonify(message="Could not commit controls - {}".format(err)), 500
        config.refresh()
        return jsonify(message="Target reconfigured."), 200

    else:
        # DELETE target request
        config.refresh()
        hostnames = None
        if target_iqn in config.config['targets']:
            target_config = config.config['targets'][target_iqn]
            hostnames = target_config['portals'].keys()
        if not hostnames:
            hostnames = [this_host()]
        resp_text, resp_code = call_api(hostnames, '_target',
                                        '{}'.format(target_iqn),
                                        http_method='delete')
        if resp_code != 200:
            return jsonify(message="{}".format(resp_text)), resp_code
        return jsonify(message="Target deleted."), 200


def local_target_reconfigure(target_iqn, tpg_controls, client_controls):
    config.refresh()

    target = GWTarget(logger, str(target_iqn), [])
    if target.error:
        logger.error("Unable to create an instance of the GWTarget class")
        return target.error_msg

    for k, v in tpg_controls.items():
        setattr(target, k, v)

    if target.exists():
        target.load_config()
        if target.error:
            logger.error("Unable to refresh tpg state")
            return target.error_msg

    try:
        target.update_tpg_controls()
    except RTSLibError as err:
        logger.error("Unable to update tpg control - {}".format(err))
        return "Unable to update tpg control - {}".format(err)

    # re-apply client control overrides
    error_msg = "ok"
    target_config = config.config['targets'][target_iqn]
    for client_iqn in target_config['clients']:
        client_metadata = target_config['clients'][client_iqn]
        image_list = list(client_metadata['luns'].keys())
        client_auth_config = client_metadata['auth']
        client_chap = CHAP(client_auth_config['username'],
                           client_auth_config['password'],
                           client_auth_config['password_encryption_enabled'])
        if client_chap.error:
            logger.debug("Password decode issue : "
                         "{}".format(client_chap.error_msg))
            halt("Unable to decode password for {}".format(client_iqn))

        client_chap_mutual = CHAP(client_auth_config['mutual_username'],
                                  client_auth_config['mutual_password'],
                                  client_auth_config['mutual_password_encryption_enabled'])
        if client_chap_mutual.error:
            logger.debug("Password decode issue : "
                         "{}".format(client_chap_mutual.error_msg))
            halt("Unable to decode password for {}".format(client_iqn))

        client = GWClient(logger, client_iqn, image_list, client_chap.user, client_chap.password,
                          client_chap_mutual.user, client_chap_mutual.password, target_iqn)
        if client.error:
            logger.error("Could not create client. Control override failed "
                         "{} - {}".format(client_iqn, client.error_msg))
            error_msg = client.error_msg
            continue

        for k, v in client_controls.items():
            setattr(client, k, v)

        client.manage('reconfigure')
        if client.error:
            logger.error("Unable to update client control - "
                         "{} - {}".format(client_iqn, client.error_msg))
            error_msg = client.error_msg
            if "Invalid argument" in client.error_msg:
                # Kernel/rtslib reported EINVAL so immediately fail
                return client.error_msg
    if error_msg != "ok":
        return "Unable to update client control - {}".format(error_msg)

    return "ok"


def delete_gateway(gateway_name, target_iqn):
    ceph_gw = CephiSCSIGateway(logger, config)

    if gateway_name is None or gateway_name == ceph_gw.hostname:
        ceph_gw.delete_target(target_iqn)
        ceph_gw.remove_from_config(target_iqn)
    else:
        # To maintain the tpg ordering completely tear down the target
        # and rebuild it with the new ordering.
        ceph_gw.redefine_target(target_iqn)


@app.route('/api/_target/<target_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def _target(target_iqn=None):
    if request.method == 'PUT':
        mode = request.form.get('mode', None)
        if mode not in ['reconfigure']:
            logger.error("Unexpected mode provided")
            return jsonify(message="Unexpected mode provided for {} - "
                                   "{}".format(target_iqn, mode)), 500
        try:
            tpg_controls, client_controls = parse_target_controls(request)
        except ValueError as err:
            logger.error("Unexpected or invalid controls")
            return jsonify(message="Unexpected or invalid controls - "
                                   "{}".format(err)), 500

        resp_text = local_target_reconfigure(target_iqn, tpg_controls,
                                             client_controls)
        if "ok" != resp_text:
            return jsonify(message="{}".format(resp_text)), 500

        return jsonify(message="Target reconfigured successfully"), 200

    else:
        # DELETE target request
        target = GWTarget(logger, target_iqn, '')
        if target.error:
            return jsonify(message="Failed to access target"), 500

        target.manage('clearconfig')
        if target.error:
            logger.error("clearconfig failed: "
                         "{}".format(target.error_msg))
            return jsonify(message=target.error_msg), 400

        else:

            config.refresh()
            return jsonify(message="Gateway removed successfully"), 200


@app.route('/api/config', methods=['GET'])
@requires_restricted_auth
def get_config():
    """
    Return the complete config object to the caller (must be authenticated)
    WARNING: Contents will include any defined CHAP credentials
    :param decrypt_passwords: (bool) if true, passwords will be decrypted
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET http://192.168.122.69:5000/api/config
    """

    if request.method == 'GET':
        config.refresh()
        decrypt_passwords = request.args.get('decrypt_passwords', 'false')
        result_config = copy.deepcopy(config.config)

        if decrypt_passwords.lower() == 'true':
            discovery_auth_config = result_config['discovery_auth']
            chap = CHAP(discovery_auth_config['username'],
                        discovery_auth_config['password'],
                        discovery_auth_config['password_encryption_enabled'])
            discovery_auth_config['password'] = chap.password
            chap = CHAP(discovery_auth_config['mutual_username'],
                        discovery_auth_config['mutual_password'],
                        discovery_auth_config['mutual_password_encryption_enabled'])
            discovery_auth_config['mutual_password'] = chap.password
            for _, target in result_config['targets'].items():
                for _, client in target['clients'].items():
                    auth_config = client['auth']
                    chap = CHAP(auth_config['username'],
                                auth_config['password'],
                                auth_config['password_encryption_enabled'])
                    auth_config['password'] = chap.password
                    chap = CHAP(auth_config['mutual_username'],
                                auth_config['mutual_password'],
                                auth_config['mutual_password_encryption_enabled'])
                    auth_config['mutual_password'] = chap.password

        return jsonify(result_config), 200


@app.route('/api/gateways/<target_iqn>', methods=['GET'])
@requires_restricted_auth
def gateways(target_iqn=None):
    """
    Return the gateway subsection of the config object to the caller
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET
        http://192.168.122.69:5000/api/gateways/iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw
    """

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    target_config = config.config['targets'][target_iqn]
    if request.method == 'GET':
        return jsonify(target_config['portals']), 200


@app.route('/api/gateway/<target_iqn>/<gateway_name>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def gateway(target_iqn=None, gateway_name=None):
    """
    Define (PUT) or delete (DELETE) iscsi gateway(s) across node(s), adding
    TPGs, disks and clients.
    gateway_name and target_iqn are required by all calls. The rest are
    required for PUT only.
    :param target_iqn: (str) target iqn
    :param gateway_name: (str) gateway name
    :param ip_address: (str) IPv4/IPv6 addresses iSCSI should use
    :param nosync: (bool) whether to sync the LIO objects to the new gateway
           default: FALSE
    :param skipchecks: (bool) whether to skip OS/software versions checks
           default: FALSE
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -d ip_address=192.168.122.69
        -X PUT http://192.168.122.69:5000/api/gateway/iscsi-gw0
    """

    # the definition of a gateway into an existing configuration can apply the
    # running config to the new host. The downside is that this sync task
    # could take a while if there are 100's of disks/clients. Future work should
    # aim to make this synchronisation of the new gateway an async task

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    # first confirm that the request is actually valid, if not return a 400
    # error with the error description
    config.refresh()
    current_config = config.config
    target_config = config.config['targets'][target_iqn]

    if request.method == 'PUT':
        if gateway_name in target_config['portals']:
            err_str = "Gateway already exists in configuration"
            logger.error(err_str)
            return jsonify(message=err_str), 400
        ip_address = request.form.get('ip_address').split(',')
        nosync = request.form.get('nosync', 'false')
        skipchecks = request.form.get('skipchecks', 'false')

        if skipchecks.lower() == 'true':
            logger.warning("Gateway request received, with validity checks "
                           "disabled")
            gateway_usable = 'ok'
        else:
            logger.info("gateway validation needed for {}".format(gateway_name))
            gateway_usable = valid_gateway(target_iqn,
                                           gateway_name,
                                           ip_address,
                                           current_config)

        if gateway_usable != 'ok':
            return jsonify(message=gateway_usable), 400

        current_disks = target_config['disks']
        current_clients = target_config['clients']

        total_objects = len(current_disks) + len(current_clients.keys())

        # if the config is empty, it doesn't matter what nosync is set to
        if total_objects == 0:
            nosync = 'true'

        gateway_ip_list = target_config.get('ip_list', [])
        gateway_ip_list += ip_address

        op = 'creation'
        api_vars = {"gateway_ip_list": ",".join(gateway_ip_list),
                    "nosync": nosync}
    elif request.method == 'DELETE':
        if gateway_name not in current_config['gateways']:
            err_str = "Gateway does not exist in configuration"
            logger.error(err_str)
            return jsonify(message=err_str), 404

        op = 'deletion'
        api_vars = None
    else:
        return jsonify(message="Unsupported request type."), 400

    gateways = list(target_config['portals'].keys())
    first_gateway = (len(gateways) == 0)
    if first_gateway:
        gateways = ['localhost']
    elif request.method == 'DELETE':
        # Update the deleted gw first, so the other gws see the updated
        # portal list
        gateways.remove(gateway_name)
        gateways.insert(0, gateway_name)
    else:
        # Update the new gw first, so other gws see the updated gateways list.
        gateways.insert(0, gateway_name)

    resp_text, resp_code = call_api(gateways, '_gateway',
                                    '{}/{}'.format(target_iqn, gateway_name),
                                    http_method=request.method.lower(),
                                    api_vars=api_vars)
    config.refresh()

    return jsonify(message="Gateway {} {}".format(op, resp_text)), resp_code


@app.route('/api/_gateway/<target_iqn>/<gateway_name>',
           methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def _gateway(target_iqn=None, gateway_name=None):
    """
    Manage the local iSCSI gateway definition
    Internal Use ONLY
    Gateways may be be added(PUT), queried (GET) or deleted (DELETE) from
    the configuration
    :param target_iqn: (str) target iqn
    :param gateway_name: (str) gateway name, normally the DNS name
    **RESTRICTED**
    """
    config.refresh()
    target_config = config.config['targets'][target_iqn]

    if request.method == 'GET':

        if gateway_name in target_config['portals']:

            return jsonify(target_config['portals'][gateway_name]), 200
        else:
            return jsonify(message="Gateway doesn't exist in the "
                                   "configuration"), 404

    elif request.method == 'DELETE':
        try:
            delete_gateway(gateway_name, target_iqn)
        except CephiSCSIError as err:
            return jsonify(message="Gateway deletion failed: {}.".format(err)), 400

        return jsonify(message="Gateway deleted."), 200
    elif request.method == 'PUT':
        # the parameters need to be cast to str for compatibility
        # with the comparison logic in common.config.add_item
        logger.debug("Attempting create of gateway {}".format(gateway_name))

        gateway_ips = str(request.form['gateway_ip_list'])
        nosync = str(request.form.get('nosync', 'false'))

        gateway_ip_list = gateway_ips.split(',')

        target_only = False
        if nosync.lower() == 'true':
            target_only = True

        try:
            ceph_gw = CephiSCSIGateway(logger, config)
            ceph_gw.define_target(target_iqn, gateway_ip_list, target_only)
        except CephiSCSIError as err:
            err_msg = "Could not create target on gateway: {}".format(err)
            logger.error(err_msg)
            return jsonify(message=err_msg), 500

        return jsonify(message="Gateway defined/mapped"), 200


@app.route('/api/targetlun/<target_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def target_disk(target_iqn=None):
    """
    Coordinate the addition(PUT) and removal(DELETE) of a disk for a target
    :param target_iqn: (str) IQN of the target
    :param disk: (str) rbd image name on the format pool/image
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -d disk=rbd.new2_1
        -X PUT https://192.168.122.69:5000/api/targetlun/iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw
    """

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    target_config = config.config['targets'][target_iqn]

    portals = [key for key in target_config['portals']]
    # Any disk operation needs at least 2 gateways to be present
    if len(portals) < settings.config.minimum_gateways:
        msg = "at least {} gateways must exist before disk mapping operations " \
              "are permitted".format(settings.config.minimum_gateways)
        logger.warning("disk add request failed: {}".format(msg))
        return jsonify(message=msg), 400

    try:
        gateways = get_remote_gateways(target_config['portals'], logger)
    except CephiSCSIError as err:
        return jsonify(message="{}".format(err)), 400
    local_gw = this_host()
    disk = request.form.get('disk')

    if request.method == 'PUT':

        if disk not in config.config['disks']:
            return jsonify(message="Disk {} is not defined in the configuration".format(disk)), 400

        for iqn, target in config.config['targets'].items():
            if disk in target['disks']:
                return jsonify(message="Disk {} cannot be used because it is already mapped on "
                                       "target {}".format(disk, iqn)), 400

        pool, image_name = disk.split('/')
        try:
            backstore = config.config['disks'][disk]
            rbd_image = RBDDev(image_name, 0, backstore, pool)
            size = rbd_image.current_size
            logger.debug("{} size is {}".format(disk, size))
        except rbd.ImageNotFound:
            return jsonify(message="Image {} not found".format(disk)), 400

        owner = LUN.get_owner(config.config['gateways'], target_config['portals'])
        logger.debug("{} owner will be {}".format(disk, owner))

        api_vars = {
            'disk': disk,
            'owner': owner,
            'allocating_host': local_gw
        }
        # process local gateway first
        gateways.insert(0, local_gw)
        resp_text, resp_code = call_api(gateways, '_targetlun',
                                        '{}'.format(target_iqn),
                                        http_method='put',
                                        api_vars=api_vars)
        if resp_code != 200:
            return jsonify(message="Add target LUN mapping failed - "
                                   "{}".format(resp_text)), resp_code

    else:
        # this is a DELETE request

        if disk not in config.config['disks']:
            return jsonify(message="Disk {} is not defined in the "
                                   "configuration".format(disk)), 400

        if disk not in target_config['disks']:
            return jsonify(message="Disk {} is not defined in target "
                                   "{}".format(disk, target_iqn)), 400

        for group_name, group in target_config['groups'].items():
            if disk in group['disks']:
                return jsonify(message="Disk {} belongs to group "
                                       "{}".format(disk, group_name)), 400

        api_vars = {
            'disk': disk,
            'purge_host': local_gw
        }
        # process other gateways first
        gateways.append(local_gw)
        resp_text, resp_code = call_api(gateways, '_targetlun',
                                        '{}'.format(target_iqn),
                                        http_method='delete',
                                        api_vars=api_vars)
        if resp_code != 200:
            return jsonify(message="Delete target LUN mapping failed - "
                                   "{}".format(resp_text)), resp_code

    return jsonify(message="Target LUN mapping updated successfully"), 200


@app.route('/api/_targetlun/<target_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def _target_disk(target_iqn=None):
    """
    Manage the addition/removal of disks from a target on the local gateway
    Internal Use ONLY
    **RESTRICTED**
    """

    config.refresh()

    disk = request.form.get('disk')
    pool, image = disk.split('/', 1)
    disk_config = config.config['disks'][disk]
    backstore = disk_config['backstore']
    backstore_object_name = disk_config['backstore_object_name']

    if request.method == 'PUT':
        target_config = config.config['targets'][target_iqn]
        ip_list = target_config.get('ip_list', [])
        gateway = GWTarget(logger,
                           target_iqn,
                           ip_list)

        if gateway.error:
            logger.error("LUN mapping failed : "
                         "{}".format(gateway.error_msg))
            return jsonify(message="LUN map failed"), 500

        owner = request.form.get('owner')
        allocating_host = request.form.get('allocating_host')

        rbd_image = RBDDev(image, 0, backstore, pool)
        size = rbd_image.current_size
        lun = LUN(logger,
                  pool,
                  image,
                  size,
                  allocating_host,
                  backstore,
                  backstore_object_name)

        if lun.error:
            logger.error("Error initializing the LUN : "
                         "{}".format(lun.error_msg))
            return jsonify(message="Error establishing LUN instance"), 500

        try:
            lun.map_lun(gateway, owner, disk)
        except CephiSCSIError as err:
            status_code = 400 if str(err) else 500
            logger.error("LUN add failed : {}".format(err))
            return jsonify(message="Failed to add the LUN - "
                                   "{}".format(err)), status_code
    else:
        # DELETE gateway request

        purge_host = request.form['purge_host']
        logger.debug("delete request for disk image '{}'".format(disk))

        lun = LUN(logger,
                  pool,
                  image,
                  0,
                  purge_host,
                  backstore,
                  backstore_object_name)

        if lun.error:
            logger.error("Error initializing the LUN : "
                         "{}".format(lun.error_msg))
            return jsonify(message="Error establishing LUN instance"), 500

        lun.unmap_lun(target_iqn)
        if lun.error:
            status_code = 400 if lun.error_msg else 500
            logger.error("LUN remove failed : {}".format(lun.error_msg))
            return jsonify(message="Failed to remove the LUN - "
                                   "{}".format(lun.error_msg)), status_code

    config.refresh()

    return jsonify(message="LUN mapped"), 200


@app.route('/api/disks')
@requires_restricted_auth
def get_disks():
    """
    Show the rbd disks defined to the gateways
    :param config: (str) 'yes' to list the config info of all disks, default is 'no'
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -d config=yes -X GET https://192.168.122.69:5000/api/disks
    """

    conf = request.form.get('config', 'no')
    if conf.lower() == "yes":
        disk_names = config.config['disks']
        response = {"disks": disk_names}
    else:
        disk_names = config.config['disks'].keys()
        response = {"disks": disk_names}

    return jsonify(response), 200


@app.route('/api/disk/<pool>/<image>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def disk(pool, image):
    """
    Coordinate the create/delete of rbd images across the gateway nodes
    This method calls the corresponding disk api entrypoints across each
    gateway. Processing is done serially: creation is done locally first,
    then other gateways - whereas, rbd deletion is performed first against
    remote gateways and then the local machine is used to perform the actual
    rbd delete.

    :param pool: (str) pool name
    :param image: (str) rbd image name
    :param mode: (str) 'create' or 'resize' the rbd image
    :param size: (str) the size of the rbd image
    :param pool: (str) the pool name the rbd image will be in
    :param count: (str) the number of images will be created
    :param owner: (str) the owner of the rbd image
    :param controls: (JSON dict) valid control overrides
    :param preserve_image: (bool) do NOT delete RBD image
    :param create_image: (bool) create RBD image if not exists
    :param backstore: (str) lio backstore
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -d mode=create -d size=1g -d pool=rbd -d count=5
        -X PUT https://192.168.122.69:5000/api/disk/rbd.new2_
    curl --insecure --user admin:admin -d mode=create -d size=10g -d pool=rbd
        -X PUT https://192.168.122.69:5000/api/disk/rbd.new3_
    curl --insecure --user admin:admin -X GET https://192.168.122.69:5000/api/disk/rbd.new2_1
    curl --insecure --user admin:admin -X DELETE https://192.168.122.69:5000/api/disk/rbd.new2_1
    """

    local_gw = this_host()
    logger.debug("this host is {}".format(local_gw))

    image_id = '{}/{}'.format(pool, image)

    config.refresh()

    if request.method == 'GET':

        if image_id in config.config['disks']:
            return jsonify(config.config["disks"][image_id]), 200

        else:
            return jsonify(message="rbd image {} not "
                                   "found".format(image_id)), 404

    # Initial disk creation is done only on local host and this host
    mode = request.form.get('mode')
    if mode == 'create':
        backstore = request.form.get('backstore', LUN.DEFAULT_BACKSTORE)
    else:
        backstore = config.config['disks'][image_id]['backstore']

    gateways = []
    if mode != 'create':
        try:
            gateways = get_remote_gateways(config.config['gateways'], logger, False)
        except CephiSCSIError as err:
            logger.warning("disk operation request failed: {}".format(err))
            return jsonify(message="{}".format(err)), 400

    if request.method == 'PUT':
        # at this point we have a disk request, and the gateways are available
        # for the LUN masking operations

        # pool = request.form.get('pool')
        size = request.form.get('size')
        count = request.form.get('count', '1')

        controls = {}
        if 'controls' in request.form:
            try:
                controls = _parse_controls(request.form['controls'],
                                           LUN.SETTINGS[backstore])
            except ValueError as err:
                logger.error("Unexpected or invalid {} controls".format(mode))
                return jsonify(message="Unexpected or invalid controls - "
                                       "{}".format(err)), 500
            logger.debug("{} controls {}".format(mode, controls))

        disk_usable = LUN.valid_disk(config, logger, pool=pool,
                                     image=image, size=size, mode=mode,
                                     count=count, controls=controls, backstore=backstore)
        if disk_usable != 'ok':
            return jsonify(message=disk_usable), 400

        create_image = request.form.get('create_image') == 'true'
        if mode == 'create' and (not create_image or not size):
            try:
                rbd_image = RBDDev(image, 0, backstore, pool)
                size = rbd_image.current_size
            except rbd.ImageNotFound:
                if not create_image:
                    return jsonify(message="Image {} does not exist".format(image_id)), 400
                else:
                    return jsonify(message="Size parameter is required when creating a new "
                                           "image"), 400

        if mode == 'reconfigure':
            resp_text, resp_code = lun_reconfigure(image_id, controls, backstore)
            if resp_code == 200:
                return jsonify(message="lun reconfigured: {}".format(resp_text)), resp_code
            else:
                return jsonify(message=resp_text), resp_code

        suffixes = [n for n in range(1, int(count) + 1)]
        # make call to local api server first!
        gateways.insert(0, 'localhost')

        for sfx in suffixes:

            image_name = image if count == '1' else "{}{}".format(image,
                                                                  sfx)

            api_vars = {'pool': pool,
                        'image': image,
                        'size': size,
                        'owner': local_gw,
                        'mode': mode,
                        'backstore': backstore}
            if 'controls' in request.form:
                api_vars['controls'] = request.form['controls']

            resp_text, resp_code = call_api(gateways, '_disk',
                                            '{}/{}'.format(pool, image_name),
                                            http_method='put',
                                            api_vars=api_vars)

            if resp_code != 200:
                return jsonify(message="disk create/update "
                                       "{}".format(resp_text)), resp_code

        return jsonify(message="disk create/update {}".format(resp_text)), \
            resp_code

    else:
        # this is a DELETE request
        disk_usable = LUN.valid_disk(config, logger, mode='delete',
                                     pool=pool, image=image, backstore=backstore)

        if disk_usable != 'ok':
            return jsonify(message=disk_usable), 400

        api_vars = {
            'purge_host': local_gw,
            'preserve_image': request.form['preserve_image'],
            'backstore': backstore
        }

        # process other gateways first
        gateways.append(local_gw)

        resp_text, resp_code = call_api(gateways, '_disk',
                                        '{}/{}'.format(pool, image),
                                        http_method='delete',
                                        api_vars=api_vars)

        return jsonify(message="disk map deletion {}".format(resp_text)), \
            resp_code


@app.route('/api/_disk/<pool>/<image>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def _disk(pool, image):
    """
    Manage a disk definition on the local gateway
    Internal Use ONLY
    Disks can be created and added to each gateway, or deleted through this
    call
    :param pool: (str) pool name
    :param image: (str) image name
    **RESTRICTED**
    """

    image_id = '{}/{}'.format(pool, image)

    config.refresh()

    if request.method == 'GET':
        if image_id in config.config['disks']:
            return jsonify(config.config["disks"][image_id]), 200

        else:
            return jsonify(message="rbd image {} not "
                                   "found".format(image_id)), 404

    elif request.method == 'PUT':
        # A put is for either a create or a resize
        # put('http://localhost:5000/api/disk/rbd.ansible3',
        #     data={'pool': 'rbd','size': '3G','owner':'ceph-1'})

        mode = request.form['mode']
        if mode == 'create':
            backstore = request.form['backstore']
            backstore_object_name = LUN.get_backstore_object_name(str(request.form['pool']),
                                                                  image,
                                                                  config.config['disks'])
        else:
            disk_config = config.config['disks'][image_id]
            backstore = disk_config['backstore']
            backstore_object_name = disk_config['backstore_object_name']
        controls = {}
        if 'controls' in request.form:
            try:
                controls = _parse_controls(request.form['controls'],
                                           LUN.SETTINGS[backstore])
            except ValueError as err:
                logger.error("Unexpected or invalid {} controls".format(mode))
                return jsonify(message="Unexpected or invalid controls - "
                                       "{}".format(err)), 500
            logger.debug("{} controls {}".format(mode, controls))

        if mode in ['create', 'resize']:
            rqst_fields = set(request.form.keys())
            if not rqst_fields.issuperset(("pool", "size", "owner", "mode")):
                # this is an invalid request
                return jsonify(message="Invalid Request - need to provide "
                                       "pool, size and owner"), 400

            lun = LUN(logger,
                      str(request.form['pool']),
                      image,
                      str(request.form['size']),
                      str(request.form['owner']),
                      backstore,
                      backstore_object_name)
            if lun.error:
                logger.error("Unable to create a LUN instance"
                             " : {}".format(lun.error_msg))
                return jsonify(message="Unable to establish LUN instance"), 500

            lun.allocate(False)
            if lun.error:
                logger.error("LUN alloc problem - {}".format(lun.error_msg))
                return jsonify(message="LUN allocation failure"), 500

            if mode == 'create':
                # new disk is allocated, so refresh the local config object
                config.refresh()
                return jsonify(message="LUN created"), 200

            elif mode == 'resize':
                return jsonify(message="LUN resized"), 200

        elif mode in ['activate', 'deactivate']:
            disk = config.config['disks'].get(image_id, None)
            if not disk:
                return jsonify(message="rbd image {} not "
                                       "found".format(image_id)), 404
            backstore = disk['backstore']
            backstore_object_name = disk['backstore_object_name']
            # calculate required values for LUN object
            rbd_image = RBDDev(image, 0, backstore, pool)
            size = rbd_image.current_size
            if not size:
                logger.error("LUN size unknown - {}".format(image_id))
                return jsonify(message="LUN {} failure".format(mode)), 500

            if 'owner' not in disk:
                msg = "Disk {}/{} must be assigned to a target".format(disk['pool'], disk['image'])
                logger.error("LUN owner not defined - {}".format(msg))
                return jsonify(message="LUN {} failure - {}".format(mode, msg)), 400

            lun = LUN(logger, pool, image, size, disk['owner'],
                      backstore, backstore_object_name)
            if mode == 'deactivate':
                try:
                    lun.deactivate()
                except CephiSCSIError as err:
                    return jsonify(message="deactivate failed - {}".format(err)), 500

                return jsonify(message="LUN deactivated"), 200
            elif mode == 'activate':
                for k, v in controls.items():
                    setattr(lun, k, v)

                try:
                    lun.activate()
                except CephiSCSIError as err:
                    return jsonify(message="activate failed - {}".format(err)), 500

                return jsonify(message="LUN activated"), 200
    else:
        # DELETE request
        # let's assume that the request has been validated by the caller

        # if valid_request(request.remote_addr):
        purge_host = request.form['purge_host']
        preserve_image = request.form['preserve_image'] == 'true'
        logger.debug("delete request for disk image '{}'".format(image_id))
        pool, image = image_id.split('/', 1)
        disk_config = config.config['disks'][image_id]
        backstore = disk_config['backstore']
        backstore_object_name = disk_config['backstore_object_name']

        lun = LUN(logger,
                  pool,
                  image,
                  0,
                  purge_host,
                  backstore,
                  backstore_object_name)

        if lun.error:
            # problem defining the LUN instance
            logger.error("Error initializing the LUN : "
                         "{}".format(lun.error_msg))
            return jsonify(message="Error establishing LUN instance"), 500

        lun.remove_lun(preserve_image)
        if lun.error:
            if 'allocated to' in lun.error_msg:
                # attempted to remove rbd that is still allocated to a client
                status_code = 400
            else:
                status_code = 500

            error_msg = "Failed to remove the LUN - {}".format(lun.error_msg)
            logger.error(error_msg)
            return jsonify(message=error_msg), status_code

        config.refresh()

        return jsonify(message="LUN removed"), 200


def lun_reconfigure(image_id, controls, backstore):
    logger.debug("lun reconfigure request")

    config.refresh()
    disk = config.config['disks'].get(image_id, None)
    if not disk:
        return "rbd image {} not found".format(image_id), 404

    try:
        gateways = get_remote_gateways(config.config['gateways'], logger)
    except CephiSCSIError as err:
        return "{}".format(err), 400

    gateways.insert(0, 'localhost')

    # deactivate disk
    api_vars = {'mode': 'deactivate'}

    logger.debug("deactivating disk")
    resp_text, resp_code = call_api(gateways, '_disk',
                                    image_id, http_method='put',
                                    api_vars=api_vars)
    if resp_code != 200:
        return "failed to deactivate disk: {}".format(resp_text), resp_code

    pool_name, image_name = image_id.split('/', 1)

    rbd_image = RBDDev(image_name, 0, backstore, pool_name)
    size = rbd_image.current_size

    lun = LUN(logger, pool_name, image_name, size, disk['owner'],
              disk['backstore'], disk['backstore_object_name'])

    for k, v in controls.items():
        setattr(lun, k, v)

    try:
        lun.activate()
    except CephiSCSIError as err:
        logger.error("local LUN activation failed - {}".format(err))
        resp_code = 500
        resp_text = "{}".format(err)
    else:
        # We already activated this local node, so skip it
        gateways.remove('localhost')
        api_vars['controls'] = json.dumps(controls)

    # activate disk
    api_vars['mode'] = 'activate'

    logger.debug("activating disk")
    activate_resp_text, activate_resp_code = call_api(gateways, '_disk',
                                                      image_id, http_method='put',
                                                      api_vars=api_vars)
    if resp_code == 200 and activate_resp_code != 200:
        resp_text = activate_resp_text
        resp_code = activate_resp_code

    if resp_code == 200:
        try:
            lun.commit_controls()
        except CephiSCSIError as err:
            resp_text = "Could not commit controls: {}".format(err)
            resp_code = 500
        else:
            config.refresh()

    return resp_text, resp_code


@app.route('/api/disksnap/<pool>/<image>/<name>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def disksnap(pool, image, name):
    """
    Coordinate the management of rbd image snapshots across the gateway
    nodes. This method calls the corresponding disk api entrypoints across
    each gateway. Processing is done serially: rollback is done locally
    first, then other gateways. Other actions are only performed locally.

    :param image_id: (str) rbd image name of the format pool/image
    :param name: (str) rbd snapshot name
    :param mode: (str) 'create' or 'rollback' the rbd snapshot
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -d mode=create
        -X PUT https://192.168.122.69:5000/api/disksnap/rbd.image/new1
    curl --insecure --user admin:admin
        -X DELETE https://192.168.122.69:5000/api/disksnap/rbd.image/new1
    """

    if not valid_snapshot_name(name):
        logger.debug("snapshot request rejected due to invalid snapshot name")
        return jsonify(message="snapshot name is invalid"), 400

    image_id = '{}/{}'.format(pool, image)

    if image_id not in config.config['disks']:
        return jsonify(message="rbd image {} not "
                               "found".format(image_id)), 404

    if request.method == 'PUT':
        mode = request.form.get('mode')
        if mode == 'create':
            resp_text, resp_code = _disksnap_create(pool, image, name)
        elif mode == 'rollback':
            resp_text, resp_code = _disksnap_rollback(image_id, pool,
                                                      image, name)
        else:
            logger.debug("snapshot request rejected due to invalid mode")
            resp_text = "mode is invalid"
            resp_code = 400
    else:
        resp_text, resp_code = _disksnap_delete(pool, image, name)

    if resp_code == 200:
        return jsonify(message="disk snapshot {}".format(resp_text)), resp_code
    else:
        return jsonify(message=resp_text), resp_code


def _disksnap_create(pool_name, image_name, name):
    logger.debug("snapshot create request")
    try:
        with rados.Rados(conffile=settings.config.cephconf,
                         name=settings.config.cluster_client_name) as cluster, \
                cluster.open_ioctx(pool_name) as ioctx, \
                rbd.Image(ioctx, image_name) as image:
            image.create_snap(name)

        resp_text = "snapshot created"
        resp_code = 200
    except rbd.ImageExists:
        resp_text = "snapshot {} already exists".format(name)
        resp_code = 400
    except Exception as err:
        resp_text = "failed to create snapshot: {}".format(err)
        resp_code = 400
    return resp_text, resp_code


def _disksnap_delete(pool_name, image_name, name):
    logger.debug("snapshot delete request")
    try:
        with rados.Rados(conffile=settings.config.cephconf,
                         name=settings.config.cluster_client_name) as cluster, \
                cluster.open_ioctx(pool_name) as ioctx, \
                rbd.Image(ioctx, image_name) as image:
            try:
                image.remove_snap(name)
                resp_text = "snapshot deleted"
                resp_code = 200

            except rbd.ImageNotFound:
                resp_text = "snapshot {} does not exist".format(name)
                resp_code = 404

    except Exception as err:
        resp_text = "failed to delete snapshot: {}".format(err)
        resp_code = 400
    return resp_text, resp_code


def _disksnap_rollback(image_id, pool_name, image_name, name):
    logger.debug("snapshot rollback request")

    disk = config.config['disks'].get(image_id, None)
    if not disk:
        return "rbd image {} not found".format(image_id), 404

    try:
        gateways = get_remote_gateways(config.config['gateways'], logger)
    except CephiSCSIError as err:
        return "{}".format(err), 400
    gateways.append(this_host())

    api_vars = {
        'mode': 'deactivate'}

    logger.debug("deactivating disk")
    resp_text, resp_code = call_api(gateways, '_disk',
                                    image_id,
                                    http_method='put',
                                    api_vars=api_vars)
    if resp_code == 200:
        try:
            with rados.Rados(conffile=settings.config.cephconf,
                             name=settings.config.cluster_client_name) as cluster, \
                    cluster.open_ioctx(pool_name) as ioctx, \
                    rbd.Image(ioctx, image_name) as image:

                try:
                    logger.debug("rolling back to snapshot")
                    image.rollback_to_snap(name)
                    resp_text = "rolled back to snapshot"
                    resp_code = 200

                except rbd.ImageNotFound:
                    resp_text = "snapshot {} does not exist".format(name)
                    resp_code = 404

        except Exception as err:
            resp_text = "failed to rollback snapshot: {}".format(err)
            resp_code = 400

    else:
        resp_text = "failed to deactivate disk: {}".format(resp_text)

    logger.debug("activating disk")
    api_vars['mode'] = 'activate'
    activate_resp_text, activate_resp_code = call_api(gateways, '_disk',
                                                      image_id,
                                                      http_method='put',
                                                      api_vars=api_vars)
    if resp_code == 200 and activate_resp_code != 200:
        resp_text = activate_resp_text
        resp_code = activate_resp_code

    return resp_text, resp_code


@app.route('/api/discoveryauth', methods=['PUT'])
@requires_restricted_auth
def discoveryauth():
    """
    Coordinate discovery authentication changes across each gateway node
    The following parameters are needed to manage discovery auth
    :param username: (str) username string is 8-64 chars long containing any alphanumeric in
                           [0-9a-zA-Z] and '.' ':' '@' '_' '-'
    :param password: (str) password string is 12-16 chars long containing any alphanumeric in
                           [0-9a-zA-Z] and '@' '-' '_' '/'
    :param mutual_username: (str) mutual_username string is 8-64 chars long containing any
                            alphanumeric in
                            [0-9a-zA-Z] and '.' ':' '@' '_' '-'
    :param mutual_password: (str) mutual_password string is 12-16 chars long containing any
                            alphanumeric in
                            [0-9a-zA-Z] and '@' '-' '_' '/'
    **RESTRICTED**
    Example:
    curl --insecure --user admin:admin -d username=myiscsiusername -d password=myiscsipassword
        -d mutual_username=myiscsiusername -d mutual_password=myiscsipassword
        -X PUT https://192.168.122.69:5000/api/discoveryauth
    """

    username = request.form.get('username', '')
    password = request.form.get('password', '')
    mutual_username = request.form.get('mutual_username', '')
    mutual_password = request.form.get('mutual_password', '')

    # Validate request
    error_msg = valid_credentials(username, password, mutual_username, mutual_password)
    if error_msg:
        logger.error("BAD discovery auth request from {} - {}".format(
            request.remote_addr, error_msg))
        return jsonify(message=error_msg), 400

    # Apply to all gateways
    api_vars = {"username": username,
                "password": password,
                "mutual_username": mutual_username,
                "mutual_password": mutual_password}
    gateways = config.config['gateways'].keys()
    resp_text, resp_code = call_api(gateways, '_discoveryauth', '',
                                    http_method='put',
                                    api_vars=api_vars)

    # Update the configuration
    Discovery.set_discovery_auth_config(username, password, mutual_username, mutual_password,
                                        config)
    config.commit("retain")

    return jsonify(message="discovery auth {}".format(resp_text)), \
        resp_code


@app.route('/api/_discoveryauth/', methods=['PUT'])
@requires_restricted_auth
def _discoveryauth():
    """
    Manage discovery authentication credentials on the local gateway
    Internal Use ONLY
    **RESTRICTED**
    """

    username = request.form.get('username', '')
    password = request.form.get('password', '')
    mutual_username = request.form.get('mutual_username', '')
    mutual_password = request.form.get('mutual_password', '')

    Discovery.set_discovery_auth_lio(username, password, False, mutual_username, mutual_password,
                                     False)

    return jsonify(message='OK'), 200


@app.route('/api/targetauth/<target_iqn>', methods=['PUT'])
@requires_restricted_auth
def targetauth(target_iqn=None):
    """
    Coordinate the gen-acls across each gateway node
    :param target_iqn: (str) IQN of the target
    :param action: (str) action to be performed
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -d auth='disable_acl'
        -X PUT https://192.168.122.69:5000/api/targetauth/iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw
    """

    action = request.form.get('action')
    if action not in ['disable_acl', 'enable_acl']:
        return jsonify(message='Invalid auth {}'.format(action)), 400

    target_config = config.config['targets'][target_iqn]

    if action == 'disable_acl' and target_config['clients'].keys():
        return jsonify(message='Cannot disable ACL authentication '
                               'because target has clients'), 400

    try:
        gateways = get_remote_gateways(target_config['portals'], logger)
    except CephiSCSIError as err:
        return jsonify(message="{}".format(err)), 400
    local_gw = this_host()
    gateways.insert(0, local_gw)

    # Apply to all gateways
    api_vars = {
        "committing_host": local_gw,
        "action": action
    }
    resp_text, resp_code = call_api(gateways, '_targetauth',
                                    target_iqn,
                                    http_method='put',
                                    api_vars=api_vars)

    return jsonify(message="target auth {} - {}".format(action, resp_text)), resp_code


@app.route('/api/_targetauth/<target_iqn>', methods=['PUT'])
@requires_restricted_auth
def _targetauth(target_iqn=None):
    """
    Apply gen-acls on the local gateway
    Internal Use ONLY
    **RESTRICTED**
    """

    config.refresh()

    local_gw = this_host()
    committing_host = request.form['committing_host']
    action = request.form['action']

    target = GWTarget(logger, target_iqn, [])

    acl_enabled = (action == 'enable_acl')

    if target.exists():
        target.load_config()
        target.update_acl(acl_enabled)

    if committing_host == local_gw:
        target_config = config.config['targets'][target_iqn]
        target_config['acl_enabled'] = acl_enabled
        config.update_item('targets', target_iqn, target_config)
        config.commit("retain")

    return jsonify(message='OK'), 200


@app.route('/api/targetinfo/<target_iqn>', methods=['GET'])
@requires_restricted_auth
def targetinfo(target_iqn):
    """
    Returns the total number of active sessions for <target_iqn>
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET
        http://192.168.122.69:5000/api/targetinfo/iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw
    """
    if target_iqn not in config.config['targets']:
        return jsonify(message="Target {} does not exist".format(target_iqn)), 400
    target_config = config.config['targets'][target_iqn]
    gateways = target_config['portals']
    num_sessions = 0
    for gateway in gateways.keys():
        target_state = target_ready([gateway])
        if target_state.get('status_api') == 'UP' and target_state.get('status_iscsi') == 'DOWN':
            # If API is 'up' and iSCSI is 'down', there are no active sessions to count
            continue
        resp_text, resp_code = call_api([gateway], '_targetinfo', target_iqn, http_method='get')
        if resp_code != 200:
            return jsonify(message="{}".format(resp_text)), resp_code
        gateway_response = json.loads(resp_text)
        num_sessions += gateway_response['num_sessions']
    return jsonify({
        "num_sessions": num_sessions
    }), 200


@app.route('/api/_targetinfo/<target_iqn>', methods=['GET'])
@requires_restricted_auth
def _targetinfo(target_iqn):
    """
    Returns the number of active sessions for <target_iqn> on local gateway
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET
        http://192.168.122.69:5000/api/_targetinfo/iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw
    """
    if target_iqn not in config.config['targets']:
        return jsonify(message="Target {} does not exist".format(target_iqn)), 400
    num_sessions = GWTarget.get_num_sessions(target_iqn)
    return jsonify({
        "num_sessions": num_sessions
    }), 200


@app.route('/api/gatewayinfo', methods=['GET'])
@requires_restricted_auth
def gatewayinfo():
    """
    Returns the number of active sessions on local gateway
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET
        http://192.168.122.69:5000/api/gatewayinfo
    """
    local_gw = this_host()
    if local_gw not in config.config['gateways']:
        return jsonify(message="Gateway {} does not exist in configuration".format(local_gw)), 400
    num_sessions = 0
    for target_iqn, target in config.config['targets'].items():
        if local_gw in target['portals']:
            num_sessions += GWTarget.get_num_sessions(target_iqn)
    return jsonify({
        "num_sessions": num_sessions
    }), 200


@app.route('/api/clients/<target_iqn>', methods=['GET'])
@requires_restricted_auth
def get_clients(target_iqn=None):
    """
    List clients defined to the configuration.
    This information will include auth information, hence the
    restricted_auth wrapper
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET
        https://192.168.122.69:5000/api/clients/iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw
    """

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    target_config = config.config['targets'][target_iqn]
    client_list = target_config['clients'].keys()
    response = {"clients": client_list}

    return jsonify(response), 200


def _update_client(**kwargs):
    """
    Handler function to apply the changes to a specific client definition
    :param args:
    """
    # convert the comma separated image_list string into a list for GWClient
    if kwargs['images']:
        image_list = str(kwargs['images']).split(',')
    else:
        image_list = []

    client = GWClient(logger,
                      kwargs['client_iqn'],
                      image_list,
                      kwargs['username'],
                      kwargs['password'],
                      kwargs['mutual_username'],
                      kwargs['mutual_password'],
                      kwargs['target_iqn'])

    if client.error:
        logger.error("Invalid client request - {}".format(client.error_msg))
        return 400, "Invalid client request"

    client.manage('present', committer=kwargs['committing_host'])
    if client.error:
        logger.error("client update failed on {} : "
                     "{}".format(kwargs['client_iqn'],
                                 client.error_msg))
        return 500, "Client update failed - {}".format(client.error_msg)
    else:
        config.refresh()
        return 200, "Client configured successfully"


@app.route('/api/clientauth/<target_iqn>/<client_iqn>', methods=['PUT'])
@requires_restricted_auth
def clientauth(target_iqn, client_iqn):
    """
    Coordinate client authentication changes across each gateway node
    The following parameters are needed to manage client auth
    :param target_iqn: (str) target IQN name
    :param client_iqn: (str) client IQN name
    :param username: (str) username string is 8-64 chars long containing any alphanumeric in
                           [0-9a-zA-Z] and '.' ':' '@' '_' '-'
    :param password: (str) password string is 12-16 chars long containing any alphanumeric in
                           [0-9a-zA-Z] and '@' '-' '_' '/'
    :param mutual_username: (str) mutual_username string is 8-64 chars long containing any
                            alphanumeric in
                            [0-9a-zA-Z] and '.' ':' '@' '_' '-'
    :param mutual_password: (str) mutual_password string is 12-16 chars long containing any
                            alphanumeric in
                            [0-9a-zA-Z] and '@' '-' '_' '/'
    **RESTRICTED**
    Example:
    curl --insecure --user admin:admin -d username=myiscsiusername -d password=myiscsipassword
        -d mutual_username=myiscsiusername -d mutual_password=myiscsipassword
        -X PUT https://192.168.122.69:5000/api/clientauth/iqn.2017-08.org.ceph:iscsi-gw0
    """

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    try:
        client_iqn, iqn_type = normalize_wwn(['iqn'], client_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(client_iqn, err)
        return jsonify(message=err_str), 500

    # http_mode = 'https' if settings.config.api_secure else 'http'
    target_config = config.config['targets'][target_iqn]
    try:
        gateways = get_remote_gateways(target_config['portals'], logger)
    except CephiSCSIError as err:
        return jsonify(message="{}".format(err)), 400

    lun_list = target_config['clients'][client_iqn]['luns'].keys()
    image_list = ','.join(lun_list)
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    mutual_username = request.form.get('mutual_username', '')
    mutual_password = request.form.get('mutual_password', '')

    client_usable = valid_client(mode='auth',
                                 client_iqn=client_iqn,
                                 username=username,
                                 password=password,
                                 mutual_username=mutual_username,
                                 mutual_password=mutual_password,
                                 target_iqn=target_iqn)
    if client_usable != 'ok':
        logger.error("BAD auth request from {}".format(request.remote_addr))
        return jsonify(message=client_usable), 400

    api_vars = {"committing_host": this_host(),
                "image_list": image_list,
                "username": username,
                "password": password,
                "mutual_username": mutual_username,
                "mutual_password": mutual_password}

    gateways.insert(0, 'localhost')

    resp_text, resp_code = call_api(gateways, '_clientauth',
                                    '{}/{}'.format(target_iqn, client_iqn),
                                    http_method='put',
                                    api_vars=api_vars)

    return jsonify(message="client auth {}".format(resp_text)), \
        resp_code


@app.route('/api/_clientauth/<target_iqn>/<client_iqn>', methods=['PUT'])
@requires_restricted_auth
def _clientauth(target_iqn, client_iqn):
    """
    Manage client authentication credentials on the local gateway
    Internal Use ONLY
    :param target_iqn: IQN of the target
    :param client_iqn: IQN of the client
    **RESTRICTED**
    """

    # PUT request to define/change authentication
    image_list = request.form['image_list']
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    mutual_username = request.form.get('mutual_username', '')
    mutual_password = request.form.get('mutual_password', '')
    committing_host = request.form['committing_host']

    status_code, status_text = _update_client(client_iqn=client_iqn,
                                              images=image_list,
                                              username=username,
                                              password=password,
                                              mutual_username=mutual_username,
                                              mutual_password=mutual_password,
                                              committing_host=committing_host,
                                              target_iqn=target_iqn)

    return jsonify(message=status_text), status_code


@app.route('/api/clientlun/<target_iqn>/<client_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def clientlun(target_iqn, client_iqn):
    """
    Coordinate the addition(PUT) and removal(DELETE) of a disk for a client
    :param client_iqn: (str) IQN of the client
    :param disk: (str) rbd image name of the format pool/image
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -d disk=rbd.new2_1
        -X PUT https://192.168.122.69:5000/api/clientlun/iqn.2017-08.org.ceph:iscsi-gw0
    """

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    try:
        client_iqn, iqn_type = normalize_wwn(['iqn'], client_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(client_iqn, err)
        return jsonify(message=err_str), 500

    # http_mode = 'https' if settings.config.api_secure else 'http'
    target_config = config.config['targets'][target_iqn]
    try:
        gateways = get_remote_gateways(target_config['portals'], logger)
    except CephiSCSIError as err:
        return jsonify(message="{}".format(err)), 400

    disk = request.form.get('disk')

    lun_list = list(target_config['clients'][client_iqn]['luns'].keys())
    if request.method == 'PUT':
        lun_list.append(disk)
    else:
        # this is a delete request
        if disk in lun_list:
            lun_list.remove(disk)
        else:
            return jsonify(message="disk not mapped to client"), 400

    auth_config = target_config['clients'][client_iqn]['auth']
    chap_obj = CHAP(auth_config['username'],
                    auth_config['password'],
                    auth_config['password_encryption_enabled'])
    chap_mutual_obj = CHAP(auth_config['mutual_username'],
                           auth_config['mutual_password'],
                           auth_config['mutual_password_encryption_enabled'])
    image_list = ','.join(lun_list)
    client_usable = valid_client(mode='disk', client_iqn=client_iqn,
                                 image_list=image_list,
                                 target_iqn=target_iqn)
    if client_usable != 'ok':
        logger.error("Bad disk request for client {} : "
                     "{}".format(client_iqn,
                                 client_usable))
        return jsonify(message=client_usable), 400

    # committing host is the local LIO node
    api_vars = {"committing_host": this_host(),
                "image_list": image_list,
                "username": chap_obj.user,
                "password": chap_obj.password,
                "mutual_username": chap_mutual_obj.user,
                "mutual_password": chap_mutual_obj.password}

    gateways.insert(0, 'localhost')
    resp_text, resp_code = call_api(gateways, '_clientlun',
                                    '{}/{}'.format(target_iqn, client_iqn),
                                    http_method='put',
                                    api_vars=api_vars)

    return jsonify(message="client masking update {}".format(resp_text)), \
        resp_code


@app.route('/api/_clientlun/<target_iqn>/<client_iqn>', methods=['GET', 'PUT'])
@requires_restricted_auth
def _clientlun(target_iqn, client_iqn):
    """
    Manage the addition/removal of disks from a client on the local gateway
    Internal Use ONLY
    **RESTRICTED**
    """
    target_config = config.config['targets'][target_iqn]

    if request.method == 'GET':

        if client_iqn in target_config['clients']:
            lun_config = target_config['clients'][client_iqn]['luns']

            return jsonify(message=lun_config), 200
        else:
            return jsonify(message="Client does not exist"), 404

    else:
        # PUT request = new/updated disks for this client

        image_list = request.form['image_list']

        username = request.form.get('username', '')
        password = request.form.get('password', '')
        mutual_username = request.form.get('mutual_username', '')
        mutual_password = request.form.get('mutual_password', '')
        committing_host = request.form['committing_host']

        status_code, status_text = _update_client(client_iqn=client_iqn,
                                                  images=image_list,
                                                  username=username,
                                                  password=password,
                                                  mutual_username=mutual_username,
                                                  mutual_password=mutual_password,
                                                  committing_host=committing_host,
                                                  target_iqn=target_iqn)

        return jsonify(message=status_text), status_code


@app.route('/api/client/<target_iqn>/<client_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def client(target_iqn, client_iqn):
    """
    Handle the client create/delete actions across gateways
    :param target_iqn: (str) IQN of the target
    :param client_iqn: (str) IQN of the client to create or delete
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin
        -X PUT https://192.168.122.69:5000/api/client/iqn.1994-05.com.redhat:myhost4
    curl --insecure --user admin:admin
        -X DELETE https://192.168.122.69:5000/api/client/iqn.1994-05.com.redhat:myhost4
    """

    method = {"PUT": 'create',
              "DELETE": 'delete'}

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    try:
        client_iqn, iqn_type = normalize_wwn(['iqn'], client_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(client_iqn, err)
        return jsonify(message=err_str), 500

    # http_mode = 'https' if settings.config.api_secure else 'http'
    target_config = config.config['targets'][target_iqn]
    try:
        gateways = get_remote_gateways(target_config['portals'], logger)
    except CephiSCSIError as err:
        return jsonify(message="{}".format(err)), 400

    # validate the PUT/DELETE request first
    client_usable = valid_client(mode=method[request.method],
                                 client_iqn=client_iqn,
                                 target_iqn=target_iqn)
    if client_usable != 'ok':
        return jsonify(message=client_usable), 400

    # committing host is the node responsible for updating the config object
    api_vars = {"committing_host": this_host()}

    if request.method == 'PUT':
        # creating a client is done locally first, then applied to the
        # other gateways
        gateways.insert(0, 'localhost')

        resp_text, resp_code = call_api(gateways, '_client',
                                        '{}/{}'.format(target_iqn, client_iqn),
                                        http_method='put',
                                        api_vars=api_vars)

        return jsonify(message="client create/update {}".format(resp_text)),\
            resp_code

    else:
        # DELETE client request
        # Process flow: remote gateways > local > delete config object entry
        gateways.append('localhost')

        resp_text, resp_code = call_api(gateways, '_client',
                                        '{}/{}'.format(target_iqn, client_iqn),
                                        http_method='delete',
                                        api_vars=api_vars)

        return jsonify(message="client delete {}".format(resp_text)), \
            resp_code


@app.route('/api/_client/<target_iqn>/<client_iqn>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def _client(target_iqn, client_iqn):
    """
    Manage a client definition on the local gateway
    Internal Use ONLY
    :param target_iqn: iscsi name for the target
    :param client_iqn: iscsi name for the client
    **RESTRICTED**
    """

    if request.method == 'GET':

        target_config = config.config['targets'][target_iqn]
        if client_iqn in target_config['clients']:
            return jsonify(target_config["clients"][client_iqn]), 200
        else:
            return jsonify(message="Client does not exist"), 404

    elif request.method == 'PUT':

        try:
            normalize_wwn(['iqn'], client_iqn)
        except RTSLibError:
            return jsonify(message="'{}' is not a valid name for "
                                   "iSCSI".format(client_iqn)), 400

        committing_host = request.form['committing_host']

        image_list = request.form.get('image_list', '')

        username = request.form.get('username', '')
        password = request.form.get('password', '')
        mutual_username = request.form.get('mutual_username', '')
        mutual_password = request.form.get('mutual_password', '')

        status_code, status_text = _update_client(client_iqn=client_iqn,
                                                  images=image_list,
                                                  username=username,
                                                  password=password,
                                                  mutual_username=mutual_username,
                                                  mutual_password=mutual_password,
                                                  committing_host=committing_host,
                                                  target_iqn=target_iqn)

        logger.debug("client create: {}".format(status_code))
        logger.debug("client create: {}".format(status_text))
        return jsonify(message=status_text), status_code

    else:
        # DELETE request
        committing_host = request.form['committing_host']

        # Make sure the delete request is for a client we have defined
        target_config = config.config['targets'][target_iqn]
        if client_iqn in target_config['clients'].keys():
            client = GWClient(logger, client_iqn, '', '', '', '', '', target_iqn)
            client.manage('absent', committer=committing_host)

            if client.error:
                logger.error("Failed to remove client : "
                             "{}".format(client.error_msg))
                return jsonify(message="Failed to remove client"), 500

            else:
                if committing_host == this_host():
                    config.refresh()

                return jsonify(message="Client deleted ok"), 200
        else:
            logger.error("Delete request for non existent client!")
            return jsonify(message="Client does not exist!"), 404


@app.route('/api/clientinfo/<target_iqn>/<client_iqn>', methods=['GET'])
@requires_restricted_auth
def clientinfo(target_iqn, client_iqn):
    """
    Returns client alias, ip_address and state for each connected portal
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET
        http://192.168.122.69:5000/api/clientinfo/
        iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw/iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw-client
    """
    if target_iqn not in config.config['targets']:
        return jsonify(message="Target {} does not exist".format(target_iqn)), 400
    target_config = config.config['targets'][target_iqn]
    if client_iqn not in target_config['clients']:
        return jsonify(message="Client {} does not exist".format(client_iqn)), 400
    gateways = target_config['portals']
    response = {
        "alias": '',
        "state": {},
        "ip_address": []
    }
    for gateway in gateways.keys():
        resp_text, resp_code = call_api([gateway],
                                        '_clientinfo',
                                        '{}/{}'.format(target_iqn, client_iqn),
                                        http_method='get')
        if resp_code != 200:
            return jsonify(message="{}".format(resp_text)), resp_code
        gateway_response = json.loads(resp_text)
        alias = gateway_response['alias']
        if alias:
            response['alias'] = gateway_response['alias']
        state = gateway_response['state']
        if state:
            if state not in response['state']:
                response['state'][state] = []
            response['state'][state].append(gateway)
        response['ip_address'].extend(gateway_response['ip_address'])
    response['ip_address'] = list(set(response['ip_address']))
    return jsonify(response), 200


@app.route('/api/_clientinfo/<target_iqn>/<client_iqn>', methods=['GET'])
@requires_restricted_auth
def _clientinfo(target_iqn, client_iqn):
    """
    Returns client alias, ip_address and state for local gateway
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET
        http://192.168.122.69:5000/api/_clientinfo/
        iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw/iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw-client
    """
    if target_iqn not in config.config['targets']:
        return jsonify(message="Target {} does not exist".format(target_iqn)), 400
    target_config = config.config['targets'][target_iqn]
    if client_iqn not in target_config['clients']:
        return jsonify(message="Client {} does not exist".format(client_iqn)), 400

    logged_in = GWClient.get_client_info(target_iqn, client_iqn)
    return jsonify(logged_in), 200


@app.route('/api/hostgroups/<target_iqn>', methods=['GET'])
@requires_restricted_auth
def hostgroups(target_iqn=None):
    """
    Return the hostgroup names defined to the configuration
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET
        http://192.168.122.69:5000/api/hostgroups/iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw
    """

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    target_config = config.config['targets'][target_iqn]
    if request.method == 'GET':
        return jsonify({"groups": target_config['groups'].keys()}), 200


@app.route('/api/hostgroup/<target_iqn>/<group_name>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def hostgroup(target_iqn, group_name):
    """
    co-ordinate the management of host groups across iSCSI gateway hosts
    **RESTRICTED**
    :param group_name: (str) group name
    :param: members (list) list of client iqn's that are members of this group
    :param: disks (list) list of disks that each member should have masked
    :param: action (str) 'add'/'remove' group's client members/disks, default is 'add'
    :return:
    Examples:
    curl --insecure --user admin:admin -X GET http://192.168.122.69:5000/api/hostgroup/group_name
    curl --insecure --user admin:admin -d members=iqn.1994-05.com.redhat:myhost4
        -d disks=rbd.disk1 -X PUT http://192.168.122.69:5000/api/hostgroup/group_name
    curl --insecure --user admin:admin -d action=remove -d disks=rbd.disk1
        -X PUT http://192.168.122.69:5000/api/hostgroup/group_name
    curl --insecure --user admin:admin
        -X DELETE http://192.168.122.69:5000/api/hostgroup/group_name
    """
    http_mode = 'https' if settings.config.api_secure else 'http'
    valid_hostgroup_actions = ['add', 'remove']

    try:
        target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
    except RTSLibError as err:
        err_str = "Invalid iqn {} - {}".format(target_iqn, err)
        return jsonify(message=err_str), 500

    target_config = config.config['targets'][target_iqn]
    try:
        gateways = get_remote_gateways(target_config['portals'], logger)
    except CephiSCSIError as err:
        return jsonify(message="{}".format(err)), 400

    action = request.form.get('action', 'add')
    if action.lower() not in valid_hostgroup_actions:
        return jsonify(message="Invalid hostgroup action specified"), 405

    target_config = config.config['targets'][target_iqn]

    if request.method == 'GET':
        # return the requested definition
        if group_name in target_config['groups'].keys():
            return jsonify(target_config['groups'].get(group_name)), 200
        else:
            # group name does not exist
            return jsonify(message="Group name does not exist"), 404

    elif request.method == 'PUT':

        if group_name in target_config['groups']:
            host_group = target_config['groups'].get(group_name)
            current_members = host_group.get('members')
            current_disks = list(host_group.get('disks').keys())
        else:
            current_members = []
            current_disks = []

        changed_members = request.form.get('members', '')
        if changed_members == '':
            changed_members = []
        else:
            changed_members = changed_members.split(',')
        changed_disks = request.form.get('disks', '')
        if changed_disks == '':
            changed_disks = []
        else:
            changed_disks = changed_disks.split(',')

        if action.lower() == 'add':
            group_members = set(current_members + changed_members)
            group_disks = set(current_disks + changed_disks)
        else:
            # remove members
            group_members = [mbr for mbr in current_members
                             if mbr not in changed_members]
            group_disks = [disk for disk in current_disks
                           if disk not in changed_disks]

        api_vars = {"members": ','.join(group_members),
                    "disks": ','.join(group_disks)}

        # updated = []
        gateways.insert(0, 'localhost')
        logger.debug("gateway update order is {}".format(','.join(gateways)))

        resp_text, resp_code = call_api(gateways, '_hostgroup',
                                        '{}/{}'.format(target_iqn, group_name),
                                        http_method='put', api_vars=api_vars)

        return jsonify(message="hostgroup create/update {}".format(resp_text)), \
            resp_code

    else:
        # Delete request just purges the entry from the config, so we only
        # need to run against the local gateway

        if not target_config['groups'].get(group_name, None):
            return jsonify(message="Group name '{}' not "
                                   "found".format(group_name)), 404

        # At this point the group name is valid, so go ahead and remove it
        api_endpoint = ("{}://{}:{}/api/"
                        "_hostgroup/{}/{}".format(http_mode,
                                                  'localhost',
                                                  settings.config.api_port,
                                                  target_iqn,
                                                  group_name
                                                  ))

        api = APIRequest(api_endpoint)
        api.delete()

        if api.response.status_code == 200:
            logger.debug("Group definition {} removed".format(group_name))
            return jsonify(message="Group definition '{}' "
                                   "deleted".format(group_name)), 200
        else:
            return jsonify(message="Delete of group '{}'"
                                   " failed : {}".format(group_name,
                                                         api.response.json()['message'])), 400


@app.route('/api/settings', methods=['GET'])
@requires_restricted_auth
def get_settings():
    """
    List settings.
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X GET https://192.168.122.69:5000/api/settings
    """

    target_default_controls = {}
    target_controls_limits = {}
    settings_list = GWTarget.SETTINGS
    for k in settings_list:
        default_val = getattr(settings.config, k, None)
        if k in settings.Settings.LIO_YES_NO_SETTINGS:
            default_val = format_lio_yes_no(default_val)
        elif k in settings.Settings.LIO_INT_SETTINGS_LIMITS:
            target_controls_limits[k] = settings.Settings.LIO_INT_SETTINGS_LIMITS[k]
        target_default_controls[k] = default_val

    disk_default_controls = {}
    disk_controls_limits = {}
    required_rbd_features = {}
    unsupported_rbd_features = {}
    for backstore, ks in LUN.SETTINGS.items():
        disk_default_controls[backstore] = {}
        disk_controls_limits[backstore] = {}
        for k in ks:
            default_val = getattr(settings.config, k, None)
            disk_default_controls[backstore][k] = default_val
            if k in settings.Settings.LIO_INT_SETTINGS_LIMITS:
                disk_controls_limits[backstore][k] = settings.Settings.LIO_INT_SETTINGS_LIMITS[k]
        required_rbd_features[backstore] = RBDDev.required_features(backstore)
        unsupported_rbd_features[backstore] = RBDDev.unsupported_features(backstore)

    return jsonify({
        'target_default_controls': target_default_controls,
        'target_controls_limits': target_controls_limits,
        'disk_default_controls': disk_default_controls,
        'disk_controls_limits': disk_controls_limits,
        'unsupported_rbd_features': unsupported_rbd_features,
        'required_rbd_features': required_rbd_features,
        'backstores': LUN.BACKSTORES,
        'default_backstore': LUN.DEFAULT_BACKSTORE,
        'config': {
            'minimum_gateways': settings.config.minimum_gateways
        }
    }), 200


@app.route('/api/_hostgroup/<target_iqn>/<group_name>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def _hostgroup(target_iqn, group_name):
    """
    Manage a hostgroup definition on the local iscsi gateway
    Internal Use ONLY
    **RESTRICTED**
    :param group_name:
    :return:
    """
    target_config = config.config['targets'][target_iqn]

    if request.method == 'GET':
        # return the requested definition
        if group_name in target_config['groups'].keys():
            return jsonify(target_config['groups'].get(group_name)), 200
        else:
            # group name does not exist
            return jsonify(message="Group name does not exist"), 404

    elif request.method == 'PUT':

        members = request.form.get('members', [])
        if members == '':
            members = []
        else:
            members = members.split(',')
        disks = request.form.get('disks', [])
        if disks == '':
            disks = []
        else:
            disks = disks.split(',')

        # create/update a host group definition
        grp = Group(logger, target_iqn, group_name, members, disks)

        grp.apply()

        if not grp.error:
            config.refresh()
            return jsonify(message="Group created/updated"), 200
        else:
            return jsonify(message="{}".format(grp.error_msg)), 400

    else:
        # request is for a delete of a host group
        grp = Group(logger, target_iqn, group_name)
        grp.purge()
        if not grp.error:
            config.refresh()
            return jsonify(message="Group '{}' removed".format(group_name)), 200
        else:
            return jsonify(message=grp.error_msg), 400


def iscsi_active():
    for x in ['/proc/net/tcp', '/proc/net/tcp6']:
        try:
            with open(x) as tcp_data:
                for con in tcp_data:
                    field = con.split()
                    if '0CBC' in field[1] and field[3] == '0A':
                        # iscsi port is up (x'0cbc' = 3260), and listening (x'0a')
                        return True
        except Exception:
            pass
    return False


@app.route('/api/_ping', methods=['GET'])
@requires_restricted_auth
def _ping():
    """
    Simple "is alive" ping responder.
    """

    if request.method == 'GET':

        gw_config = config.config['gateways']
        if this_host() in gw_config:
            if iscsi_active():
                rc = 200
            else:
                rc = 503
        else:
            # host is not yet defined, which means the port check would fail
            # so just return a 200 OK back to the caller
            rc = 200

        return jsonify(message='pong'), rc


def target_ready(gateway_list):
    """
    function which determines whether all gateways in the configuration are
    up and ready to process commands
    :param gateway_list: (list) list of gateway names/IP addresses
    :return: (str) either 'ok' or an error description
    """
    http_mode = 'https' if settings.config.api_secure else 'http'
    target_state = {"status": 'OK',
                    "status_iscsi": 'UP',
                    "status_api": 'UP',
                    "summary": ''}

    for gw in gateway_list:
        api_endpoint = ("{}://{}:{}/api/_ping".format(http_mode,
                                                      normalize_ip_literal(gw),
                                                      settings.config.api_port))
        try:
            api = APIRequest(api_endpoint)
            api.get()
        except GatewayAPIError:
            target_state['status'] = 'NOTOK'
            target_state['status_iscsi'] = 'UNKNOWN'
            target_state['status_api'] = 'DOWN'
            target_state['summary'] += ',{}(iscsi Unknown, API down)'.format(gw)
        else:
            if api.response.status_code == 200:
                continue
            elif api.response.status_code == 503:
                target_state['status'] = 'NOTOK'
                target_state['status_iscsi'] = 'DOWN'
                target_state['status_api'] = 'UP'
                target_state['summary'] += ',{}(iscsi down, API up)'.format(gw)
            else:
                target_state['status'] = 'NOTOK'
                target_state['status_iscsi'] = 'UNKNOWN'
                target_state['status_api'] = 'UNKNOWN'
                target_state['summary'] += ',{}(UNKNOWN state)'.format(gw)

    target_state['summary'] = target_state['summary'][1:]   # ignore 1st char

    return target_state


def call_api(gateway_list, endpoint, element, http_method='put', api_vars=None):
    """
    Generic API handler to process a given request across multiple gateways
    :param gateway_list: (list)
    :param endpoint: (str) http api endpoint name to call
    :param element: (str) object to act upon
    :param http_method: (str) put or get http method
    :param api_vars: (dict) variables to pass to the api call
    :return: (str, int) string description and http status code
    """

    target_state = target_ready(gateway_list)
    if target_state.get('status') != 'OK':
        return ('failed, gateway(s) unavailable:'
                '{}'.format(target_state.get('summary'))), 503

    http_mode = 'https' if settings.config.api_secure else 'http'
    updated = []

    logger.debug("gateway update order is {}".format(','.join(gateway_list)))

    for gw in gateway_list:
        logger.debug("processing GW '{}'".format(gw))
        api_endpoint = ("{}://{}:{}/api/"
                        "{}/{}".format(http_mode,
                                       normalize_ip_literal(gw),
                                       settings.config.api_port,
                                       endpoint,
                                       element
                                       ))

        api = APIRequest(api_endpoint, data=api_vars)
        api_method = getattr(api, http_method)
        api_method()

        if api.response.status_code == 200:
            updated.append(gw)
            logger.info("{} update on {}, successful".format(endpoint, gw))
            continue
        else:
            logger.error("{} change on {} failed with "
                         "{}".format(endpoint,
                                     gw,
                                     api.response.status_code))
            if gw == 'localhost':
                gw = this_host()

            if len(updated) > 0:

                aborted = [gw_name for gw_name in gateway_list
                           if gw_name not in updated]
                fail_msg = ("failed on {}, "
                            "applied to {}, "
                            "aborted {}. ".format(gw,
                                                  ','.join(updated),
                                                  ','.join(aborted)))

            else:
                fail_msg = "failed on {}. ".format(gw)
            try:
                fail_msg += api.response.json()['message']
            except Exception:
                logger.debug(api.response.text)
                fail_msg += "unknown failure"

            logger.debug(fail_msg)

            return fail_msg, api.response.status_code

    return api.response.text if http_method == 'get' else 'successful', 200


def pre_reqs_errors():
    """
    function to check pre-reqs are installed and at the relevant versions

    :return: list of configuration errors detected
    """

    dist_translations = {
        "centos": "redhat",
        "opensuse-leap": "suse"}
    valid_dists = {
        "redhat": 7.4,
        "suse": 15.1}

    k_vers = '3.10.0'
    k_rel = '823.el7'

    errors_found = []

    os_release = read_os_release()
    dist = os_release.get('ID', '')
    rel = os_release.get('VERSION_ID')

    dist = dist.lower()
    dist = dist_translations.get(dist, dist)
    if dist in valid_dists:
        if dist == 'redhat':
            import platform
            _, rel, _ = platform.linux_distribution(full_distribution_name=0)
        # CentOS formats a release similar 7.4.1708
        rel = float(".".join(rel.split('.')[:2]))
        if rel < valid_dists[dist]:
            errors_found.append("OS version is unsupported")

    else:
        errors_found.append("OS is unsupported")

    # check the running kernel is OK (required kernel has patches to rbd.ko)
    os_info = os.uname()
    this_arch = os_info[-1]
    this_kernel = os_info[2].replace(".{}".format(this_arch), '')
    this_ver, this_rel = this_kernel.split('-', 1)

    # use labelCompare from the rpm module to handle the comparison
    if labelCompare(('1', this_ver, this_rel), ('1', k_vers, k_rel)) < 0:
        logger.error("Kernel version check failed")
        errors_found.append("Kernel version too old - {}-{} "
                            "or above needed".format(k_vers,
                                                     k_rel))

    return errors_found


def halt(message):
    logger.critical(message)
    sys.exit(16)


class ConfigWatcher(threading.Thread):
    """
    A ConfigWatcher checks the epoc xattr of the rados config object every 'n'
    seconds to determine if a change has been made. If a change has been made
    the local copy of the config object is refreshed
    """

    def __init__(self, interval=1):
        threading.Thread.__init__(self)
        self.interval = interval
        self.daemon = True

    def run(self):

        logger.info("Started the configuration object watcher")
        logger.info("Checking for config object changes every {}s".format(
            self.interval))

        cluster = rados.Rados(conffile=settings.config.cephconf,
                              name=settings.config.cluster_client_name)
        cluster.connect()
        ioctx = cluster.open_ioctx(settings.config.pool)
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

    ceph_gw = CephiSCSIGateway(logger, config)

    osd_state_ok = ceph_gw.osd_blacklist_cleanup()
    if not osd_state_ok:
        sys.exit(16)

    try:
        ceph_gw.define()
    except (CephiSCSIError, RTSLibError) as err:
        err_str = "Could not load gateway: {}".format(err)
        logger.error(err_str)
        ceph_gw.delete()
        halt(err_str)

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

    # Start the API server. threaded is enabled to prevent deadlocks when one
    # request makes further api requests
    app.run(host=settings.config.api_host,
            port=settings.config.api_port,
            debug=settings.config.debug,
            use_evalex=False,
            threaded=True,
            use_reloader=False,
            ssl_context=context)


def signal_stop(*args):
    logger.info("Shutdown received")

    ceph_gw = CephiSCSIGateway(logger, config)
    sys.exit(ceph_gw.delete())


def signal_reload(*args):
    logger.info("Refreshing local copy of the Gateway configuration")
    config.refresh()

    ceph_gw = CephiSCSIGateway(logger, config)
    ceph_gw.define()


if __name__ == '__main__':

    settings.init()
    logger_level = logging.getLevelName(settings.config.logger_level)

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
    file_handler = RotatingFileHandler('/var/log/rbd-target-api/rbd-target-api.log',
                                       maxBytes=5242880,
                                       backupCount=7)
    file_handler.setLevel(logger_level)
    file_format = logging.Formatter(
        "%(asctime)s %(levelname)8s [%(filename)s:%(lineno)s:%(funcName)s()] "
        "- %(message)s")
    file_handler.setFormatter(file_format)

    logger.addHandler(syslog_handler)
    logger.addHandler(file_handler)

    # config is set in the outer scope, so it's easily accessible to all
    # api functions
    config = Config(logger)
    if config.error:
        logger.error(config.error_msg)
        halt("Unable to open/read the configuration object")
    else:
        main()
