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
import re
import platform

from functools import wraps
from rpm import labelCompare
import rados

import werkzeug
from flask import Flask, jsonify, make_response, request
from rtslib_fb.utils import RTSLibError, normalize_wwn

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.gateway import GWTarget
from ceph_iscsi_config.group import Group
from ceph_iscsi_config.lun import LUN
from ceph_iscsi_config.client import GWClient, CHAP
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.utils import (get_ip, this_host, ipv4_addresses,
                                     gen_file_hash, valid_rpm)

from gwcli.utils import (this_host, APIRequest, valid_gateway,
                         valid_disk, valid_client, GatewayAPIError)

from gwcli.client import Client

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

        if (auth.username != settings.config.api_user or
           auth.password != settings.config.api_password):
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
        local_gw = ['127.0.0.1']
        gw_names = [gw for gw in config.config['gateways']
                    if isinstance(config.config['gateways'][gw], dict)]
        gw_ips = [get_ip(gw_name) for gw_name in gw_names] + \
                 local_gw + settings.config.trusted_ip_list

        if request.remote_addr not in gw_ips:
            return jsonify(message="API access not available to "
                                   "{}".format(request.remote_addr)), 403

        # check credentials supplied in the http request are valid
        auth = request.authorization
        if not auth:
            return jsonify(message="Missing credentials"), 401

        if (auth.username != settings.config.api_user or
                    auth.password != settings.config.api_password):
            return jsonify(message="username/password mismatch with the "
                                   "configuration file"), 401

        return f(*args, **kwargs)

    return decorated


@app.route('/api', methods=['GET'])
def get_api_info():
    """
    Display all the available API endpoints
    **UNRESTRICTED**
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
    Valid query types are: ipv4_addresses, checkconf and checkversions
    **RESTRICTED**
    """

    if query_type == 'ipv4_addresses':

        return jsonify(data=ipv4_addresses()), 200

    elif query_type == 'checkconf':

        local_hash = gen_file_hash('/etc/ceph/iscsi-gateway.cfg')
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


@app.route('/api/target/<target_iqn>', methods=['PUT'])
@requires_restricted_auth
def target(target_iqn=None):
    """
    Handle the definition of the iscsi target name
    The target is added to the configuration object, seeding the configuration
    for ALL gateways
    :param target_iqn: IQN of the target each gateway will use
    **RESTRICTED**
    """
    if request.method == 'PUT':

        gateway_ip_list = []

        target = GWTarget(logger,
                          str(target_iqn),
                          gateway_ip_list)

        if target.error:
            logger.error("Unable to create an instance of the GWTarget class")
            return jsonify(message="GWTarget problem - "
                                   "{}".format(target.error_msg)), 500

        target.manage('init')
        if target.error:
            logger.error("Failure during gateway 'init' processing")
            return jsonify(message="iscsi target 'init' process failed "
                                   "for {} - {}".format(target_iqn,
                                                        target.error_msg)), 500

        return jsonify(message="Target defined successfully"), 200

    else:
        # return unrecognised request
        return jsonify(message="Invalid method ({}) to target "
                               "API".format(request.method)), 405


@app.route('/api/config', methods=['GET'])
@requires_restricted_auth
def get_config():
    """
    Return the complete config object to the caller (must be authenticated)
    WARNING: Contents will include any defined CHAP credentials
    **RESTRICTED**
    """
    if request.method == 'GET':
        return jsonify(config.config), 200


@app.route('/api/gateways', methods=['GET'])
@requires_restricted_auth
def gateways():
    """
    Return the gateway subsection of the config object to the caller
    **RESTRICTED**
    """
    if request.method == 'GET':
        return jsonify(config.config['gateways']), 200


@app.route('/api/gateway/<gateway_name>', methods=['PUT'])
@requires_restricted_auth
def gateway(gateway_name=None):
    """
    Define iscsi gateway(s) across node(s), adding TPGs, disks and clients
    The call requires the following variables to be set;
    :param gateway_name: (str) gateway name
    :param ip_address: (str) ipv4 dotted quad for the address iSCSI should use
    :param nosync: (bool) whether to sync the LIO objects to the new gateway
           default: FALSE
    :param skipchecks: (bool) whether to skip OS/software versions checks
           default: FALSE
    **RESTRICTED**
    """

    # the definition of a gateway into an existing configuration can apply the
    # running config to the new host. The downside is that this sync task
    # could take a while if there are 100's of disks/clients. Future work should
    # aim to make this synchronisation of the new gateway an async task


    ip_address = request.form.get('ip_address')
    nosync = request.form.get('nosync', False)
    skipchecks = request.form.get('skipchecks', 'false')

    # first confirm that the request is actually valid, if not return a 400
    # error with the error description
    current_config = config.config

    if skipchecks.lower() == 'true':
        logger.warning("Gateway request received, with validity checks "
                       "disabled")
        gateway_usable = 'ok'
    else:
        logger.info("gateway validation needed for {}".format(gateway_name))
        gateway_usable = valid_gateway(gateway_name,
                                       ip_address,
                                       current_config)

    if gateway_usable != 'ok':
        return jsonify(message=gateway_usable), 400

    resp_text = "Gateway added"  # Assume the best!
    http_mode = 'https' if settings.config.api_secure else 'http'

    current_disks = config.config['disks']
    current_clients = config.config['clients']
    target_iqn = config.config['gateways'].get('iqn')

    total_objects = (len(current_disks.keys()) +
                     len(current_clients.keys()))

    # if the config is empty, it doesn't matter what nosync is set to
    if total_objects == 0:
        nosync = True

    gateway_ip_list = config.config['gateways'].get('ip_list', [])

    gateway_ip_list.append(ip_address)

    first_gateway = (len(gateway_ip_list) == 1)

    if first_gateway:
        gateways =['127.0.0.1']
    else:
        gateways = gateway_ip_list

    api_vars = {"target_iqn": target_iqn,
                "gateway_ip_list": ",".join(gateway_ip_list),
                "mode": "target"}

    resp_text, resp_code = call_api(gateways, '_gateway',
                                    gateway_name,
                                    http_method='put',
                                    api_vars=api_vars)

    if resp_code == 200:
        # GW definition has been added, so before we declare victory we need
        # to sync tpg's to the existing gateways and sync the disk and client
        # configuration to the new gateway

        if len(current_disks.keys()) > 0:
            # there are disks in the environment, so we need to add them to the
            # new tpg created when the new gateway was added
            seed_gateways = [ip for ip in gateways if ip != ip_address]

            resp_text, resp_code = seed_tpg(seed_gateways,
                                            gateway_name,
                                            api_vars)

            if resp_code != 200:
                return jsonify(message="TPG sync failed on existing gateways"), \
                       resp_code

        # No check to see if the new gateway needs to be synchronised as part
        # of this request
        if nosync:
            # no further action needed
            return jsonify(message="Gateway creation {}".format(resp_text)), \
                   resp_code
        else:

            resp_text, resp_code = seed_disks(current_disks,
                                              ip_address)

            if resp_code != 200:
                return jsonify(message="Disk mapping {}".format(resp_text)), \
                       resp_code
            else:
                # disks added, so seed the clients on the new gateway
                resp_text, resp_code = seed_clients(current_clients,
                                                    ip_address)

    else:

        return jsonify(message="Gateway creation {}".format(resp_text)), \
               resp_code


def seed_tpg(gateways, gateway_name, api_vars):

    http_mode = 'https' if settings.config.api_secure else 'http'
    state = 'succeeded'
    rc = 200
    api_vars['mode'] = 'map'

    for gw in gateways:
        logger.debug("Updating tpg on {}".format(gw))
        gw_api = '{}://{}:{}/api/_gateway/{}'.format(http_mode,
                                                     gw,
                                                     settings.config.api_port,
                                                     gateway_name)
        api = APIRequest(gw_api, data=api_vars)
        api.put()
        if api.response.status_code != 200:
            state = 'failed'
            rc = 500
            break

    return "TPG mapping {}".format(state), rc


def seed_disks(current_disks, gw_ip):

    http_mode = 'https' if settings.config.api_secure else 'http'
    state = 'succeeded'

    for disk_key in current_disks:

        this_disk = current_disks[disk_key]
        disk_api = '{}://{}:{}/api/disk/{}'.format(http_mode,
                                                   gw_ip,
                                                   settings.config.api_port,
                                                   disk_key)

        api_vars = {"pool": this_disk['pool'],
                    "size": "0G",
                    "owner": this_disk['owner'],
                    "mode": "sync"}

        api = APIRequest(disk_api, data=api_vars)
        api.put()

        if api.response.status_code != 200:
            state = 'failed'
            break

        logger.debug("added {} to gateway {}".format(disk_key,
                                                     gw_ip))

    return "disk seeding on {} {}".format(gw_ip, state), \
           api.response.status_code


def seed_clients(current_clients, gw_ip):

    http_mode = 'https' if settings.config.api_secure else 'http'
    state = 'succeeded'
    local_gw = this_host()

    for client_iqn in current_clients:

        this_client = current_clients[client_iqn]
        client_luns = this_client['luns']
        lun_list = [(disk, client_luns[disk]['lun_id'])
                    for disk in client_luns]
        srtd_list = Client.get_srtd_names(lun_list)

        api_vars = {'chap': this_client['auth']['chap'],
                    'image_list': ','.join(srtd_list),
                    'committing_host': local_gw}

        client_api = '{}://{}:{}/api/client/{}'.format(http_mode,
                                                       gw_ip,
                                                       settings.config.api_port,
                                                       client_iqn)

        api = APIRequest(client_api,
                         data=api_vars)
        api.put()

        if api.response.status_code != 200:
            state = 'failed'
            break

        logger.debug("client '{}' defined to GW {}".format(client_iqn,
                                                           gw_ip))

    return "Client seeding to '{}' {}".format(gw_ip, state), \
           api.response.status_code


@app.route('/api/_gateway/<gateway_name>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def _gateway(gateway_name=None):
    """
    Manage the local iSCSI gateway definition
    Internal Use ONLY
    Gateways may be be added(PUT), queried (GET) or deleted (DELETE) from
    the configuration
    :param gateway_name: (str) gateway name, normally the DNS name
    **RESTRICTED**
    """

    if request.method == 'GET':

        if gateway_name in config.config['gateways']:

            return jsonify(config.config['gateways'][gateway_name]), 200
        else:
            return jsonify(message="Gateway doesn't exist in the "
                                   "configuration"), 404

    elif request.method == 'PUT':
        # the parameters need to be cast to str for compatibility
        # with the comparison logic in common.config.add_item
        logger.debug("Attempting create of gateway {}".format(gateway_name))

        gateway_ips = str(request.form['gateway_ip_list'])
        target_iqn = str(request.form['target_iqn'])
        target_mode = str(request.form.get('mode', 'target'))

        gateway_ip_list = gateway_ips.split(',')

        gateway = GWTarget(logger,
                           target_iqn,
                           gateway_ip_list)

        if gateway.error:
            logger.error("Unable to create an instance of the GWTarget class")
            return jsonify(message="Failed to create the gateway"), 500

        gateway.manage(target_mode)
        if gateway.error:
            logger.error("manage({}) logic failed for {}".format(target_mode,
                                                                 gateway_name))
            return jsonify(message="Failed to create the gateway"), 500

        logger.info("created the gateway")

        if target_mode == 'target':
            # refresh only for target definitions, since that's when the config
            # will actually change
            logger.info("refreshing the configuration after the gateway "
                        "creation")
            config.refresh()

        return jsonify(message="Gateway defined/mapped"), 200

    else:
        # DELETE gateway request
        gateway = GWTarget(logger,
                           config.config['gateways']['iqn'],
                           '')
        if gateway.error:
            return jsonify(message="Failed to connect to the gateway"), 500

        gateway.manage('clearconfig')
        if gateway.error:
            logger.error("clearconfig failed for {} : "
                         "{}".format(gateway_name,
                                     gateway.error_msg))
            return jsonify(message="Unable to remove {} from the "
                                   "configuration".format(gateway_name)), 400

        else:

            config.refresh()

            return jsonify(message="Gateway removed successfully"), 200


@app.route('/api/disks')
@requires_restricted_auth
def get_disks():
    """
    Show the rbd disks defined to the gateways
    **RESTRICTED**
    """

    disk_names = config.config['disks'].keys()
    response = {"disks": disk_names}

    return jsonify(response), 200


@app.route('/api/disk/<image_id>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def disk(image_id):
    """
    Coordinate the create/delete of rbd images across the gateway nodes
    This method calls the corresponding disk api entrypoints across each
    gateway. Processing is done serially: creation is done locally first,
    then other gateways - whereas, rbd deletion is performed first against
    remote gateways and then the local machine is used to perform the actual
    rbd delete.

    :param image_id: (str) rbd image name of the format pool.image
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -d mode=create -d size=1g -d pool=rbd -d count=5 -X PUT https://192.168.122.69:5001/api/disk/rbd.new2_
    """

    disk_regex = re.compile("[a-zA-Z0-9\-]+(\.)[a-zA-Z0-9\-]+")
    if not disk_regex.search(image_id):
        logger.debug("disk request rejected due to invalid image name")
        return jsonify(message="image id format is invalid - must be "
                               "pool.image_name"), 400

    local_gw = this_host()
    logger.debug("this host is {}".format(local_gw))

    if request.method == 'GET':

        if image_id in config.config['disks']:
            return jsonify(config.config["disks"][image_id]), 200

        else:
            return jsonify(message="rbd image {} not "
                                   "found".format(image_id)), 404

    # This is a create/resize operation, so first confirm the gateways
    # are in place (we need gateways to perform the lun masking tasks
    gateways = [key for key in config.config['gateways']
                if isinstance(config.config['gateways'][key], dict)]
    logger.debug("All gateways: {}".format(gateways))

    # Any disk operation needs at least 2 gateways to be present
    if len(gateways) < settings.config.minimum_gateways:
        msg = "at least {} gateways must exist before disk operations " \
              "are permitted".format(settings.config.minimum_gateways)
        logger.warning("disk create request failed: {}".format(msg))
        return jsonify(message=msg), 400

    if request.method == 'PUT':

        # at this point we have a disk request, and the gateways are available
        # for the LUN masking operations
        gateways.remove(local_gw)
        logger.debug("Other gateways: {}".format(gateways))

        # pool = request.form.get('pool')
        size = request.form.get('size')
        mode = request.form.get('mode')
        count = request.form.get('count', '1')

        pool, image_name = image_id.split('.')

        disk_usable = valid_disk(pool=pool, image=image_name, size=size,
                                 mode=mode, count=count)
        if disk_usable != 'ok':
            return jsonify(message=disk_usable), 400

        suffixes = [n for n in range(1, int(count)+1)]
        # make call to local api server first!
        gateways.insert(0, '127.0.0.1')

        for sfx in suffixes:

            image_name = image_id if count == '1' else "{}{}".format(image_id,
                                                                     sfx)

            api_vars = {'pool': pool, 'size': size, 'owner': local_gw,
                        'mode': mode}

            resp_text, resp_code = call_api(gateways, '_disk',
                                            image_name,
                                            http_method='put',
                                            api_vars=api_vars)

            if resp_code != 200:
                return jsonify(message="disk create/update "
                                       "{}".format(resp_text)), resp_code

        return jsonify(message="disk create/update {}".format(resp_text)), \
               resp_code

    else:
        # this is a DELETE request
        pool_name, image_name = image_id.split('.')
        disk_usable = valid_disk(mode='delete', pool=pool_name,
                                 image=image_name)

        if disk_usable != 'ok':
            return jsonify(message=disk_usable), 400

        api_vars = {'purge_host': local_gw}

        # process other gateways first
        gateways.remove(local_gw)
        gateways.append(local_gw)

        resp_text, resp_code = call_api(gateways, '_disk',
                                        image_id,
                                        http_method='delete',
                                        api_vars=api_vars)

        return jsonify(message="disk map deletion {}".format(resp_text)), \
               resp_code


@app.route('/api/_disk/<image_id>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def _disk(image_id):
    """
    Manage a disk definition on the local gateway
    Internal Use ONLY
    Disks can be created and added to each gateway, or deleted through this
    call
    :param image_id: (str) of the form pool.image_name
    **RESTRICTED**
    """

    if request.method == 'GET':

        if image_id in config.config['disks']:
            return jsonify(config.config["disks"][image_id]), 200

        else:
            return jsonify(message="rbd image {} not "
                                   "found".format(image_id)), 404

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
                logger.error("Unable to create a LUN instance"
                             " : {}".format(lun.error_msg))
                return jsonify(message="Unable to establish LUN instance"), 500

            if request.form['mode'] == 'create' and len(config.config['disks']) >= 256:
                logger.error("LUN alloc problem - too many LUNs")
                return jsonify(message="LUN allocation failure: too many LUNs"), 500

            lun.allocate()
            if lun.error:
                logger.error("LUN alloc problem - {}".format(lun.error_msg))
                return jsonify(message="LUN allocation failure"), 500

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
                    logger.error("LUN mapping failed : "
                                 "{}".format(gateway.error_msg))
                    return jsonify(message="LUN map failed"), 500

                return jsonify(message="LUN created"), 200

            elif request.form['mode'] == 'resize':

                return jsonify(message="LUN resized"), 200

        else:

            # this is an invalid request
            return jsonify(message="Invalid Request - need to provide"
                                   "pool, size and owner"), 400

    else:
        # DELETE request
        # let's assume that the request has been validated by the caller

        # if valid_request(request.remote_addr):
        purge_host = request.form['purge_host']
        logger.debug("delete request for disk image '{}'".format(image_id))
        pool, image = image_id.split('.', 1)

        lun = LUN(logger,
                  pool,
                  image,
                  '0G',
                  purge_host)

        if lun.error:
            # problem defining the LUN instance
            logger.error("Error initialising the LUN : "
                         "{}".format(lun.error_msg))
            return jsonify(message="Error establishing LUN instance"), 500

        lun.remove_lun()
        if lun.error:
            if 'allocated to' in lun.error_msg:
                # attempted to remove rbd that is still allocated to a client
                status_code = 400
            else:
                status_code = 500

            logger.error("LUN remove failed : {}".format(lun.error_msg))
            return jsonify(message="Failed to remove the LUN"), status_code

        config.refresh()

        return jsonify(message="LUN removed"), 200


@app.route('/api/clients', methods=['GET'])
@requires_restricted_auth
def get_clients():
    """
    List clients defined to the configuration.
    This information will include auth information, hence the
    restricted_auth wrapper
    **RESTRICTED**
    """

    client_list = config.config['clients'].keys()
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
                      kwargs['chap'])

    if client.error:
        logger.error("Invalid client request - {}".format(client.error_msg))
        return 400, "Invalid client request"

    client.manage('present', committer=kwargs['committing_host'])
    if client.error:
        logger.error("client update failed on {} : "
                     "{}".format(kwargs['client_iqn'],
                                 client.error_msg))
        return 500, "Client update failed"
    else:
        config.refresh()
        return 200, "Client configured successfully"


@app.route('/api/clientauth/<client_iqn>', methods=['PUT'])
@requires_restricted_auth
def clientauth(client_iqn):
    """
    Coordinate client authentication changes across each gateway node
    The following parameters are needed to manage client auth
    :param client_iqn: (str) client IQN name
    :param chap: (str) chap string of the form username/password or ''
            username is 8-64 chars long containing any alphanumeric in [0-9a-zA-Z] and '.' ':' '@' '_' '-'
            password is 12-16 chars long containing any alphanumeric in [0-9a-zA-Z] and '@' '-' '_'
    **RESTRICTED**
    """

    # http_mode = 'https' if settings.config.api_secure else 'http'
    local_gw = this_host()
    logger.debug("this host is {}".format(local_gw))
    gateways = [key for key in config.config['gateways']
                if isinstance(config.config['gateways'][key], dict)]
    logger.debug("other gateways - {}".format(gateways))
    gateways.remove(local_gw)

    lun_list = config.config['clients'][client_iqn]['luns'].keys()
    image_list = ','.join(lun_list)
    chap = request.form.get('chap')

    client_usable = valid_client(mode='auth', client_iqn=client_iqn, chap=chap)
    if client_usable != 'ok':
        logger.error("BAD auth request from {}".format(request.remote_addr))
        return jsonify(message=client_usable), 400

    api_vars = {"committing_host": local_gw,
                "image_list": image_list,
                "chap": chap}

    gateways.insert(0, '127.0.0.1')

    resp_text, resp_code = call_api(gateways, '_clientauth', client_iqn,
                                    http_method='put',
                                    api_vars=api_vars)

    return jsonify(message="client auth {}".format(resp_text)), \
           resp_code


@app.route('/api/_clientauth/<client_iqn>', methods=['PUT'])
@requires_restricted_auth
def _clientauth(client_iqn):
    """
    Manage client authentication credentials on the local gateway
    Internal Use ONLY
    :param client_iqn: IQN of the client
    **RESTRICTED**
    """

    # PUT request to define/change authentication
    image_list = request.form['image_list']
    chap = request.form['chap']
    committing_host = request.form['committing_host']

    status_code, status_text = _update_client(client_iqn=client_iqn,
                                              images=image_list,
                                              chap=chap,
                                              committing_host=committing_host)

    return jsonify(message=status_text), status_code


@app.route('/api/clientlun/<client_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def clientlun(client_iqn):
    """
    Coordinate the addition(PUT) and removal(DELETE) of a disk for a client
    :param client_iqn: (str) IQN of the client
    :param disk: (str) rbd image name of the format pool.image
    **RESTRICTED**
    """

    # http_mode = 'https' if settings.config.api_secure else 'http'

    local_gw = this_host()
    logger.debug("this host is {}".format(local_gw))
    gateways = [key for key in config.config['gateways']
                if isinstance(config.config['gateways'][key], dict)]
    logger.debug("other gateways - {}".format(gateways))
    gateways.remove(local_gw)

    disk = request.form.get('disk')

    lun_list = config.config['clients'][client_iqn]['luns'].keys()

    if request.method == 'PUT':
        lun_list.append(disk)
    else:
        # this is a delete request
        if disk in lun_list:
            lun_list.remove(disk)
        else:
            return jsonify(message="disk not mapped to client"), 400

    chap_obj = CHAP(config.config['clients'][client_iqn]['auth']['chap'])
    chap = "{}/{}".format(chap_obj.user, chap_obj.password)
    image_list = ','.join(lun_list)

    client_usable = valid_client(mode='disk', client_iqn=client_iqn,
                                 image_list=image_list)
    if client_usable != 'ok':
        logger.error("Bad disk request for client {} : "
                     "{}".format(client_iqn,
                                 client_usable))
        return jsonify(message=client_usable), 400

    # committing host is the local LIO node
    api_vars = {"committing_host": local_gw,
                "image_list": image_list,
                "chap": chap}

    gateways.insert(0, '127.0.0.1')
    resp_text, resp_code = call_api(gateways, '_clientlun', client_iqn,
                                    http_method='put',
                                    api_vars=api_vars)

    return jsonify(message="client masking update {}".format(resp_text)), \
           resp_code


@app.route('/api/_clientlun/<client_iqn>', methods=['GET', 'PUT'])
@requires_restricted_auth
def _clientlun(client_iqn):
    """
    Manage the addition/removal of disks from a client on the local gateway
    Internal Use ONLY
    **RESTRICTED**
    """

    if request.method == 'GET':

        if client_iqn in config.config['clients']:
            lun_config = config.config['clients'][client_iqn]['luns']

            return jsonify(message=lun_config), 200
        else:
            return jsonify(message="Client does not exist"), 404

    else:
        # PUT request = new/updated disks for this client

        image_list = request.form['image_list']

        chap = request.form['chap']
        committing_host = request.form['committing_host']

        status_code, status_text = _update_client(client_iqn=client_iqn,
                                                  images=image_list,
                                                  chap=chap,
                                                  committing_host=committing_host)

        return jsonify(message=status_text), status_code


@app.route('/api/client/<client_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def client(client_iqn):
    """
    Handle the client create/delete actions across gateways
    :param client_iqn: (str) IQN of the client to create or delete
    **RESTRICTED**
    Examples:
    curl --insecure --user admin:admin -X PUT https://192.168.122.69:5001/api/all_client/iqn.1994-05.com.redhat:myhost4
    curl --insecure --user admin:admin -X DELETE https://192.168.122.69:5001/api/all_client/iqn.1994-05.com.redhat:myhost4
    """

    method = {"PUT": 'create',
              "DELETE": 'delete'}

    # http_mode = 'https' if settings.config.api_secure else 'http'
    local_gw = this_host()
    logger.debug("this host is {}".format(local_gw))
    gateways = [key for key in config.config['gateways']
                if isinstance(config.config['gateways'][key], dict)]
    logger.debug("other gateways - {}".format(gateways))
    gateways.remove(local_gw)

    # committing host is the node responsible for updating the config object
    api_vars = {"committing_host": local_gw}

    # validate the PUT/DELETE request first
    client_usable = valid_client(mode=method[request.method],
                                 client_iqn=client_iqn)
    if client_usable != 'ok':
        return jsonify(message=client_usable), 400

    if request.method == 'PUT':
        # creating a client is done locally first, then applied to the
        # other gateways
        gateways.insert(0, '127.0.0.1')

        resp_text, resp_code = call_api(gateways, '_client', client_iqn,
                                        http_method='put',
                                        api_vars=api_vars)

        return jsonify(message="client create/update {}".format(resp_text)),\
               resp_code

    else:
        # DELETE client request
        # Process flow: remote gateways > local > delete config object entry
        gateways.append('127.0.0.1')

        resp_text, resp_code = call_api(gateways, '_client', client_iqn,
                                        http_method='delete',
                                        api_vars=api_vars)

        return jsonify(message="client delete {}".format(resp_text)), \
               resp_code


@app.route('/api/_client/<client_iqn>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def _client(client_iqn):
    """
    Manage a client definition on the local gateway
    Internal Use ONLY
    :param client_iqn: iscsi name for the client
    **RESTRICTED**
    """

    if request.method == 'GET':

        if client_iqn in config.config['clients']:
            return jsonify(config.config["clients"][client_iqn]), 200
        else:
            return jsonify(message="Client does not exist"), 404

    elif request.method == 'PUT':

        try:
            valid_iqn = normalize_wwn(['iqn'], client_iqn)
        except RTSLibError:
            return jsonify(message="'{}' is not a valid name for "
                                   "iSCSI".format(client_iqn)), 400

        committing_host = request.form['committing_host']

        image_list = request.form.get('image_list', '')

        chap = request.form.get('chap', '')

        status_code, status_text = _update_client(client_iqn=client_iqn,
                                                  images=image_list,
                                                  chap=chap,
                                                  committing_host=committing_host)

        logger.debug("client create: {}".format(status_code))
        logger.debug("client create: {}".format(status_text))
        return jsonify(message=status_text), status_code

    else:
        # DELETE request
        committing_host = request.form['committing_host']

        # Make sure the delete request is for a client we have defined
        if client_iqn in config.config['clients'].keys():
            client = GWClient(logger, client_iqn, '', '')
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

@app.route('/api/hostgroups', methods=['GET'])
@requires_restricted_auth
def hostgroups():
    """
    Return the hostgroup names defined to the configuration
    **RESTRICTED**
    """
    if request.method == 'GET':
        return jsonify({"groups": config.config['groups'].keys()}), 200


@app.route('/api/hostgroup/<group_name>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def hostgroup(group_name):
    """
    co-ordinate the management of host groups across iSCSI gateway hosts
    **RESTRICTED**
    :param group_name: (str) group name
    :param: members (list) list of client iqn's that are members of this group
    :param: disks (list) list of disks that each member should have masked
    :return:
    """
    http_mode = 'https' if settings.config.api_secure else 'http'
    valid_hostgroup_actions = ['add', 'remove']

    local_gw = this_host()
    gw_list = [key for key in config.config['gateways']
               if isinstance(config.config['gateways'][key], dict)]
    gw_list.remove(local_gw)

    action = request.form.get('action', 'add')
    if action.lower() not in valid_hostgroup_actions:
        return jsonify(message="Invalid hostgroup action specified"), 405

    if request.method == 'GET':
        # return the requested definition
        if group_name in config.config['groups'].keys():
            return jsonify(config.config['groups'].get(group_name)), 200
        else:
            # group name does not exist
            return jsonify(message="Group name does not exist"), 404

    elif request.method == 'PUT':

        if group_name in config.config['groups']:
            host_group = config.config['groups'].get(group_name)
            current_members = host_group.get('members')
            current_disks = host_group.get('disks').keys()
        else:
            current_members = []
            current_disks = []

        changed_members = request.form.get('member', '')
        if changed_members == '':
            changed_members = []
        else:
            changed_members = changed_members.split(',')
        changed_disks = request.form.get('disk', '')
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
        gw_list.insert(0, '127.0.0.1')
        logger.debug("gateway update order is {}".format(','.join(gw_list)))

        resp_text, resp_code = call_api(gw_list, '_hostgroup', group_name,
                                        http_method='put', api_vars=api_vars)

        return jsonify(message="hostgroup create/update {}".format(resp_text)),\
               resp_code

    else:
        # Delete request just purges the entry from the config, so we only
        # need to run against the local gateway

        if not config.config['groups'].get(group_name, None):
            return jsonify(message="Group name '{}' not "
                                   "found".format(group_name)), 404

        # At this point the group name is valid, so go ahead and remove it
        api_endpoint = ("{}://{}:{}/api/"
                        "_hostgroup/{}".format(http_mode,
                                               '127.0.0.1',
                                               settings.config.api_port,
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


@app.route('/api/_hostgroup/<group_name>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def _hostgroup(group_name):
    """
    Manage a hostgroup definition on the local iscsi gateway
    Internal Use ONLY
    **RESTRICTED**
    :param group_name:
    :return:
    """
    if request.method == 'GET':
        # return the requested definition
        if group_name in config.config['groups'].keys():
            return jsonify(config.config['groups'].get(group_name)), 200
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
        grp = Group(logger, group_name, members, disks)

        grp.apply()

        if not grp.error:
            config.refresh()
            return jsonify(message="Group created/updated"), 200
        else:
            return jsonify(message="{}".format(grp.error_msg)), 400

    else:
        # request is for a delete of a host group
        grp = Group(logger, group_name)
        grp.purge()
        if not grp.error:
            return jsonify(message="Group '{}' removed".format(group_name)), \
                   200
        else:
            return jsonify(message=grp.error_msg), 400


def iscsi_active():

    state = False

    with open('/proc/net/tcp') as tcp_data:
        for con in tcp_data:
            field = con.split()
            if '0CBC' in field[1] and field[3] == '0A':
                # iscsi port is up (x'0cbc' = 3260), and listening (x'0a')
                state = True
                break
    return state


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

        return jsonify(message='pong'), \
               rc


def target_ready(gateway_list):
    """
    function which determines whether all gateways in the configuration are
    up and ready to process commands
    :param gateway_list: (list) list of gateway names/IP addresses
    :return: (str) either 'ok' or an error description
    """
    http_mode = 'https' if settings.config.api_secure else 'http'
    target_state = {"status": 'OK',
                    "summary": ''}

    for gw in gateway_list:
        api_endpoint = ("{}://{}:{}/api/_ping".format(http_mode,
                                                      gw,
                                                      settings.config.api_port))
        try:
            api = APIRequest(api_endpoint)
            api.get()
        except GatewayAPIError:
            target_state['status'] = 'NOTOK'
            target_state['summary'] += ',{}(iscsi Unknown, API down)'.format(gw)
        else:
            if api.response.status_code == 200:
                continue
            elif api.response.status_code == 503:
                target_state['status'] = 'NOTOK'
                target_state['summary'] += ',{}(iscsi down, API up)'.format(gw)
            else:
                target_state['status'] = 'NOTOK'
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
                '{}'.format(target_state.get('summary'))), \
               503

    http_mode = 'https' if settings.config.api_secure else 'http'
    updated = []

    logger.debug("gateway update order is {}".format(','.join(gateway_list)))

    for gw in gateway_list:
        logger.debug("processing GW '{}'".format(gw))
        api_endpoint = ("{}://{}:{}/api/"
                        "{}/{}".format(http_mode,
                                       gw,
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
            if gw == '127.0.0.1':
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
            fail_msg += api.response.json()['message']
            logger.debug(fail_msg)

            return fail_msg, api.response.status_code

    return "successful", 200


def pre_reqs_errors():
    """
    function to check pre-req rpms are installed and at the relevant versions

    :return: list of configuration errors detected
    """

    valid_dists = ["redhat"]
    valid_versions = ['7.4']

    required_rpms = [
        {"name": "python-rtslib",
         "version": "2.1.fb64",
         "release": "0.1"},
        {"name": "tcmu-runner",
         "version": "1.3.0",
         "release": "0.2.3"}
    ]

    k_vers = '3.10.0'
    k_rel = '695.el7'

    errors_found = []

    dist, rel, dist_id = platform.linux_distribution(full_distribution_name=0)

    if dist.lower() in valid_dists:
        if rel not in valid_versions:
            errors_found.append("OS version is unsupported")

        # check rpm versions are OK
        for rpm in required_rpms:
            if not valid_rpm(rpm):
                logger.error("RPM check for {} failed")
                errors_found.append("{} rpm must be installed at >= "
                                    "{}-{}".format(rpm['name'],
                                                   rpm['version'],
                                                   rpm['release']))
    else:
        errors_found.append("OS is unsupported")

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

    # Start the API server. threaded is enabled to prevent deadlocks when one
    # request makes further api requests
    app.run(host='0.0.0.0',
            port=settings.config.api_port,
            debug=True,
            threaded=True,
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
    file_format = logging.Formatter(
        "%(asctime)s %(levelname)8s [%(filename)s:%(lineno)s:%(funcName)s()] "
        "- %(message)s")
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
