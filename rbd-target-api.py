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
from flask import Flask, jsonify, make_response, request
from rtslib_fb.utils import RTSLibError, normalize_wwn

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.gateway import GWTarget
from ceph_iscsi_config.lun import LUN
from ceph_iscsi_config.client import GWClient, CHAP
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.utils import (get_ip, this_host, ipv4_addresses,
                                     gen_file_hash, valid_rpm)
from gwcli.utils import (this_host, APIRequest, valid_gateway,
                         valid_disk, valid_client)

from gwcli.client import Client

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

    internal_text = "Internal Use ONLY"

    links = []
    for rule in app.url_map.iter_rules():
        url = rule.rule
        if rule.endpoint == 'static':
            continue
        else:
            func_doc = inspect.getdoc(globals()[rule.endpoint])
            if func_doc:
                # doc = func_doc.split('\n')[0]
                doc = func_doc.split('\n')

                url = "{} : {}".format(url, doc[0])
                if internal_text in doc:
                    pos = doc.index(internal_text)
                    doc = doc[1:(pos+1)]
                else:
                    doc = doc[1:]

            else:
                doc = ["Missing description - FIXME!"]
            # url = "{} : {}".format(url, doc[0])
        links.append((url, doc))

    return jsonify(api=links), 200


@app.route('/api/sysinfo/<query_type>', methods=['GET'])
@requires_basic_auth
def sys_info(query_type=None):
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
def get_gateways():
    """
    Return the gateway subsection of the config object to the caller
    **RESTRICTED**
    """
    if request.method == 'GET':
        return jsonify(config.config['gateways']), 200


@app.route('/api/all_gateway/<gateway_name>', methods=['PUT'])
@requires_restricted_auth
def all_gateway(gateway_name=None):
    """
    Define iscsi gateway(s) across node(s), adding TPGs, disks and clients
    The call requires the following variables to be set;
    :param gateway_name: (str) gateway name
    :param ip_address: (str) ipv4 dotted quad for the address iSCSI should use
    :param nosync: (bool) whether to sync the LIO objects to the new gateway
    **RESTRICTED**
    """

    ip_address = request.form.get('ip_address')
    nosync = request.form.get('nosync', False)

    # first confirm that the request is actually valid, if not return a 400
    # error with the error description
    current_config = config.config
    gateway_usable = valid_gateway(gateway_name, ip_address, current_config)
    if gateway_usable != 'ok':
        return jsonify(message=gateway_usable), 400

    resp_text = "Gateway added"  # Assume the best!
    http_mode = 'https' if settings.config.api_secure else 'http'

    current_disks = config.config['disks']
    current_clients = config.config['clients']
    target_iqn = config.config['gateways'].get('iqn')

    total_objects = (len(current_disks.keys()) +
                     len(current_clients.keys()))
    if total_objects == 0:
        nosync = True

    gateway_ip_list = config.config['gateways'].get('ip_list', [])
    gateway_ip_list.append(ip_address)

    first_gateway = (len(gateway_ip_list) == 1)

    for endpoint in gateway_ip_list:
        if first_gateway:
            endpoint = '127.0.0.1'

        logger.debug("Processing GW endpoint {} for {}".format(endpoint,
                                                               gateway_name))

        api_endpoint = '{}://{}:{}/api'.format(http_mode,
                                               endpoint,
                                               settings.config.api_port)

        gw_rqst = api_endpoint + '/gateway/{}'.format(gateway_name)
        gw_vars = {"target_iqn": target_iqn,
                   "gateway_ip_list": ",".join(gateway_ip_list),
                   "mode": "target"}

        logger.debug("Calling API at {} with {}".format(gw_rqst, gw_vars))

        api = APIRequest(gw_rqst, data=gw_vars)
        api.put()
        if api.response.status_code != 200:
            # GW creation failed
            msg = api.response.json()['message']

            logger.error("Failed to create gateway {}: {}".format(gateway_name,
                                                                  msg))

            return jsonify(message="Failed to create gateway"), 500

        # for the new gateway, when sync is selected we need to run the
        # disk api to register all the rbd's to that gateway
        if endpoint == ip_address and not nosync:

            for disk_key in current_disks:

                this_disk = current_disks[disk_key]
                lun_rqst = api_endpoint + '/disk/{}'.format(disk_key)
                lun_vars = {"pool": this_disk['pool'],
                            "size": "0G",
                            "owner": this_disk['owner'],
                            "mode": "sync"}

                api = APIRequest(lun_rqst, data=lun_vars)
                api.put()
                if api.response.status_code != 200:
                    msg = api.response.json()['message']
                    logger.error("Failed to add disk {} to {} new "
                                 "tpg : {}".format(disk_key,
                                                   endpoint,
                                                   msg))
                    return jsonify(message="Failed to add disk"), 500

            resp_text += ", {} disks added".format(len(current_disks))

        # Adding a gateway introduces a new tpg - each tpg MUST have the
        # luns defined so a RTPG call can be responded to correctly, so
        # we need to sync the disks to the new tpg's
        if len(current_disks.keys()) > 0:

            if endpoint != ip_address or not nosync:

                gw_vars['mode'] = 'map'
                api = APIRequest(gw_rqst, data=gw_vars)
                api.put()
                if api.response.status_code != 200:
                    # GW creation failed - if the failure was severe you'll
                    # see a json issue here.
                    msg = api.response.json()['message']
                    logger.error("Failed to map existing disks to new"
                                 " tpg on {} - ".format(endpoint))
                    return jsonify(message="Failed to map disk"), 500

            if endpoint == ip_address and not nosync:

                for client_iqn in current_clients:

                    this_client = current_clients[client_iqn]
                    client_luns = this_client['luns']
                    lun_list = [(disk, client_luns[disk]['lun_id'])
                                for disk in client_luns]
                    srtd_list = Client.get_srtd_names(lun_list)

                    # client_iqn, image_list, chap, committing_host
                    client_vars = {'chap': this_client['auth']['chap'],
                                   'image_list': ','.join(srtd_list),
                                   'committing_host': local_gw}

                    api = APIRequest(api_endpoint +
                                     "/client/{}".format(client_iqn),
                                     data=client_vars)
                    api.put()
                    if api.response.status_code != 200:
                        msg = api.response.json()['message']
                        logger.error("Problem adding client {} - "
                                     "{}".format(client_iqn,
                                                 api.response.json()[
                                                     'message']))
                        return jsonify(message="Failed to add client"), 500

                resp_text += ", {} clients defined".format(
                    len(current_clients))

    return jsonify(message=resp_text), 200


@app.route('/api/gateway/<gateway_name>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def manage_gateway(gateway_name=None):
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


@app.route('/api/all_disk/<image_id>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def all_disk(image_id):
    """
    Coordinate the create/delete of rbd images across the gateway nodes
    The "all_" method calls the corresponding disk api entrypoints across each
    gateway. Processing is done serially: creation is done locally first,
    then other gateways - whereas, rbd deletion is performed first against
    remote gateways and then the local machine is used to perform the actual
    rbd delete.

    :param image_id: (str) rbd image name of the format pool.image
    **RESTRICTED**
    """

    http_mode = 'https' if settings.config.api_secure else 'http'

    local_gw = this_host()
    logger.debug("this host is {}".format(local_gw))
    gateways = [key for key in config.config['gateways']
                if isinstance(config.config['gateways'][key], dict)]
    logger.debug("other gateways - {}".format(gateways))
    gateways.remove(local_gw)
    logger.debug("other gw's {}".format(gateways))

    if request.method == 'PUT':

        pool = request.form.get('pool')
        size = request.form.get('size')
        mode = request.form.get('mode')

        pool, image_name = image_id.split('.')

        disk_usable = valid_disk(pool=pool, image=image_name, size=size,
                                 mode=mode)
        if disk_usable != 'ok':
            return jsonify(message=disk_usable), 400

        # make call to local api server first!
        disk_api = '{}://127.0.0.1:{}/api/disk/{}'.format(http_mode,
                                                          settings.config.api_port,
                                                          image_id)

        api_vars = {'pool': pool, 'size': size, 'owner': local_gw,
                    'mode': mode}

        logger.debug("Issuing disk request to the local API "
                     "for {}".format(image_id))

        api = APIRequest(disk_api, data=api_vars)
        api.put()

        if api.response.status_code == 200:
            logger.info("LUN is ready on this host")

            for gw in gateways:
                logger.debug("Adding {} to gw {}".format(image_id,
                                                         gw))
                disk_api = '{}://{}:{}/api/disk/{}'.format(http_mode,
                                                           gw,
                                                           settings.config.api_port,
                                                           image_id)
                api = APIRequest(disk_api, data=api_vars)
                api.put()

                if api.response.status_code == 200:
                    logger.info("LUN is ready on {}".format(gw))
                else:
                    return jsonify(message=api.response.json()['message']), 500

        else:
            logger.error(api.response.json()['message'])
            return jsonify(message=api.response.json()['message']), 500

        logger.info("LUN defined to all gateways for {}".format(image_id))

        return jsonify(message="ok"), 200

    else:
        # this is a DELETE request
        pool_name, image_name = image_id.split('.')
        disk_usable = valid_disk(mode='delete', pool=pool_name,
                                 image=image_name)

        if disk_usable != 'ok':
            return jsonify(message=disk_usable), 400

        api_vars = {'purge_host': local_gw}

        # process other gateways first
        for gw_name in gateways:
            disk_api = '{}://{}:{}/api/disk/{}'.format(http_mode,
                                                       gw_name,
                                                       settings.config.api_port,
                                                       image_id)

            logger.debug("removing '{}' from {}".format(image_id,
                                                        gw_name))

            api = APIRequest(disk_api, data=api_vars)
            api.delete()

            if api.response.status_code == 200:
                logger.debug("{} removed from {}".format(image_id, gw_name))

            elif api.response.status_code == 400:
                # 400 means the rbd is still allocated to a client
                msg = api.response.json()['message']
                logger.error(msg)
                return jsonify(message=msg), 400
            else:
                # delete failed - don't know why, pass the error to the
                # admin and abort
                msg = api.response.json()['message']
                return jsonify(message=msg), 500

        # at this point the remote gateways are cleaned up, now perform the
        # purge on the local host which will also purge the rbd
        disk_api = '{}://127.0.0.1:{}/api/disk/{}'.format(http_mode,
                                                          settings.config.api_port,
                                                          image_id)

        logger.debug("- removing '{}' from the local "
                     "machine, deleting the rbd".format(image_id))

        api = APIRequest(disk_api, data=api_vars)
        api.delete()

        if api.response.status_code == 200:
            logger.debug("- rbd {} deleted".format(image_id))
            return jsonify(message="ok"), 200
        else:
            return jsonify(message="failed to delete rbd "
                                   "{}".format(image_id)), 500


@app.route('/api/disk/<image_id>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def manage_disk(image_id):
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
                                 "".format(gateway.error_msg))
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


@app.route('/api/all_clientauth/<client_iqn>', methods=['PUT'])
@requires_restricted_auth
def all_client_auth(client_iqn):
    """
    Coordinate client authentication changes across each gateway node
    The following parameters are needed to manage client auth
    :param client_iqn: (str) client IQN name
    :param chap: (str) chap string of the form user/password or ''
    **RESTRICTED**
    """

    http_mode = 'https' if settings.config.api_secure else 'http'
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

    clientauth_api = '{}://127.0.0.1:{}/api/clientauth/{}'.format(
        http_mode,
        settings.config.api_port,
        client_iqn)
    logger.debug("Issuing client update to local gw for {}".format(
        client_iqn))

    api = APIRequest(clientauth_api, data=api_vars)
    api.put()

    if api.response.status_code == 200:
        logger.debug("Client update succeeded on local LIO")

        for gw in gateways:
            clientauth_api = '{}://{}:{}/api/clientauth/{}'.format(
                http_mode,
                gw,
                settings.config.api_port,
                client_iqn)
            logger.debug("updating client {} on {}".format(client_iqn,
                                                           gw))
            api = APIRequest(clientauth_api, data=api_vars)
            api.put()
            if api.response.status_code == 200:
                logger.info("client update successful on {}".format(gw))
                continue
            else:
                return jsonify(message="client update failed on "
                                       "{}".format(gw)), \
                       api.response.status_code

        logger.info("All gateways updated")
        return jsonify(message="ok"), 200

    else:
        # the local update failed, so abort further updates
        return jsonify(message="Client updated failed on local "
                               "LIO instance"), api.response.status_code


@app.route('/api/clientauth/<client_iqn>', methods=['PUT'])
@requires_restricted_auth
def manage_client_auth(client_iqn):
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

@app.route('/api/all_clientlun/<client_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def all_client_luns(client_iqn):
    """
    Coordinate the addition(PUT) and removal(DELETE) of a disk from a client
    :param client_iqn: (str) IQN of the client
    :param disk: (str) rbd image name of the format pool.image
    **RESTRICTED**
    """

    http_mode = 'https' if settings.config.api_secure else 'http'

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

    clientlun_api = '{}://127.0.0.1:{}/api/clientlun/{}'.format(http_mode,
                                                                settings.config.api_port,
                                                                client_iqn)

    api = APIRequest(clientlun_api, data=api_vars)
    api.put()

    if api.response.status_code == 200:

        logger.info("disk mapping update for {} successful".format(client_iqn))

        for gw in gateways:
            clientlun_api = '{}://{}:{}/api/clientlun/{}'.format(
                http_mode,
                gw,
                settings.config.api_port,
                client_iqn)

            logger.debug("Updating disk map for {} on GW {}".format(
                client_iqn,
                gw))
            api = APIRequest(clientlun_api, data=api_vars)
            api.put()

            if api.response.status_code == 200:
                logger.debug("gateway '{}' updated".format(gw))
                continue
            else:
                logger.error("disk mapping update on {} failed".format(gw))
                return jsonify(message="disk map updated failed on "
                                       "{}".format(gw)), \
                       api.response.status_code

        return jsonify(message="ok"), 200

    else:
        # disk map update failed at the first hurdle!
        logger.error("disk map update failed on the local LIO instance")
        return jsonify(message="failed to update local LIO instance"), \
               api.response.status_code


@app.route('/api/clientlun/<client_iqn>', methods=['GET', 'PUT'])
@requires_restricted_auth
def manage_client_luns(client_iqn):
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


@app.route('/api/all_client/<client_iqn>', methods=['PUT', 'DELETE'])
@requires_restricted_auth
def all_client(client_iqn):
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

    http_mode = 'https' if settings.config.api_secure else 'http'
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

        client_api = '{}://127.0.0.1:{}/api/client/{}'.format(
            http_mode,
            settings.config.api_port,
            client_iqn)

        logger.debug("Processing client CREATE for {}".format(client_iqn))
        api = APIRequest(client_api, data=api_vars)
        api.put()
        if api.response.status_code == 200:
            logger.info("Client {} added to local LIO".format(client_iqn))

            for gw in gateways:
                client_api = '{}://{}:{}/api/client/{}'.format(
                    http_mode,
                    gw,
                    settings.config.api_port,
                    client_iqn)

                logger.debug("sending request to {} to create {}".format(
                    gw,
                    client_iqn))
                api = APIRequest(client_api, data=api_vars)
                api.put()

                if api.response.status_code == 200:
                    logger.info(
                        "Client '{}' added to {}".format(client_iqn, gw))
                    continue
                else:
                    # client create failed against the remote LIO instance
                    msg = api.response.json()['message']
                    logger.error("Client create for {} failed on {} "
                                 ": {}".format(
                        client_iqn,
                        gw,
                        msg))

                    return jsonify(message=msg), 500

            # all gateways processed return a success state to the caller
            return jsonify(message='ok'), 200

        else:
            # client create failed against the local LIO instance
            msg = api.response.json()['message']
            logger.error("Client create on local LIO instance failed "
                         "for {} : {}".format(client_iqn,
                                              msg))
            return jsonify(message=msg), 500

    else:
        # DELETE client request
        # Process flow: remote gateways > local > delete config object entry
        for gw in gateways:
            client_api = '{}://{}:{}/api/client/{}'.format(http_mode,
                                                           gw,
                                                           settings.config.api_port,
                                                           client_iqn)
            logger.info("- removing '{}' from {}".format(client_iqn, gw))
            api = APIRequest(client_api, data=api_vars)
            api.delete()

            if api.response.status_code == 200:
                logger.info("- '{}' removed".format(client_iqn))
                continue
            elif api.response.status_code == 400:
                logger.error("- '{}' is in use on {}".format(client_iqn, gw))
                return jsonify(message="Client in use"), 400
            else:
                msg = api.response.json()['message']
                logger.error("Failed to remove {} from {}".format(
                    client_iqn,
                    gw))
                return jsonify(message="failed to remove client '{}' on "
                                       "{}".format(client_iqn, msg)), 500

        # At this point the other gateways have removed the client, so
        # remove from the local LIO instance
        client_api = '{}://127.0.0.1:{}/api/client/{}'.format(http_mode,
                                                              settings.config.api_port,
                                                              client_iqn)
        api = APIRequest(client_api, data=api_vars)
        api.delete()

        if api.response.status_code == 200:
            logger.info("successfully removed '{}'".format(client_iqn))
            return jsonify(message="ok"), 200

        else:
            return jsonify(message="Unable to delete {} from local LIO "
                                   "instance".format(client_iqn)), \
                   api.response.status_code


@app.route('/api/client/<client_iqn>', methods=['GET', 'PUT', 'DELETE'])
@requires_restricted_auth
def manage_client(client_iqn):
    """
    Manage a client definition to the local gateway
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


def pre_reqs_errors():
    """
    function to check pre-req rpms are installed and at the relevant versions

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
        "%(asctime)s [%(levelname)8s] - %(message)s")
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
