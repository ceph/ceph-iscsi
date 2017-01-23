#!/usr/bin/env python

import sys
import json
import socket

from gwcli.node import UIGroup, UINode, UIRoot
# from requests import delete, put, get, ConnectionError

from gwcli.storage import Disks
from gwcli.client import Clients, Client, CHAP
from gwcli.utils import (this_host, get_other_gateways,
                         GatewayAPIError, GatewayError,
                         APIRequest, progress_message,
                         console_message)

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.utils import get_ip, ipv4_addresses, gen_file_hash

from rtslib_fb.utils import normalize_wwn, RTSLibError
import rtslib_fb.root as root

from gwcli.ceph import CephGroup

# FIXME - code is using a self signed cert common across all gateways
# the embedded urllib3 package will issue warnings when ssl cert validation is
# disabled - so this disable_warnings stops the user interface from being
# bombed
from requests.packages import urllib3

__author__ = 'pcuzner@redhat.com'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ISCSIRoot(UIRoot):

    # display_attributes = ['http_mode', 'local_api']

    def __init__(self, shell, logger, endpoint=None):
        UIRoot.__init__(self, shell)

        self.error = False
        self.error_msg = ''
        self.interactive = True           # default interactive mode
        self.logger = logger

        if settings.config.api_secure:
            self.http_mode = 'https'
        else:
            self.http_mode = 'http'

        if endpoint == None:
            self.local_api = '{}://127.0.0.1:{}/api'.format(self.http_mode,
                                                            settings.config.api_port)
        else:
            self.local_api = endpoint

        self.config = {}
        # Establish the root nodes within the UI, for the different components

        self.disks = Disks(self)
        self.ceph = CephGroup(self)
        self.target = ISCSITarget(self)

    def refresh(self):
        self.config = self._get_config()

        if not self.error:

            if 'disks' in self.config:
                self.disks.refresh(self.config['disks'])
            else:
                self.disks.refresh({})

            if 'gateways' in self.config:
                self.target.gateway_group = self.config['gateways']
            else:
                self.target.gateway_group = {}

            if 'clients' in self.config:
                self.target.client_group = self.config['clients']
            else:
                self.target.client_group = {}

            self.target.refresh()

            self.ceph.refresh()

        else:
            # Unable to get the config, tell the user and exit the cli
            self.logger.critical("Unable to access the configuration "
                                 "object : {}".format(self.error_msg))
            raise GatewayError


    def _get_config(self, endpoint=None):

        if not endpoint:
            endpoint = self.local_api

        api = APIRequest(endpoint + "/config")
        api.get()
        # response = get(self.local_api + "/config",
        #                auth=(settings.config.api_user, settings.config.api_password),
        #                verify=settings.config.api_ssl_verify)

        # except ConnectionError as e:
        #     self.error = True
        #     self.error_msg = "API unavailable @ {}".format(self.local_api)
        #     return {}

        if api.response.status_code == 200:
            return api.response.json()
        else:
            self.error = True
            self.error_msg = "REST API failure, code : " \
                             "{}".format(api.response.status_code)
            return {}



    def export_ansible(self, config):

        this_gw = this_host()
        ansible_vars = []
        ansible_vars.append("seed_monitor: {}".format(self.ceph.local_ceph.healthy_mon))
        ansible_vars.append("cluster_name: {}".format(settings.config.cluster_name))
        ansible_vars.append("gateway_keyring: {}".format(settings.config.gateway_keyring))
        ansible_vars.append("deploy_settings: true")
        ansible_vars.append("perform_system_checks: true")
        ansible_vars.append('gateway_iqn: "{}"'.format(config['gateways']['iqn']))
        ansible_vars.append('gateway_ip_list: "{}"'.format(",".join(config['gateways']['ip_list'])))
        ansible_vars.append("# rbd device definitions")
        ansible_vars.append("rbd_devices:")

        disk_template = ("  - {{ pool: '{}', image: '{}', size: '{}', "
                         "host: '{}', state: 'present' }}")

        for disk in self.disks.children:

            ansible_vars.append(disk_template.format(disk.pool,
                                                     disk.image,
                                                     disk.size_h,
                                                     this_gw))
        ansible_vars.append("# client connections")
        ansible_vars.append("client_connections:")
        client_template = ("  - {{ client: '{}', image_list: '{}', "
                           "chap: '{}', status: 'present' }}")

        for client in sorted(config['clients'].keys()):
            client_metadata = config['clients'][client]
            lun_data = client_metadata['luns']
            sorted_luns = [s[0] for s in sorted(lun_data.iteritems(),
                                                key=lambda (x, y): y['lun_id'])]
            chap = CHAP(client_metadata['auth']['chap'])
            ansible_vars.append(client_template.format(client,
                                                       ','.join(sorted_luns),
                                                       chap.chap_str))
        for var in ansible_vars:
            print(var)

    def export_copy(self, config):

        fmtd_config = json.dumps(config, sort_keys=True,
                                 indent=4, separators=(',', ': '))
        print(fmtd_config)


    def ui_command_export(self, mode='ansible'):


        self.logger.debug("CMD: export mode={}".format(mode))

        current_config = self._get_config()

        if mode == "ansible":
            self.export_ansible(current_config)
        elif mode == 'copy':
            self.export_copy(current_config)

    def ui_command_info(self):
        self.logger.debug("CMD: info")

        if settings.config.trusted_ip_list:
            display_ips = ','.join(settings.config.trusted_ip_list)
        else:
            display_ips = 'None'

        console_message("HTTP mode          : {}".format(self.http_mode))
        console_message("Rest API port      : {}".format(settings.config.api_port))
        console_message("Local endpoint     : {}".format(self.local_api))
        console_message("Local Ceph Cluster : {}".format(settings.config.cluster_name))
        console_message("2ndary API IP's    : {}".format(display_ips))


class ISCSITarget(UIGroup):
    help_intro = '''
                 The iscsi-target group shows you...bla
                 '''

    def __init__(self, parent):
        UIGroup.__init__(self, 'iscsi-target', parent)
        self.logger = self.parent.logger
        self.gateway_group = {}
        self.client_group = {}


    def ui_command_create(self, target_iqn):
        """
        Create a gateway target. This target is defined across all gateway nodes,
        providing the client with a single 'image' for iscsi discovery.

        Only ONE target is supported, at this time.
        """

        self.logger.debug("CMD: /iscsi create {}".format(target_iqn))

        defined_targets = [tgt.name for tgt in self.children]
        if len(defined_targets) > 0:
            self.logger.error("Only ONE iscsi target image is supported")
            return

        # We need LIO to be empty, so check there aren't any targets defined
        local_lio = root.RTSRoot()
        current_target_names = [tgt.wwn for tgt in local_lio.targets]
        if current_target_names:
            self.logger.error("Local LIO instance already has LIO configured "
                              "with a target - unable to continue")
            raise GatewayError

        # OK - this request is valid, lets make sure the iqn is also valid :P
        try:
            valid_iqn = normalize_wwn(['iqn'], target_iqn)
        except RTSLibError:
            self.logger.error("IQN name '{}' is not valid for "
                              "iSCSI".format(target_iqn))
            return


        # 'safe' to continue with the definition
        self.logger.debug("Create an iscsi target definition in the UI")

        local_api = '{}://127.0.0.1:{}/api/target/{}'.format(self.http_mode,
                                                             settings.config.api_port,
                                                             target_iqn)
        api = APIRequest(local_api)
        api.put()

        if api.response.status_code == 200:
            self.logger.info('ok')
            # create the target entry in the UI tree
            Target(target_iqn, self)
        else:
            self.logger.error("Failed to create the target on the local node")

            raise GatewayAPIError("iSCSI target creation failed - "
                                  "{}".format(api.response.json()['message']))

    def ui_command_clearconfig(self, confirm=None):
        """
        The 'clearconfig' command allows you to return the configuration to an
        unused state: LIO on each gateway will be cleared, and gateway
        definitions in the configuration object will be removed.

        > clearconfig confirm=true

        In order to run the clearconfig command, all clients and disks *must*
        have already have been removed.
        """

        self.logger.debug("CMD: clearconfig confirm={}".format(confirm))

        confirm = self.ui_eval_param(confirm, 'bool', False)
        if not confirm:
            self.logger.error("To clear the configuration you must specify "
                              "confirm=true")
            return

        # get a new copy of the config dict over the local API
        # check that there aren't any disks or client listed
        local_api = "{}://127.0.0.1:{}/api/config".format(self.http_mode,
                                                          settings.config.api_port)
        api = APIRequest(local_api)
        api.get()

        if api.response.status_code != 200:
            self.logger.error("Unable to get fresh copy of the configuration")
            raise GatewayAPIError

        current_config = api.response.json()
        num_clients = len(current_config['clients'].keys())
        num_disks = len(current_config['disks'].keys())

        if num_clients > 0 or num_disks > 0:
            self.logger.error("Clients({}) and Disks({}) must be removed first"
                              " before clearing the gateway "
                              "configuration".format(num_clients,
                                                     num_disks))
            return

        self.clear_config(current_config['gateways'])

    def clear_config(self, gateway_group):

        # we need to process the gateways, leaving the local machine until
        # last to ensure we don't fall foul of the api auth check
        gw_list = [gw_name for gw_name in gateway_group
                   if isinstance(gateway_group[gw_name], dict)]
        gw_list.remove(this_host())
        gw_list.append(this_host())

        for gw_name in gw_list:

            gw_api = '{}://{}:{}/api/gateway/{}'.format(self.http_mode,
                                                        gw_name,
                                                        settings.config.api_port,
                                                        gw_name)
            api = APIRequest(gw_api)
            api.delete()
            if api.response.status_code != 200:
                msg = api.response.json()['message']
                self.logger.error("Delete of {} failed : {}".format(gw_name,
                                                                    msg))
                raise GatewayAPIError
            else:
                self.logger.debug("- deleted {}".format(gw_name))

        # gateways removed, so lets delete the objects from the UI tree
        self.reset()

        # remove any bookmarks stored in the prefs.bin file
        del self.shell.prefs['bookmarks']

        self.logger.info('ok')

    def refresh(self):

        self.logger.debug("Refreshing gateway & client information")
        self.reset()
        if 'iqn' in self.gateway_group:
            tgt = Target(self.gateway_group['iqn'], self)
            tgt.gateway_group.load(self.gateway_group)
            tgt.client_group.load(self.client_group)

    def summary(self):
        return "Targets: {}".format(len(self.children)), None

class Target(UIGroup):

    help_info = '''
                The iscsi target bla
                '''

    def __init__(self, target_iqn, parent):
        UIGroup.__init__(self, target_iqn, parent)
        self.logger = self.parent.logger
        self.target_iqn = target_iqn
        self.gateway_group = GatewayGroup(self)
        self.client_group = Clients(self)

    def summary(self):
        return "Gateways: {}".format(len(self.gateway_group.children)), None


class GatewayGroup(UIGroup):

    help_intro = '''
                 The gateway-group shows you the high level details of the
                 iscsi gateway nodes that have been configured. It also allows
                 you to add further gateways to the configuration, but when
                 creating new gateways, it is your responsibility to ensure the
                 following requirements are met:
                 - device-mapper-mulitpath
                 - ceph_iscsi_config

                 In addition multipath.conf must be set up specifically for use
                 as a gateway.

                 If in doubt, use Ansible :)
                 '''

    def __init__(self,  parent):

        UIGroup.__init__(self, 'gateways', parent)
        self.logger = self.parent.logger

        # record the shortcut
        shortcut = self.shell.prefs['bookmarks'].get('gateways', None)
        if not shortcut or shortcut is not self.path:

            self.shell.prefs['bookmarks']['gateways'] = self.path
            self.shell.prefs.save()
            self.shell.log.debug("Bookmarked %s as %s."
                                 % (self.path, 'gateways'))

    def load(self, gateway_group):
        # define the host entries from the gateway_group dict
        gateway_list = [gw for gw in gateway_group
                        if isinstance(gateway_group[gw], dict)]
        for gateway_name in gateway_list:
            Gateway(self, gateway_name, gateway_group[gateway_name])

    def ui_command_info(self):

        self.logger.debug("CMD: ../gateways/ info")

        for child in self.children:
            print(child)

    def ui_command_refresh(self):
        """
        refresh allows you to refresh the connection status of each of the
        configured gateways (i.e. check the up/down state).
        """

        if len(self.children) > 0:
            for gw in self.children:
                self.logger.debug("Refreshing {}".format(gw.name))
                gw.refresh()
        else:
            self.logger.error("No gateways to refresh")

    def ui_command_create(self, gateway_name, ip_address, nosync=False):
        """
        Define a gateway to the gateway group for this iscsi target. The
        first host added should be the gateway running the command

        gateway_name ... should resolve to the hostname of the gateway
        ip_address ..... is the IP v4 address of the interface the iscsi
                         portal should use
        nosync ......... by default new gateways are sync'd with the
                         existing configuration by cli. By specifying nosync
                         the sync step is bypassed - so the new gateway
                         will need to have it's rbd-target-gw daemon
                         restarted to apply the current configuration
        """

        self.logger.debug("CMD: ../gateways/ create {} {} "
                          "nosync={}".format(gateway_name,
                                             ip_address,
                                             nosync))

        # where possible, validation is done against the local ui tree elements
        # as opposed to multiple calls to the API - in order to to keep the UI
        # as responsive as possible

        # validate the gateway name is resolvable
        if get_ip(gateway_name) == '0.0.0.0':
            self.logger.error("Gateway '{}' is not resolvable to an ipv4"
                              " address".format(gateway_name))
            return

        # validate the ip_address is valid ipv4
        if get_ip(ip_address) == '0.0.0.0':
            self.logger.error("IP address provided is not usable (name doesn't"
                              " resolve, or not a valid ipv4 address)")
            return

        # validate that the gateway name isn't already known within the
        # configuration
        current_gws = [gw for gw in self.children]
        current_gw_names = [gw.name for gw in current_gws]
        current_gw_portals = [gw.portal_ip_address for gw in current_gws]
        if gateway_name in current_gw_names:
            self.logger.error("'{}' is already defined to the "
                              "configuration".format(gateway_name))
            return

        # validate that the ip address given is NOT already known
        if ip_address in current_gw_portals:
            self.logger.error("'{}' is already defined within the "
                              "configuration".format(ip_address))
            return
        gw_api = '{}://{}:{}/api'.format(self.http_mode,
                                         gateway_name,
                                         settings.config.api_port)

        # check the intended host actually has the requested IP available
        api = APIRequest(gw_api + '/sysinfo/ipv4_addresses')
        api.get()

        if api.response.status_code != 200:
            self.logger.error("ipv4_addresses query to {} failed - check"
                              "rbd-target-gw log, is the API server "
                              "running?".format(gateway_name))

            raise GatewayAPIError("API call to {}, returned status "
                                  "{}".format(gateway_name,
                                              api.response.status_code))

        target_ips = api.response.json()['data']
        if ip_address not in target_ips:
            self.logger.error("{} is not available on {}".format(ip_address,
                                                                 gateway_name))
            self.logger.error("{} IP's are : {}".format(gateway_name,
                                                        ','.join(target_ips)))
            return


        api = APIRequest(gw_api + '/sysinfo/checkconf')
        api.get()
        if api.response.status_code !=200:
            msg = ("checkconf API call to {} failed with "
                   "code".format(gateway_name, api.response.status_code))

            self.logger.error(msg)
            return

        # compare the hash of the new gateways conf file with the local one
        local_hash = gen_file_hash('/etc/ceph/iscsi-gateway.cfg')
        remote_hash = str(api.response.json()['data'])
        if local_hash != remote_hash:
            self.logger.error("/etc/ceph/iscsi-gateway.conf on {} does "
                              "not match the local version. Correct and "
                              "retry".format(gateway_name))
            return

        api = APIRequest(gw_api + '/sysinfo/checkversions')
        api.get()
        if api.response.status_code !=200:
            errors = api.response.json()['data']
            self.logger.error("{} failed rpm/file validation "
                              "checks".format(gateway_name))
            for err_desc in errors:
                self.logger.error("- {}".format(err_desc))
            return

        local_gw = this_host()
        current_gateways = [tgt.name for tgt in self.children]

        if gateway_name == local_gw and len(current_gateways) == 0:
            first_gateway = True
        else:
            first_gateway = False

        if gateway_name != local_gw and len(current_gateways) == 0:
            # the first gateway defined must be the local machine. By doing
            # this the initial create uses 127.0.0.1, and places it's portal IP
            # in the gateway ip list. Once the gateway ip list is defined, the
            # api server can resolve against the gateways - until the list is
            # defined only a request from 127.0.0.1 is acceptable to the api
            self.logger.error("The first gateway defined must be the local "
                              "machine")
            return

        if local_gw in current_gateways:
            current_gateways.remove(local_gw)

        config = self.parent.parent.parent._get_config()
        if not config:
            self.logger.error("Unable to refresh local config"
                              " over API - sync aborted, restart rbd-target-gw"
                              " on {} to sync".format(gateway_name))


        current_disks = config['disks']
        current_clients = config['clients']
        total_objects = (len(current_disks.keys()) +
                         len(current_clients.keys()))
        gateway_ip_list = config['gateways'].get('ip_list', [])
        gateway_ip_list.append(ip_address)

        if total_objects == 0:
            nosync = True

        for endpoint in gateway_ip_list:
            if first_gateway:
                endpoint = '127.0.0.1'

            self.logger.debug("processing endpoint {} for "
                              "{}".format(endpoint,
                                          gateway_name))

            api_endpoint = '{}://{}:{}/api'.format(self.http_mode,
                                                   endpoint,
                                                   settings.config.api_port)

            gateway_rqst = api_endpoint + '/gateway/{}'.format(gateway_name)
            gw_vars = {"target_iqn": self.parent.target_iqn,
                        "gateway_ip_list": ",".join(gateway_ip_list),
                        "mode": "target"}

            api = APIRequest(gateway_rqst, data=gw_vars)
            api.put()
            if api.response.status_code != 200:
                # GW creation failed
                msg = api.response.json()['message']

                self.logger.error("Failed to create gateway {} - "
                                  "{}".format(gateway_name,
                                              msg))

                raise GatewayAPIError(msg)

            # for the new gateway, when sync is selected we need to run the
            # disk api to register all the rbd's to that gateway
            if endpoint == ip_address and not nosync:
                cnt = 1
                total_disks = len(current_disks.keys())
                for disk_key in current_disks:
                    if self.interactive:
                        progress_message("syncing disks {}/{}".format(cnt,
                                                                      total_disks))
                    this_disk = current_disks[disk_key]
                    lun_rqst = api_endpoint + '/disk/{}'.format(disk_key)
                    lun_vars = { "pool": this_disk['pool'],
                                 "size": "0G",
                                 "owner": this_disk['owner'],
                                 "mode": "sync"}

                    api = APIRequest(lun_rqst, data=lun_vars)
                    api.put()
                    if api.response.status_code != 200:
                        msg = api.response.json()['message']
                        self.logger.error("Failed to add {} to {} new "
                                          "tpg : {}".format(disk_key,
                                                            endpoint,
                                                            msg))
                        raise GatewayAPIError(msg)

                    cnt += 1

                if self.interactive:
                    print("")

            # Adding a gateway introduces a new tpg - each tpg MUST have the
            # luns defined so a RTPG call can be responded to correctly, so
            # we need to sync the disks to the new tpg's

            if len(current_disks.keys()) > 0:

                if endpoint != ip_address or not nosync:

                    gw_vars['mode'] = 'map'
                    api = APIRequest(gateway_rqst, data=gw_vars)
                    api.put()
                    if api.response.status_code != 200:
                        # FIXME
                        # GW creation failed - if the failure was severe you'll
                        # see a json issue here.
                        msg = api.response.json()['message']
                        self.logger.error("Failed to map existing disks to new"
                                          " tpg on {} - ".format(endpoint))
                        raise GatewayAPIError(msg)

                if endpoint == ip_address and not nosync:
                    cnt = 1
                    total_clients = len(current_clients.keys())
                    for client_iqn in current_clients:
                        if self.interactive:
                            progress_message("syncing clients {}/{}".format(cnt,
                                                                            total_clients))
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
                            self.logger.error("Problem adding client {} - "
                                              "{}".format(client_iqn,
                                                          api.response.json()['message']))
                            raise GatewayAPIError(msg)
                        cnt += 1

                    # add a new line, to tidy up the display
                    if self.interactive:
                        print("")

        self.logger.debug("Processing complete. Adding gw to UI")
        # Target created OK, get the details back from the gateway and
        # add to the UI. We have to use the new gateway to ensure what
        # we get back is current (the other gateways will lag)
        new_gw_endpoint = '{}://{}:{}/api'.format(self.http_mode,
                                                  gateway_name,
                                                  settings.config.api_port)
        config = self.parent.parent.parent._get_config(endpoint=new_gw_endpoint)
        gw_config = config['gateways'][gateway_name]
        Gateway(self, gateway_name, gw_config)

        self.logger.info('ok')

    def summary(self):

        up_count = len([gw.state for gw in self.children if gw.state == 'UP'])
        gw_count = len(self.children)

        return ("Up: {}/{}, Portals: {}".format(up_count,
                                                gw_count,
                                                gw_count),
                up_count == gw_count)


    def _interactive_shell(self):
        return self.parent.parent.parent.interactive

    interactive = property(_interactive_shell,
                           doc="determine whether the cli is running in "
                               "interactive mode")


class Gateway(UINode):

    display_attributes = ["name",
                          "gateway_ip_list",
                          "portal_ip_address",
                          "inactive_portal_ips",
                          "active_luns",
                          "tpgs"]

    TCP_PORT = 3260

    def __init__(self, parent, gateway_name, gateway_config):
        """
        Create the LIO element
        :param parent: parent object the gateway group object
        :param gateway_config: dict holding the fields that define the gateway
        :return:
        """

        UINode.__init__(self, gateway_name, parent)

        for k, v in gateway_config.iteritems():
            self.__setattr__(k, v)

        self.refresh()

    def refresh(self):

        self.parent.logger.debug("- checking iSCSI port is accessible on "
                                 "{}".format(self.name))
        self.state = self._get_state()

    def _get_state(self):
        """
        determine whether the iscsi port is open based on port 3260 being
        accessible
        :return:
        """

        socket.setdefaulttimeout(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        result = sock.connect_ex((self.portal_ip_address, Gateway.TCP_PORT))
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

        return "UP" if result == 0 else "DOWN"

    def summary(self):

        state = self.state
        return "{} ({})".format(self.portal_ip_address,
                                state), (state == "UP")

