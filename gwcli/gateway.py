#!/usr/bin/env python

import json
import threading

from gwcli.node import UIGroup, UINode, UIRoot
from gwcli.hostgroup import HostGroups
from gwcli.storage import Disks
from gwcli.client import Clients, CHAP
from gwcli.utils import (this_host, response_message, GatewayAPIError,
                         GatewayError, APIRequest, console_message, valid_iqn)

import ceph_iscsi_config.settings as settings

import rtslib_fb.root as root

from gwcli.ceph import CephGroup

# FIXME - code is using a self signed cert common across all gateways
# the embedded urllib3 package will issue warnings when ssl cert validation is
# disabled - so this disable_warnings stops the user interface from being
# bombed
from requests.packages import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ISCSIRoot(UIRoot):

    def __init__(self, shell, endpoint=None):
        UIRoot.__init__(self, shell)

        self.error = False
        self.error_msg = ''
        self.interactive = True           # default interactive mode

        if settings.config.api_secure:
            self.http_mode = 'https'
        else:
            self.http_mode = 'http'

        if endpoint is None:

            self.local_api = ('{}://127.0.0.1:{}/'
                              'api'.format(self.http_mode,
                                           settings.config.api_port))

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

        if api.response.status_code == 200:
            try:
                return api.response.json()
            except:
                self.error = True
                self.error_msg = "Malformed REST API response"
                return {}
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
        valid_modes = ['ansible', 'copy']

        self.logger.debug("CMD: export mode={}".format(mode))

        if mode not in valid_modes:
            self.logger.error("Invalid export mode requested - supported "
                              "modes are: {}".format(','.join(valid_modes)))
            return

        current_config = self._get_config()
        if not current_config.get('gateways'):
            self.logger.error("Export requested, but the config is empty")
            return

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
                 The iscsi-target group defines the ISCSI Target that the 
                 group of gateways will be known as by iSCSI initiators (clients).
                 
                 Only one iSCSI target is allowed, but each target can consist
                 of 2-4 gateway nodes. Multiple gateways are needed to deliver 
                 high availability storage to the iSCSI client.

                 '''

    def __init__(self, parent):
        UIGroup.__init__(self, 'iscsi-target', parent)
        self.gateway_group = {}
        self.client_group = {}

    def ui_command_create(self, target_iqn):
        """
        Create an iSCSI target. This target is defined across all gateway nodes,
        providing the client with a single 'image' for iscsi discovery.

        Only ONE iSCSI target is supported, at this time.
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
            return

        # OK - this request is valid, but is the IQN usable?
        if not valid_iqn(target_iqn):
            self.logger.error("IQN name '{}' is not valid for "
                              "iSCSI".format(target_iqn))
            return


        # 'safe' to continue with the definition
        self.logger.debug("Create an iscsi target definition in the UI")

        local_api = ('{}://127.0.0.1:{}/api/'
                     'target/{}'.format(self.http_mode,
                                        settings.config.api_port,
                                        target_iqn))

        api = APIRequest(local_api)
        api.put()

        if api.response.status_code == 200:
            self.logger.info('ok')
            # create the target entry in the UI tree
            Target(target_iqn, self)
        else:
            self.logger.error("Failed to create the target on the local node")

            raise GatewayAPIError("iSCSI target creation failed - "
                                  "{}".format(response_message(api.response,
                                                               self.logger)))

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
        local_api = ("{}://127.0.0.1:{}/api/"
                     "config".format(self.http_mode,
                                     settings.config.api_port))

        api = APIRequest(local_api)
        api.get()

        if api.response.status_code != 200:
            self.logger.error("Unable to get fresh copy of the configuration")
            raise GatewayAPIError

        try:
            current_config = api.response.json()
        except:
            self.logger.error("Malformed REST API response")
            raise GatewayAPIError

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

        this_gw = this_host()
        if this_gw not in gw_list:
            self.logger.warning("Executor({}) must be in gateway list: "
                              "{}".format(this_gw, gw_list))
            return

        gw_list.remove(this_gw)
        gw_list.append(this_gw)

        for gw_name in gw_list:

            gw_api = ('{}://{}:{}/api/'
                      '_gateway/{}'.format(self.http_mode,
                                           gw_name,
                                           settings.config.api_port,
                                           gw_name))

            api = APIRequest(gw_api)
            api.delete()
            if api.response.status_code != 200:
                msg = response_message(api.response, self.logger)
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
                The iscsi target is the name that the group of gateways are 
                known as by the iscsi initiators (clients).
                '''

    def __init__(self, target_iqn, parent):

        UIGroup.__init__(self, target_iqn, parent)
        self.target_iqn = target_iqn
        self.gateway_group = GatewayGroup(self)
        self.client_group = Clients(self)
        self.host_groups = HostGroups(self)

    def summary(self):
        return "Gateways: {}".format(len(self.gateway_group.children)), None


class GatewayGroup(UIGroup):

    help_intro = '''
                 The gateway-group shows you the high level details of the
                 iscsi gateway nodes that have been configured. It also allows
                 you to add further gateways to the configuration, but this
                 requires the API service instance to be started on the new 
                 gateway host

                 If in doubt, use Ansible :)
                 '''

    def __init__(self,  parent):

        UIGroup.__init__(self, 'gateways', parent)

        self.thread_lock = threading.Lock()
        self.check_interval = 10           # check gateway state every 'n' secs
        self.last_state = 0

        # record the shortcut
        shortcut = self.shell.prefs['bookmarks'].get('gateways', None)
        if not shortcut or shortcut is not self.path:

            self.shell.prefs['bookmarks']['gateways'] = self.path
            self.shell.prefs.save()
            self.shell.log.debug("Bookmarked %s as %s."
                                 % (self.path, 'gateways'))

    @property
    def gateways_down(self):
        return len([gw for gw in self.children
                    if gw.state != 'UP'])

    def load(self, gateway_group):
        # define the host entries from the gateway_group dict
        gateway_list = [gw for gw in gateway_group
                        if isinstance(gateway_group[gw], dict)]
        for gateway_name in gateway_list:
            Gateway(self, gateway_name, gateway_group[gateway_name])

        self.check_gateways()

    def ui_command_info(self):

        self.logger.debug("CMD: ../gateways/ info")

        for child in self.children:
            console_message(child)

    def check_gateways(self):

        check_thread = threading.Timer(self.check_interval,
                                       self.check_gateways)
        check_thread.daemon = True
        check_thread.start()
        self.refresh()

    def refresh(self, mode='auto'):

        self.thread_lock.acquire()

        if len(self.children) > 0:
            for gw in self.children:
                gw.refresh(mode)
        else:
            pass

        gateways_down = self.gateways_down
        if gateways_down != self.last_state:
            if gateways_down == 0:
                self.logger.info("\nAll gateways accessible")
            else:
                err_str = "gateway is" if gateways_down == 1 else "gateways are"
                self.logger.warning("\n{} {} inaccessible - updates will "
                                    "be disabled".format(gateways_down,
                                                         err_str))
            self.last_state = gateways_down

        self.thread_lock.release()


    def ui_command_refresh(self):
        """
        refresh allows you to refresh the connection status of each of the
        configured gateways (i.e. check the up/down state).
        """
        num_gw = len(self.children)
        if num_gw > 0:
            self.logger.debug("{} gateways to refresh".format(num_gw))
            self.refresh(mode='interactive')
        else:
            self.logger.error("No gateways to refresh")

    def ui_command_create(self, gateway_name, ip_address, nosync=False,
                          skipchecks='false'):
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
                         (default = False)
        skipchecks ..... set this to true to force gateway validity checks
                         to be bypassed(default = False). This is a developer
                         option ONLY. Skipping these checks has the potential
                         to result in an unstable configuration.
        """

        self.logger.debug("CMD: ../gateways/ create {} {} "
                          "nosync={} skipchecks={}".format(gateway_name,
                                                           ip_address,
                                                           nosync,
                                                           skipchecks))

        local_gw = this_host()
        current_gateways = [tgt.name for tgt in self.children]

        if gateway_name != local_gw and len(current_gateways) == 0:
            # the first gateway defined must be the local machine. By doing
            # this the initial create uses 127.0.0.1, and places it's portal IP
            # in the gateway ip list. Once the gateway ip list is defined, the
            # api server can resolve against the gateways - until the list is
            # defined only a request from 127.0.0.1 is acceptable to the api
            self.logger.error("The first gateway defined must be the local "
                              "machine")
            return

        if skipchecks not in ['true', 'false']:
            self.logger.error("skipchecks must be either true or false")
            return

        if local_gw in current_gateways:
            current_gateways.remove(local_gw)

        config = self.parent.parent.parent._get_config()
        if not config:
            self.logger.error("Unable to refresh local config"
                              " over API - sync aborted, restart rbd-target-gw"
                              " on {} to sync".format(gateway_name))

        if nosync:
            sync_text = "sync skipped"
        else:
            sync_text = ("sync'ing {} disk(s) and "
                         "{} client(s)".format(len(config['disks']),
                                               len(config['clients'])))
        if skipchecks == 'true':
            self.logger.warning("OS version/package checks have been bypassed")

        self.logger.info("Adding gateway, {}".format(sync_text))

        gw_api = '{}://{}:{}/api'.format(self.http_mode,
                                         "127.0.0.1",
                                         settings.config.api_port)
        gw_rqst = gw_api + '/gateway/{}'.format(gateway_name)
        gw_vars = {"nosync": nosync,
                   "skipchecks": skipchecks,
                   "ip_address": ip_address}

        api = APIRequest(gw_rqst, data=gw_vars)
        api.put()

        msg = response_message(api.response, self.logger)
        if api.response.status_code != 200:
            self.logger.error("Failed : {}".format(msg))
            return

        self.logger.debug("{}".format(msg))
        self.logger.debug("Adding gw to UI")

        # Target created OK, get the details back from the gateway and
        # add to the UI. We have to use the new gateway to ensure what
        # we get back is current (the other gateways will lag until they see
        # epoch xattr change on the config object)
        new_gw_endpoint = ('{}://{}:{}/'
                           'api'.format(self.http_mode,
                                        gateway_name,
                                        settings.config.api_port))

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

    @property
    def interactive(self):
        """determine whether the cli is running in interactive mode"""
        return self.parent.parent.parent.interactive


class Gateway(UINode):

    display_attributes = ["name",
                          "gateway_ip_list",
                          "portal_ip_address",
                          "inactive_portal_ips",
                          "active_luns",
                          "tpgs",
                          "service_state"]

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

        self.state = "DOWN"
        self.service_state = {"iscsi": "DOWN",
                              "api": "DOWN"}

        self.refresh()

    def ui_command_refresh(self):
        """
        The refresh command will initiate a check against the gateway node,
        checking that the API is available, and that the iscsi port is
        listening
        """

        self.refresh()

    def refresh(self, mode="interactive"):

        if mode == 'interactive':
            self.logger.debug("- checking iSCSI/API ports on "
                              "{}".format(self.name))
        self._get_state()

    def _get_state(self):
        """
        Determine iSCSI and gateway API service state using the _ping api
        endpoint
        :return:
        """

        lookup = {200: {"status": "UP",
                        "iscsi": "UP", "api": "UP"},
                  500: {"status": "UNKNOWN",
                        "iscsi": "UNKNOWN", "api": "UNKNOWN"},
                  503: {"status": "PARTIAL",
                        "iscsi": "DOWN", "api": "UP"},
                  999: {"status": "UNKNOWN",
                        "iscsi": "UNKNOWN", "api": "UNKNOWN"},
                  }

        gw_api = '{}://{}:{}/api/_ping'.format(self.http_mode,
                                               self.name,
                                               settings.config.api_port)
        api = APIRequest(gw_api)
        try:
            api.get()
            rc = api.response.status_code
        except GatewayAPIError:
            rc = 999

        self.state = lookup[rc].get('status')
        self.service_state['iscsi'] = lookup[rc].get('iscsi')
        self.service_state['api'] = lookup[rc].get('api')

    def summary(self):

        state = self.state
        return "{} ({})".format(self.portal_ip_address,
                                state), (state == "UP")
