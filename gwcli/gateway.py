import json
import threading

from gwcli.node import UIGroup, UINode, UIRoot
from gwcli.hostgroup import HostGroups
from gwcli.storage import Disks, TargetDisks
from gwcli.client import Clients
from gwcli.utils import (this_host, response_message, GatewayAPIError,
                         GatewayError, APIRequest, console_message, get_config)

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.utils import (normalize_ip_address, format_lio_yes_no)
from ceph_iscsi_config.target import GWTarget

from gwcli.ceph import CephGroup

from rtslib_fb.utils import normalize_wwn, RTSLibError

# FIXME - code is using a self signed cert common across all gateways
# the embedded urllib3 package will issue warnings when ssl cert validation is
# disabled - so this disable_warnings stops the user interface from being
# bombed
from requests.packages import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ISCSIRoot(UIRoot):

    def __init__(self, shell, scan_threads=1, endpoint=None):
        UIRoot.__init__(self, shell)

        self.error = False
        self.error_msg = ''
        self.interactive = True           # default interactive mode
        self.scan_threads = scan_threads

        if settings.config.api_secure:
            self.http_mode = 'https'
        else:
            self.http_mode = 'http'

        if endpoint is None:

            self.local_api = ('{}://{}:{}/'
                              'api'.format(self.http_mode,
                                           settings.config.api_host,
                                           settings.config.api_port))

        else:
            self.local_api = endpoint

        self.config = {}
        # Establish the root nodes within the UI, for the different components

        self.disks = Disks(self)
        self.ceph = CephGroup(self)
        self.target = ISCSITargets(self)

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

            self.target.refresh(self.config['targets'], self.config['discovery_auth'])

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
            except Exception:
                self.error = True
                self.error_msg = "Malformed REST API response"
                return {}
        else:
            self.error = True
            self.error_msg = "REST API failure, code : " \
                             "{}".format(api.response.status_code)
            return {}

    def export_copy(self, config):

        fmtd_config = json.dumps(config, sort_keys=True,
                                 indent=4, separators=(',', ': '))
        print(fmtd_config)

    def ui_command_export(self, mode='copy'):
        """
        Print the configuration in a format that can be used as a backup.

        The export command supports two modes:

        copy - This prints the internal configuration. It can used for backup
               or for support requests.
        """

        valid_modes = ['copy']

        self.logger.debug("CMD: export mode={}".format(mode))

        if mode not in valid_modes:
            self.logger.error("Invalid export mode requested - supported "
                              "modes are: {}".format(','.join(valid_modes)))
            return

        current_config = self._get_config()

        if mode == 'copy':
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


class ISCSITargets(UIGroup):
    help_intro = '''
                 The iscsi-target group defines the ISCSI Target that the
                 group of gateways will be known as by iSCSI initiators (clients).

                 Only one iSCSI target is allowed, but each target can consist
                 of 2-4 gateway nodes. Multiple gateways are needed to deliver
                 high availability storage to the iSCSI client.

                 '''

    def __init__(self, parent):
        UIGroup.__init__(self, 'iscsi-targets', parent)
        self.gateway_group = {}
        self.auth = None

    def ui_command_create(self, target_iqn):
        """
        Create an iSCSI target. This target is defined across all gateway nodes,
        providing the client with a single 'image' for iscsi discovery.
        """

        self.logger.debug("CMD: /iscsi create {}".format(target_iqn))

        # is the IQN usable?
        try:
            target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
        except RTSLibError:
            self.logger.error("IQN name '{}' is not valid for "
                              "iSCSI".format(target_iqn))
            return

        # 'safe' to continue with the definition
        self.logger.debug("Create an iscsi target definition in the UI")

        local_api = ('{}://{}:{}/api/'
                     'target/{}'.format(self.http_mode,
                                        settings.config.api_host,
                                        settings.config.api_port,
                                        target_iqn))

        api = APIRequest(local_api)
        api.put()

        if api.response.status_code == 200:
            self.logger.info('ok')
            # create the target entry in the UI tree
            target_exists = len([target for target in self.children
                                 if target.name == target_iqn]) > 0
            if not target_exists:
                Target(target_iqn, self)
        else:
            self.logger.error("Failed to create the target on the local node")

            raise GatewayAPIError("iSCSI target creation failed - "
                                  "{}".format(response_message(api.response,
                                                               self.logger)))

    def ui_command_delete(self, target_iqn):
        """
        Delete an iSCSI target.
        """

        self.logger.debug("CMD: /iscsi delete {}".format(target_iqn))

        try:
            target_iqn, iqn_type = normalize_wwn(['iqn'], target_iqn)
        except RTSLibError:
            self.logger.error("IQN name '{}' is not valid for "
                              "iSCSI".format(target_iqn))
            return

        gw_api = ('{}://{}:{}/api/'
                  'target/{}'.format(self.http_mode,
                                    settings.config.api_host,
                                     settings.config.api_port,
                                     target_iqn))

        api = APIRequest(gw_api)
        api.delete()

        if api.response.status_code == 200:
            self.logger.info('ok')
            # delete the target entry from the UI tree
            target_object = [target for target in self.children
                             if target.name == target_iqn][0]
            self.remove_child(target_object)
        else:
            self.logger.error("Failed - {}".format(response_message(api.response, self.logger)))

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
        current_config = get_config()
        for target_iqn, target in current_config['targets'].items():
            num_clients = len(target['clients'].keys())
            if num_clients > 0:
                self.logger.error("{} - Clients({}) must be removed first"
                                  " before clearing the gateway "
                                  "configuration".format(target_iqn,
                                                         num_clients))
                return

        num_disks = len(current_config['disks'].keys())
        if num_disks > 0:
            self.logger.error("Disks({}) must be removed first"
                              " before clearing the gateway "
                              "configuration".format(num_disks))
            return

        for target_iqn, target in current_config['targets'].items():
            target_config = current_config['targets'][target_iqn]

            self.clear_config(target_config['portals'], target_iqn)

    def clear_config(self, gw_list, target_iqn):

        for gw_name in gw_list:

            gw_api = ('{}://{}:{}/api/'
                      '_target/{}'.format(self.http_mode,
                                          gw_name,
                                          settings.config.api_port,
                                          target_iqn))

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
        if 'bookmarks' in self.shell.prefs:
            del self.shell.prefs['bookmarks']

        self.logger.info('ok')

    def ui_command_discovery_auth(self, username=None, password=None, mutual_username=None,
                                  mutual_password=None):
        """
        Discovery authentication can be set to use CHAP/CHAP_MUTUAL by supplying
        username, password, mutual_username, mutual_password

        Specifying 'nochap' will remove discovery authentication.

        e.g.
        auth username=<user> password=<pass> mutual_username=<m_user> mutual_password=<m_pass>

        """

        self.logger.warn("discovery username={}, password={}, mutual_username={}, "
                         "mutual_password={}".format(username, password, mutual_username,
                                                     mutual_password))

        self.logger.debug("CMD: /iscsi discovery_auth")

        if not username:
            self.logger.error("To set or reset discovery authentication, specify either "
                              "username=<user> password=<password> [mutual_username]=<user> "
                              "[mutual_password]=<password> or nochap")
            return

        if username == 'nochap':
            username = ''
            password = ''
            mutual_username = ''
            mutual_password = ''

        self.logger.debug("discovery auth to be set to username='{}', password='{}', "
                          "mutual_username='{}', mutual_password='{}'".format(username, password,
                                                                              mutual_username,
                                                                              mutual_password))

        api_vars = {
            "username": username,
            "password": password,
            "mutual_username": mutual_username,
            "mutual_password": mutual_password
        }
        discoveryauth_api = ('{}://{}:{}/api/'
                             'discoveryauth'.format(self.http_mode,
                                                    settings.config.api_host,
                                                    settings.config.api_port))
        api = APIRequest(discoveryauth_api, data=api_vars)
        api.put()

        if api.response.status_code == 200:
            self._set_auth(username, password, mutual_username, mutual_password)
            self.logger.info('ok')
        else:
            self.logger.error("Error: {}".format(response_message(api.response, self.logger)))
            return

    def _set_auth(self, username, password, mutual_username, mutual_password):
        if mutual_username != '' and mutual_password != '':
            self.auth = "CHAP_MUTUAL"
        elif username != '' and password != '':
            self.auth = "CHAP"
        else:
            self.auth = None

    def refresh(self, targets, discovery_auth):

        self.logger.debug("Refreshing gateway & client information")
        self.reset()
        self._set_auth(discovery_auth['username'],
                       discovery_auth['password'],
                       discovery_auth['mutual_username'],
                       discovery_auth['mutual_password'])
        for target_iqn, target in targets.items():
            tgt = Target(target_iqn, self)
            tgt.controls = target['controls']

            tgt.gateway_group.load(target['portals'])
            tgt.target_disks.load(target['disks'])
            tgt.client_group.load(target['clients'])

    def summary(self):
        return "DiscoveryAuth: {}, Targets: {}".format(self.auth, len(self.children)), None


class Target(UINode):

    display_attributes = ["target_iqn", "control_values"]

    help_intro = '''
                 The iscsi target is the name that the group of gateways are
                 known as by the iscsi initiators (clients).
                 '''

    def __init__(self, target_iqn, parent):
        UIGroup.__init__(self, target_iqn, parent)
        self.target_iqn = target_iqn

        self.control_values = []
        self.controls = {}

        self.gateway_group = GatewayGroup(self)
        self.client_group = Clients(self)
        self.host_groups = HostGroups(self)
        self.target_disks = TargetDisks(self)

    def _get_controls(self):
        return self._controls.copy()

    def _set_controls(self, controls):
        self._controls = controls.copy()
        self._refresh_control_values()

    controls = property(_get_controls, _set_controls)

    def summary(self):
        return "Gateways: {}".format(len(self.gateway_group.children)), None

    def ui_command_reconfigure(self, attribute, value):
        """
        The reconfigure command allows you to tune various gateway attributes.
        An empty value for an attribute resets the lun attribute to its
        default.
        attribute : attribute to reconfigure. supported attributes:
          - cmdsn_depth : integer 1 - 512
          - dataout_timeout : integer 2 - 60
          - nopin_response_timeout : integer 3 - 60
          - nopin_timeout : integer 3 - 60
          - immediate_data : [Yes|No]
          - initial_r2t : [Yes|No]
          - first_burst_length : integer 512 - 16777215
          - max_burst_length : integer 512 - 16777215
          - max_outstanding_r2t : integer 1 - 65535
          - max_recv_data_segment_length : integer 512 - 16777215
          - max_xmit_data_segment_length : integer 512 - 16777215
        value     : value of the attribute to reconfigure
        e.g.
        set cmdsn_depth
          - reconfigure attribute=cmdsn_depth value=128
        reset cmdsn_depth
          - reconfigure attribute=cmdsn_depth value=
        """
        settings_list = GWTarget.SETTINGS
        if attribute not in settings_list:
            self.logger.error("supported attributes: {}".format(",".join(
                sorted(settings_list))))
            return

        # Issue the api request for the reconfigure
        gateways_api = ('{}://{}:{}/api/'
                        'target/{}'.format(self.http_mode,
                                           settings.config.api_host,
                                           settings.config.api_port,
                                           self.target_iqn))

        controls = {attribute: value}
        controls_json = json.dumps(controls)
        api_vars = {'mode': 'reconfigure', 'controls': controls_json}

        self.logger.debug("Issuing reconfigure request: controls={}".format(controls_json))
        api = APIRequest(gateways_api, data=api_vars)
        api.put()

        if api.response.status_code != 200:
            self.logger.error("Failed to reconfigure : "
                              "{}".format(response_message(api.response,
                                                           self.logger)))
            return

        config = self.parent.parent._get_config()
        if not config:
            self.logger.error("Unable to refresh local config")
        self.controls = config['targets'][self.target_iqn]['controls']

        self.logger.info('ok')

    def _refresh_control_values(self):
        self.control_values = {}
        settings_list = GWTarget.SETTINGS
        for k in settings_list:
            val = self._controls.get(k)
            default_val = getattr(settings.config, k, None)
            if k in settings.Settings.LIO_YES_NO_SETTINGS:
                if val is not None:
                    val = format_lio_yes_no(val)
                default_val = format_lio_yes_no(default_val)

            if val is None or str(val) == str(default_val):
                self.control_values[k] = default_val
            else:
                self.control_values[k] = "{} (override)".format(val)


class GatewayGroup(UIGroup):

    help_intro = '''
                 The gateway-group shows you the high level details of the
                 iscsi gateway nodes that have been configured. It also allows
                 you to add further gateways to the configuration, but this
                 requires the API service instance to be started on the new
                 gateway host

                 If in doubt, use Ansible :)
                 '''

    def __init__(self, parent):

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

    def load(self, portal_group):
        for gateway_name in portal_group:
            Gateway(self, gateway_name, portal_group[gateway_name])

        self.check_gateways()

    def ui_command_info(self):
        '''
        List configured gateways.
        '''
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

    def ui_command_delete(self, gateway_name, confirm=None):
        """
        Delete a gateway from the group. This will stop and delete the target
        running on the gateway.

        If this is the last gateway the target is mapped to all objects added
        to it will be removed, and confirm=True is required.
        """

        self.logger.debug("CMD: ../gateways/ delete {} confirm {}".
                          format(gateway_name, confirm))

        self.logger.info("Deleting gateway, {}".format(gateway_name))

        config = self.parent.parent.parent._get_config()
        if not config:
            self.logger.error("Unable to refresh local config over API - sync "
                              "aborted, restart rbd-target-api on {} to "
                              "sync".format(gateway_name))
            return

        target_iqn = self.parent.name

        gw_cnt = len(config['targets'][target_iqn]['portals'])
        if gw_cnt == 0:
            self.logger.error("Target is not mapped to any gateways.")
            return

        if gw_cnt == 1:
            confirm = self.ui_eval_param(confirm, 'bool', False)
            if not confirm:
                self.logger.error("Deleting the last gateway will remove all "
                                  "objects on this target. Use confirm=true")
                return

        gw_api = '{}://{}:{}/api'.format(self.http_mode,
                                         settings.config.api_host,
                                         settings.config.api_port)
        gw_rqst = gw_api + '/gateway/{}/{}'.format(target_iqn, gateway_name)

        api = APIRequest(gw_rqst)
        api.delete()

        msg = response_message(api.response, self.logger)
        if api.response.status_code != 200:
            self.logger.error("Failed : {}".format(msg))
            return

        self.logger.debug("{}".format(msg))
        self.logger.debug("Removing gw from UI")

        gw_object = self.get_child(gateway_name)
        self.remove_child(gw_object)

        config = self.parent.parent.parent._get_config()
        if not config:
            self.logger.error("Could not refresh disaply. Restart gwcli.")
        elif not config['targets'][target_iqn]['portals']:
            # no more gws so everything but the target is dropped.
            disks_object = self.parent.get_child("disks")
            disks_object.reset()

            hosts_grp_object = self.parent.get_child("host-groups")
            hosts_grp_object.reset()

            hosts_object = self.parent.get_child("hosts")
            hosts_object.reset()

    def ui_command_create(self, gateway_name, ip_address, nosync=False,
                          skipchecks='false'):
        """
        Define a gateway to the gateway group for this iscsi target. The
        first host added should be the gateway running the command

        gateway_name ... should resolve to the hostname of the gateway
        ip_address ..... is the IPv4/IPv6 address of the interface the iscsi
                         portal should use
        nosync ......... by default new gateways are sync'd with the
                         existing configuration by cli. By specifying nosync
                         the sync step is bypassed - so the new gateway
                         will need to have it's rbd-target-api daemon
                         restarted to apply the current configuration
                         (default = False)
        skipchecks ..... set this to true to force gateway validity checks
                         to be bypassed(default = false). This is a developer
                         option ONLY. Skipping these checks has the potential
                         to result in an unstable configuration.
        """

        ip_address = normalize_ip_address(ip_address)
        self.logger.debug("CMD: ../gateways/ create {} {} "
                          "nosync={} skipchecks={}".format(gateway_name,
                                                           ip_address,
                                                           nosync,
                                                           skipchecks))

        local_gw = this_host()
        current_gateways = [tgt.name for tgt in self.children]

        if gateway_name != local_gw and len(current_gateways) == 0:
            # the first gateway defined must be the local machine. By doing
            # this the initial create uses localhost, and places it's portal IP
            # in the gateway ip list. Once the gateway ip list is defined, the
            # api server can resolve against the gateways - until the list is
            # defined only a request from localhost is acceptable to the api
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
                              " over API - sync aborted, restart rbd-target-api"
                              " on {} to sync".format(gateway_name))

        target_iqn = self.parent.name
        target_config = config['targets'][target_iqn]
        if nosync:
            sync_text = "sync skipped"
        else:
            sync_text = ("sync'ing {} disk(s) and "
                         "{} client(s)".format(len(target_config['disks']),
                                               len(target_config['clients'])))
        if skipchecks == 'true':
            self.logger.warning("OS version/package checks have been bypassed")

        self.logger.info("Adding gateway, {}".format(sync_text))

        gw_api = '{}://{}:{}/api'.format(self.http_mode,
                                         settings.config.api_host,
                                         settings.config.api_port)
        gw_rqst = gw_api + '/gateway/{}/{}'.format(target_iqn, gateway_name)
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
        target_config = config['targets'][target_iqn]
        portal_config = target_config['portals'][gateway_name]
        Gateway(self, gateway_name, portal_config)

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

        for k, v in gateway_config.items():
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
                  401: {"status": "UNAUTHORIZED",
                        "iscsi": "UNKNOWN", "api": "UP"},
                  403: {"status": "UNAUTHORIZED",
                        "iscsi": "UNKNOWN", "api": "UP"},
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
            if rc not in lookup:
                rc = 999
        except GatewayAPIError:
            rc = 999

        self.state = lookup[rc].get('status')
        self.service_state['iscsi'] = lookup[rc].get('iscsi')
        self.service_state['api'] = lookup[rc].get('api')

    def summary(self):

        state = self.state
        return "{} ({})".format(self.portal_ip_address,
                                state), (state == "UP")
