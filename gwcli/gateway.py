__author__ = 'pcuzner@redhat.com'

import sys
import json

from gwcli.node import UIGroup, UINode, UIRoot
# from requests import delete, put, get, ConnectionError

from gwcli.storage import Disks
from gwcli.client import Clients
from gwcli.utils import (this_host, get_other_gateways,
                         GatewayAPIError, GatewayError,
                         APIRequest)
import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.utils import get_ip

from rtslib_fb.utils import normalize_wwn, RTSLibError
import rtslib_fb.root as root

from gwcli.ceph import Ceph

# FIXME - code is using a self signed cert common across all gateways
# the embedded urllib3 package will issue warnings when ssl cert validation is
# disabled - so this disable_warnings stops the user interface from being
# bombed
from requests.packages import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ISCSIRoot(UIRoot):

    display_attributes = ['http_mode', 'local_api']

    def __init__(self, shell, logger, endpoint=None):
        UIRoot.__init__(self, shell)
        self.config = {}
        self.error = False
        self.error_msg = ''
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

        # Establish the root nodes within the UI, for the different components

        self.disks = Disks(self)
        self.ceph = Ceph(self)
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
            self.logger.critical("Unable to access the configuration object : {}".format(self.error_msg))
            raise GatewayError


    def _get_config(self):

        api = APIRequest(self.local_api + "/config")
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
            self.error_msg = "REST API failure, code : {}".format(api.response.status_code)
            return {}



    def export_ansible(self, config):

        this_gw = this_host()
        ansible_vars = []
        ansible_vars.append("seed_monitor: {}".format(self.ceph.healthy_mon))
        ansible_vars.append("cluster_name: {}".format(settings.config.cluster_name))
        ansible_vars.append("gateway_keyring: {}".format(settings.config.gateway_keyring))
        ansible_vars.append("deploy_settings: true")
        ansible_vars.append("perform_system_checks: true")
        ansible_vars.append('gateway_iqn: "{}"'.format(config['gateways']['iqn']))
        ansible_vars.append('gateway_ip_list: "{}"'.format(",".join(config['gateways']['ip_list'])))
        ansible_vars.append("# rbd device definitions")
        ansible_vars.append("rbd_devices:")

        disk_template = "  - {{ pool: '{}', image: '{}', size: '{}', host: '{}', state: 'present' }}"
        for disk in self.disks.children:

            ansible_vars.append(disk_template.format(disk.pool,
                                                     disk.image,
                                                     disk.size_h,
                                                     this_gw))
        ansible_vars.append("# client connections")
        ansible_vars.append("client_connections:")
        client_template = "  - {{ client: '{}', image_list: '{}', chap:'{}', status: 'present' }}"
        for client in sorted(config['clients'].keys()):
            client_metadata = config['clients'][client]
            lun_data = client_metadata['luns']
            sorted_luns = [s[0] for s in sorted(lun_data.iteritems(), key=lambda (x, y): y['lun_id'])]
            ansible_vars.append(client_template.format(client,
                                                       ','.join(sorted_luns),
                                                       client_metadata['auth']['chap']))
        for var in ansible_vars:
            print(var)

    def export_copy(self, config):

        fmtd_config = json.dumps(config, sort_keys=True, indent=4, separators=(',', ': '))
        print(fmtd_config)


    def ui_command_export(self, mode='ansible'):

        current_config = self._get_config()

        if mode == "ansible":
            self.export_ansible(current_config)
        elif mode == 'copy':
            self.export_copy(current_config)

    def ui_command_info(self):
        print("HTTP mode         : {}".format(self.http_mode))
        print("Rest API port     : {}".format(settings.config.api_port))
        print("Local endpoint    : {}".format(self.local_api))
        print("Ceph Cluster Name : {}".format(settings.config.cluster_name))
        if settings.config.trusted_ip_list:
            display_ips = ','.join(settings.config.trusted_ip_list)
        else:
            display_ips = 'None'
        print("2ndary API IP's   : {}".format(display_ips))


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

        defined_targets = [tgt.name for tgt in self.children]
        if len(defined_targets) > 0:
            self.logger.error("Only ONE iscsi target image is supported")
            return

        # We need LIO to be empty, so check there aren't any targets defined
        local_lio = root.RTSRoot()
        current_target_names = [tgt.wwn for tgt in local_lio.targets]
        if current_target_names:
            self.logger.error("Local LIO instance already has LIO configured with a target - unable to continue")
            raise GatewayError

        # OK - this request is valid, lets make sure the iqn is also valid :P
        try:
            valid_iqn = normalize_wwn(['iqn'], target_iqn)
        except RTSLibError:
            self.logger.error("IQN name '{}' is not valid for iSCSI".format(target_iqn))
            return


        # 'safe' to continue with the definition
        self.logger.debug("Create an iscsi target definition in the UI")
        Target(target_iqn, self)
        self.logger.info('ok')

        # FIXME - should this iqn be committed to the config object?
        # that way when you exit the cli, and then enter again it will be retained

    def ui_command_delete(self, target_iqn):
        # this delete request would need to
        # 1. confirm no sessions for this specific target
        # 2. delete all hosts definitions
        # 3. delete all gateway definitions
        # 4. delete the target
        print "FIXME - not implemented yet"


    def refresh(self):

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
        # self.gateways = [ gw for gw in gateway_group if isinstance(gateway_group[gw], dict)]
        self.target_iqn = target_iqn
        self.gateway_group = GatewayGroup(self)
        self.client_group = Clients(self)



    # def load_gateways(self):
    #     GatewayGroup(self, gateway_group)
    #
    # def load_clients(self):
    #     Clients(self, client_group)

    # def refresh(self):
    #     self.reset()
    #     # self.load_gateways()
    #     # self.load_clients()


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
        # gateway_list = [gw for gw in gateway_group if isinstance(gateway_group[gw], dict)]
        # for gateway_name in gateway_list:
        #     Gateway(self, gateway_name, gateway_group[gateway_name])


    def load(self, gateway_group):
        # define the host entries from the gateway_group dict
        gateway_list = [gw for gw in gateway_group if isinstance(gateway_group[gw], dict)]
        for gateway_name in gateway_list:
            Gateway(self, gateway_name, gateway_group[gateway_name])

    def ui_command_info(self):
        for child in self.children:
            print(child)

    def ui_command_create(self, gateway_name, ip_address):
        """
        Define a gateway to the gateway group for this iscsi target. The
        first host added should be the gateway running the command

        gateway_name ... should resolve to the hostname of the gateway
        ip_address ..... is the IP v4 address of the interface the iscsi
                         portal should use
        """
        # where possible, validation is done against the local ui tree elements
        # as opposed to multiple calls to the API - in order to to keep the UI
        # as responsive as possible

        # validate the gateway name is resolvable
        if get_ip(gateway_name) == '0.0.0.0':
            self.logger.error("Gateway '{}' is not resolvable to an ipv4 address".format(gateway_name))
            return

        # validate the ip_address is valid ipv4
        if get_ip(ip_address) == '0.0.0.0':
            self.logger.error("IP address provided is not usable (name doesn't resolve, or not a valid ipv4 address)")
            return

        # validate that the gateway name isn't already known within the configuration
        current_gws = [gw for gw in self.children]
        current_gw_names = [gw.name for gw in current_gws]
        current_gw_portals = [gw.portal_ip_address for gw in current_gws]
        if gateway_name in current_gw_names:
            self.logger.error("'{}' is already defined to the configuration".format(gateway_name))
            return

        # validate that the ip address given is NOT already known
        if ip_address in current_gw_portals:
            self.logger.error("'{}' is already defined within the configuration".format(ip_address))
            return

        # check the intended host actually has the requested IP available
        api = APIRequest('{}://{}:{}/api/sysinfo/ipv4_addresses'.format(self.http_mode,
                                                                         gateway_name,
                                                                         settings.config.api_port))
        api.get()

        if api.response.status_code != 200:
            self.logger.error("Network query failed to {} - check API server is running".format(gateway_name))
            raise GatewayAPIError("API call to {}, returned status {}".format(gateway_name,
                                                                              api.response.status_code))

        target_ips = api.response.json()['data']
        if ip_address not in target_ips:
            self.logger.error("{} is not available on {}".format(ip_address,
                                                                 gateway_name))
            return

        local_gw = this_host()
        current_gateways = [tgt.name for tgt in self.children]

        if gateway_name != local_gw and len(current_gateways) == 0:
            # the first gateway defined must be the local machine. By doing this
            # the initial create uses 127.0.0.1, and places it's portal IP in the
            # gateway ip list. Once the gateway ip list is defined, the api server
            # can resolve against the gateways - until the list is defined only a
            # request from 127.0.0.1 is acceptable in the api
            self.logger.error("The first gateway defined must be the name of the local machine")
            return

        if local_gw in current_gateways:
            current_gateways.remove(local_gw)

        portals = [tgt.portal_ip_address for tgt in self.children]
        portals.append(ip_address)
        portals_str = ','.join(portals)

        # The local API must be updated first. When the config is empty, the api will
        # accept a 127.0.0.1 request so we have to apply the updates locally first
        api_vars = {"gateway_ip_list": portals_str,
                    "target_iqn": self.parent.target_iqn}
        api = APIRequest('{}://127.0.0.1:{}/api/gateway/{}'.format(self.http_mode,
                                                                   settings.config.api_port,
                                                                   gateway_name),
                         data=api_vars)
        api.put()


        # response = put(local_api,
        #                data=api_vars,
        #                auth=(settings.config.api_user, settings.config.api_password),
        #                verify=settings.config.api_ssl_verify)

        if api.response.status_code == 200:
            self.logger.debug("- gateway '{}' added locally".format(gateway_name))
            current_gateways.append(gateway_name)
            for gw in current_gateways:
                gateway_api = '{}://{}:{}/api/gateway/{}'.format(self.http_mode,
                                                                 gw,
                                                                 settings.config.api_port,
                                                                 gw)
                api = APIRequest(gateway_api, data=api_vars)
                api.put()
                # response = put(gateway_api,
                #                data=api_vars,
                #                auth=(settings.config.api_user, settings.config.api_password),
                #                verify=settings.config.api_ssl_verify)

                if api.response.status_code == 200:
                    self.logger.debug("- gateway defined on {}".format(gw))
                    continue
                else:

                    error_msg = "gateway definition failed on {}, with http status {}".format(gw,
                                                                                              response.status_code)
                    self.logger.error(error_msg)
                    raise GatewayAPIError(api.response.json()['message'])

            # Get the gateways metadata to use for the local gateway object in the UI
            new_gw = '{}://{}:{}/api/gateway/{}'.format(self.http_mode,
                                                        gateway_name,
                                                        settings.config.api_port,
                                                        gateway_name)
            api = APIRequest(new_gw)
            api.get()
            # response = get(new_gw,
            #                auth=(settings.config.api_user, settings.config.api_password),
            #                verify=settings.config.api_ssl_verify)

            if api.response.status_code == 200:

                gateway_config = api.response.json()
                Gateway(self, gateway_name, gateway_config)
                self.logger.info('ok')

            else:
                raise GatewayAPIError("Unable to read the gateway info from the config - status code: {}".format(api.response.status_code))
        else:
            raise GatewayAPIError("Unable to define the gateway ({})\n{} ".format(api.response.status_code,
                                                                                  api.response.json()['message']))




    def summary(self):

        return "Portals: {}".format(len(self.children)), True


class Gateway(UINode):

    display_attributes = ["name",
                          "gateway_ip_list",
                          "portal_ip_address",
                          "inactive_portal_ips",
                          "active_luns",
                          "tpgs"]

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

    def summary(self):
        return self.portal_ip_address, True
