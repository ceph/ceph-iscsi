__author__ = 'pcuzner@redhat.com'

import sys
import json

# FIXME - relative imports
from gwcli.node import UIGroup, UINode, UIRoot
from requests import delete, put, get, ConnectionError

from gwcli.storage import Disks
from gwcli.client import Clients
from gwcli.utils import this_host
import ceph_iscsi_config.settings as settings

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
            # print("Unable to access the configuration object : {}".format(self.error_msg))
            sys.exit(16)

    def _get_config(self):
        try:
            response = get(self.local_api + "/config",
                           auth=(settings.config.api_user, settings.config.api_password),
                           verify=settings.config.api_ssl_verify)

        except ConnectionError as e:
            self.error = True
            self.error_msg = "API unavailable @ {}".format(self.local_api)
            return {}

        if response.status_code == 200:
            return response.json()
        else:
            self.error = True
            self.error_msg = "REST API failure, code : {}".format(response.status_code)
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

    def ui_command_refresh(self):

        print "not implemented yet"
        # self.target.reset()
        # self.disks.reset()
        # self.clients.reset()

        # self.refresh()

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
        self.gateway_group = {}
        self.client_group = {}

    def reset(self):
        children = set(self.children)  # set of child objects
        for child in children:
            self.remove_child(child)

    def refresh(self):

        if 'iqn' in self.gateway_group:
            Target(self.gateway_group, self.client_group, self)

    def summary(self):
        return "Targets: {}".format(len(self.children)), None

class Target(UIGroup):
    help_info = '''
                definition of iscsi target
                '''
    def __init__(self, gateway_group, client_group, parent):
        UIGroup.__init__(self, gateway_group['iqn'], parent)
        self.gateways = [ gw for gw in gateway_group if isinstance(gateway_group[gw], dict)]

        # if we have gateways, add it's subtree under the target iqn
        if self.gateways:
            GatewayGroup(self, gateway_group)

        # if we have clients, add the subtree here
        if client_group:
            Clients(self, client_group)

    def summary(self):
        return "Gateways: {}".format(len(self.gateways)), None

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

    def __init__(self,  parent, gateway_group):

        UIGroup.__init__(self, 'gateways', parent)

        gateway_list = [gw for gw in gateway_group if isinstance(gateway_group[gw], dict)]
        for gateway_name in gateway_list:
            Gateway(self, gateway_name, gateway_group[gateway_name])


    def reset(self):
        self.iqn = ''
        children = set(self.children)  # set of child objects
        for child in children:
            self.remove_child(child)

    def ui_command_info(self):
        for child in self.children:
            print(child)

    def ui_command_create(self):
        """
        Define the gateway group
        :return:
        """

        pass

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
