
__author__ = 'pcuzner@redhat.com'

from ConfigParser import ConfigParser
from distutils.util import strtobool

import re

# this module when imported preserves the global values
# defined by the init method allowing other classes to
# access common configuration settings
def init():
    global config
    config = Settings()

class Settings(object):

    defaults = {"cluster_name": "ceph",
                "gateway_keyring": "/etc/ceph/ceph.client.admin.keyring",
                "time_out": 30,
                "api_port": 5000,
                "api_secure": "true",
                "loop_delay": 2,
                "trusted_ip_list": '',                  # comma separate list of IPs
                "api_enabled": 'true',
                "api_user": "admin",
                "api_password": "admin",
                "ceph_user": "admin",
                "debug": "false",
                "minimum_gateways": 2
                }

    def __init__(self, conffile='/etc/ceph/iscsi-gateway.conf'):

        self.size_suffixes = ['M', 'G', 'T']
        self.rbd_map_file = '/etc/ceph/rbdmap'

        self.error = False
        self.error_msg = ''

        config = ConfigParser()
        dataset = config.read(conffile)
        if len(dataset) == 0:
            # no config file present, set up defaults
            self._define_settings(Settings.defaults)
        else:
            # If we have a file use it to override the defaults
            if config.has_section("config"):
                runtime_settings = dict(Settings.defaults)
                runtime_settings.update(dict(config.items("config")))
                self._define_settings(runtime_settings)

        self.cephconf = '/etc/ceph/{}.conf'.format(self.cluster_name)
        if self.api_secure:
            self.api_ssl_verify = False if self.api_secure else None

    def __repr__(self):
        s = ''
        for k in self.__dict__:
            s += "{} = {}\n".format(k, self.__dict__[k])
        return s

    def _define_settings(self, settings):
        """
        receive a settings dict and apply those key/value to the
        current instance, settings that look like numbers are converted
        :param settings: dict of settings
        :return: None
        """

        float_regex = re.compile("^[0-9]*\.{1}[0-9]$")
        int_regex = re.compile("^[0-9]+")

        for k in settings:

            v = settings[k]

            if k == 'trusted_ip_list':
                v = v.split(',') if v else []

            if v in ['true', 'True', 'false', 'False']:
                v = strtobool(v)

            if isinstance(v, str):
                # convert any strings that hold numbers to int/float
                if float_regex.search(settings[k]):
                    v = float(settings[k])

                if int_regex.search(settings[k]):
                    v = int(settings[k])

            self.__setattr__(k, v)



