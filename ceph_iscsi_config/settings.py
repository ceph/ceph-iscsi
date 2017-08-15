
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
                "api_ssl_verify": "false",
                "loop_delay": 2,
                "trusted_ip_list": '',          # comma separate list of IPs
                "api_user": "admin",
                "api_password": "admin",
                "ceph_user": "admin",
                "debug": "false",
                "minimum_gateways": 2,
                "ceph_config_dir": '/etc/ceph',
                "priv_key": 'iscsi-gateway.key',
                "pub_key": 'iscsi-gateway-pub.key'
                }

    target_defaults = {"osd_op_timeout": 30,
                       "nopin_response_timeout" : 5,
                       "nopin_timeout" : 5,
                       "qfull_timeout" : 5
                       }

    def __init__(self, conffile='/etc/ceph/iscsi-gateway.cfg'):

        self.size_suffixes = ['M', 'G', 'T']

        self.error = False
        self.error_msg = ''

        config = ConfigParser()
        dataset = config.read(conffile)
        if len(dataset) == 0:
            # no config file present, set up defaults
            self._define_settings(Settings.defaults)
            self._define_settings(Settings.target_defaults)
        else:
            # If we have a file use it to override the defaults
            if config.has_section("config"):
                runtime_settings = dict(Settings.defaults)
                runtime_settings.update(dict(config.items("config")))
                self._define_settings(runtime_settings)

            if config.has_section("target"):
                target_settings = dict(Settings.target_defaults)
                target_settings.update(dict(config.items("target")))
                self._define_settings(target_settings)
            else:
                # We always want these values set to at least the defaults.
                self._define_settings(Settings.target_defaults)

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



