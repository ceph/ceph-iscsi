
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
    LIO_YES_NO_SETTINGS = ["immediate_data", "initial_r2t"]

    _float_regex = re.compile(r"^[0-9]*\.{1}[0-9]$")
    _int_regex = re.compile(r"^[0-9]+$")

    @staticmethod
    def normalize_controls(raw_controls, settings_list):
        """
        Convert a controls dictionary from a json converted or a user input
        dictionary where the values are strings.
        """
        controls = {}

        for key, raw_value in raw_controls.iteritems():
            if key not in settings_list:
                raise ValueError("Supported controls: {}".format(",".join(settings_list)))

            if not raw_value:
                # Use the default/reset.
                controls[key] = None
                continue

            # Do not use normalize() because if the user inputs invalid
            # values we want to pass up more detailed errors.
            if key in Settings.LIO_YES_NO_SETTINGS:
                try:
                    value = Settings.convert_lio_yes_no(raw_value)
                except ValueError:
                    raise ValueError("expected yes or no for {}".format(key))
            else:
                try:
                    value = int(raw_value)
                except ValueError:
                    raise ValueError("expected integer for {}".format(key))

            controls[key] = value

        return controls

    @staticmethod
    def convert_lio_yes_no(value):
        """
        Convert true/false/yes/no to boolean
        """

        value = str(value).lower()
        if value in ['1', 'true', 'yes']:
            return True
        elif value in ['0', 'false', 'no']:
            return False
        raise ValueError(value)

    @staticmethod
    def normalize(k, v):
        if k == 'trusted_ip_list':
            v = v.split(',') if v else []

        if k in Settings.LIO_YES_NO_SETTINGS:
            try:
                v = Settings.convert_lio_yes_no(v)
            except Exception:
                v = True
        elif v in ['true', 'True', 'false', 'False']:
            v = strtobool(v)

        if isinstance(v, str):
            # convert any strings that hold numbers to int/float
            if Settings._float_regex.search(v):
                v = float(v)

            if Settings._int_regex.search(v):
                v = int(v)
        return v

    defaults = {"cluster_name": "ceph",
                "gateway_keyring": "ceph.client.admin.keyring",
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
                "pub_key": 'iscsi-gateway-pub.key',
                "prometheus_exporter": "true",
                "prometheus_port": 9287,
                "prometheus_host": "::"
                }

    target_defaults = {"osd_op_timeout": 30,
                       "dataout_timeout": 20,
                       "nopin_response_timeout": 5,
                       "nopin_timeout": 5,
                       "qfull_timeout": 5,
                       "cmdsn_depth": 128,
                       "immediate_data": "Yes",
                       "initial_r2t": "Yes",
                       "max_outstanding_r2t": 1,
                       "first_burst_length": 262144,
                       "max_burst_length": 524288,
                       "max_recv_data_segment_length": 262144,
                       "max_xmit_data_segment_length": 262144,
                       "max_data_area_mb": 8,
                       "alua_failover_type": "implicit",
                       "hw_max_sectors": "1024"
                       }

    def __init__(self, conffile='/etc/ceph/iscsi-gateway.cfg'):

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

        for k in settings:
            v = settings[k]
            v = self.normalize(k, settings[k])

            self.__setattr__(k, v)
