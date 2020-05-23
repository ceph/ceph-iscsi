
__author__ = 'pcuzner@redhat.com'

try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser

import hashlib
import json
import re

from ceph_iscsi_config.gateway_setting import (TGT_SETTINGS, SYS_SETTINGS,
                                               TCMU_SETTINGS,
                                               TCMU_DEV_STATUS_SETTINGS)


# this module when imported preserves the global values
# defined by the init method allowing other classes to
# access common configuration settings
def init():
    global config
    config = Settings()


class Settings(object):
    _float_regex = re.compile(r"^[0-9]*\.{1}[0-9]$")
    _int_regex = re.compile(r"^[0-9]+$")

    @staticmethod
    def normalize_controls(raw_controls, settings_list):
        """
        Convert a controls dictionary from a json converted or a user input
        dictionary where the values are strings.
        """
        controls = {}

        for key, raw_value in raw_controls.items():
            setting = settings_list.get(key)
            if setting is None:
                raise ValueError("Supported controls: {}".format(",".join(settings_list.keys())))

            if raw_value in [None, '']:
                # Use the default/reset.
                controls[key] = None
                continue

            controls[key] = setting.normalize(raw_value)

        return controls

    exclude_from_hash = ["cluster_client_name",
                         "logger_level"
                         ]

    def __init__(self, conffile='/etc/ceph/iscsi-gateway.cfg'):

        self.error = False
        self.error_msg = ''

        config = ConfigParser()
        dataset = config.read(conffile)

        self._add_attrs_from_defs(SYS_SETTINGS)
        self._add_attrs_from_defs(TGT_SETTINGS)
        self._add_attrs_from_defs(TCMU_SETTINGS)
        self._add_attrs_from_defs(TCMU_DEV_STATUS_SETTINGS)

        if len(dataset) != 0:
            # If we have a file use it to override the defaults
            if config.has_section("config"):
                self._override_attrs_from_conf(config.items("config"),
                                               SYS_SETTINGS)

            if config.has_section("device_status"):
                self._override_attrs_from_conf(config.items("device_status"),
                                               TCMU_DEV_STATUS_SETTINGS)

            if config.has_section("target"):
                all_settings = TGT_SETTINGS.copy()
                all_settings.update(TCMU_SETTINGS)

                self._override_attrs_from_conf(config.items("target"),
                                               all_settings)

        self.cephconf = '{}/{}.conf'.format(self.ceph_config_dir, self.cluster_name)
        if self.api_secure:
            self.api_ssl_verify = False if self.api_secure else None

    def __repr__(self):
        s = ''
        for k in self.__dict__:
            s += "{} = {}\n".format(k, self.__dict__[k])
        return s

    def _add_attrs_from_defs(self, def_settings):
        """
        receive a settings dict and apply those key/value to the
        current instance, settings that look like numbers are converted
        :param settings: array of setting objects
        :return: None
        """
        for k, setting in def_settings.items():
            self.__setattr__(k, setting.def_val)

    def _override_attrs_from_conf(self, config, def_settings):
        """
        receive a settings dict and apply those key/value to the
        current instance, settings that look like numbers are converted
        :param settings: dict of settings
        :return: None
        """
        for k, v in config:
            if hasattr(self, k):
                setting = def_settings[k]
                try:
                    self.__setattr__(k, setting.normalize(v))
                except ValueError:
                    # We do not even have the logger up yet, so just ignore
                    # so the deamons can still start
                    pass

    def _hash_settings(self, def_settings, sync_settings):
        for setting in def_settings:
            if setting not in Settings.exclude_from_hash:
                sync_settings[setting] = getattr(self, setting)

    def hash(self):
        """
        Generates a sha256 hash of the settings that are required to be in sync between gateways.
        :return: checksum (str)
        """

        sync_settings = {}
        self._hash_settings(SYS_SETTINGS.keys(), sync_settings)
        self._hash_settings(TGT_SETTINGS.keys(), sync_settings)
        self._hash_settings(TCMU_SETTINGS.keys(), sync_settings)
        self._hash_settings(TCMU_DEV_STATUS_SETTINGS.keys(), sync_settings)

        h = hashlib.sha256()
        h.update(json.dumps(sync_settings).encode('utf-8'))
        return h.hexdigest()
