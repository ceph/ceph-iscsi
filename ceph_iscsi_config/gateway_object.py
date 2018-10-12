#!/usr/bin/env python

import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.utils import CephiSCSIError


class GWObject(object):
    def __init__(self, cfg_type, cfg_type_key, logger, control_settings):
        self.control_settings = control_settings
        self.cfg_type = cfg_type
        self.cfg_type_key = cfg_type_key
        self.logger = logger

        self.config = Config(self.logger)
        if self.config.error:
            raise CephiSCSIError(self.config.error_msg)

        # Copy of controls that will not be written until commit is called.
        # To update the kernel call the child object's update function.
        self.controls = self._get_config_controls().copy()
        self._add_properies()

    def _set_config_controls(self, config, controls):
        if self.cfg_type_key:
            config.config[self.cfg_type][self.cfg_type_key]['controls'] = controls
        else:
            config.config['controls'] = controls

    def _get_config_controls(self):
        # global controls
        if self.cfg_type == 'controls':
            return self.config.config.get('controls', {})

        # This might be the initial creation so it will not be in the
        # config yet
        if self.cfg_type_key in self.config.config[self.cfg_type]:
            return self.config.config[self.cfg_type][self.cfg_type_key].get('controls', {})
        else:
            return {}

    def _get_control(self, key):
        value = self.controls.get(key, None)
        if value is not None:
            value = settings.Settings.normalize(key, value)
        if value is None:
            return getattr(settings.config, key)
        return value

    def _set_control(self, key, value):
        if value is None or \
           settings.Settings.normalize(key, value) == getattr(settings.config, key):
            self.controls.pop(key, None)
        else:
            self.controls[key] = value

    def _add_properies(self):
        for k in self.control_settings:
            setattr(GWObject, k,
                    property(lambda self, k=k: self._get_control(k),
                             lambda self, v, k=k: self._set_control(k, v)))

    def commit_controls(self):
        committed_controls = self._get_config_controls()

        if self.controls != committed_controls:
            # update our config
            self._set_config_controls(self.config, self.controls)

            # update remote config
            if self.cfg_type == 'controls':
                self.config.update_item(self.cfg_type, self.cfg_type_key,
                                        self.controls)
            else:
                updated_obj = self.config.config[self.cfg_type][self.cfg_type_key]
                self.config.update_item(self.cfg_type, self.cfg_type_key,
                                        updated_obj)

        self.config.commit()
        if self.config.error:
            raise CephiSCSIError(self.config.error_msg)
