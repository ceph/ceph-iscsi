import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.common import Config
from ceph_iscsi_config.utils import CephiSCSIError


class GWObject(object):
    def __init__(self, cfg_type, cfg_type_key, logger, control_settings):
        self.cfg_type = cfg_type
        self.cfg_type_key = cfg_type_key
        self.logger = logger

        self.config = Config(self.logger)
        if self.config.error:
            raise CephiSCSIError(self.config.error_msg)

        # Copy of controls that will not be written until commit is called.
        # To update the kernel call the child object's update function.
        self.controls = self._get_config_controls().copy()
        self._add_properies(control_settings)

    def _set_config_controls(self, config, controls):
        config.config[self.cfg_type][self.cfg_type_key]['controls'] = controls

    def _get_config_controls(self):
        # This might be the initial creation so it will not be in the
        # config yet
        if self.cfg_type_key in self.config.config[self.cfg_type]:
            return self.config.config[self.cfg_type][self.cfg_type_key].get('controls', {})
        else:
            return {}

    def _get_control(self, key, setting):
        value = self.controls.get(key, None)
        if value is None:
            return getattr(settings.config, key)

        return setting.normalize(value)

    def _set_control(self, key, value):
        if value is None or value == getattr(settings.config, key):
            self.controls.pop(key, None)
        else:
            self.controls[key] = value

    def _add_properies(self, control_settings):
        for k, setting in control_settings.items():
            setattr(GWObject, k,
                    property(lambda self, k=k, s=setting: self._get_control(k, s),
                             lambda self, v, k=k: self._set_control(k, v)))

    def update_controls(self):
        committed_controls = self._get_config_controls()

        if self.controls != committed_controls:
            # update our config
            self._set_config_controls(self.config, self.controls)

            updated_obj = self.config.config[self.cfg_type][self.cfg_type_key]
            self.config.update_item(self.cfg_type, self.cfg_type_key,
                                    updated_obj)

    def commit_controls(self):
        self.update_controls()
        self.config.commit()
        if self.config.error:
            raise CephiSCSIError(self.config.error_msg)
