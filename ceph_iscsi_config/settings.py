
__author__ = 'pcuzner@redhat.com'

from ConfigParser import ConfigParser

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
                "ceph_user": "admin"
                }

    def __init__(self, conffile='/etc/ceph/iscsi-gateway.conf'):

        self.size_suffixes = ['M', 'G', 'T']
        self.loop_delay = 2
        self.rbd_map_file = '/etc/ceph/rbdmap'

        self.error = False
        self.error_msg = ''

        config = ConfigParser()
        dataset = config.read(conffile)
        if len(dataset) == 0:
            # no config file present, set up defaults
            self._define_settings(Settings.defaults)
        else:
            # If we have a
            if config.has_section("config"):
                runtime_settings = dict(Settings.defaults)
                runtime_settings.update(dict(config.items("config")))
                self._define_settings(runtime_settings)

        self.cephconf = '/etc/ceph/{}.conf'.format(self.cluster_name)

    def __repr__(self):
        s = ''
        for k in self.__dict__:
            s += "{} = {}\n".format(k, self.__dict__[k])
        return s

    def _define_settings(self, settings):
        """
        receive a settings dict and apply those key/value to the
        current instance
        :param settings: dict of settings
        :return: None
        """
        for k in settings:
            self.__setattr__(k, settings[k])
