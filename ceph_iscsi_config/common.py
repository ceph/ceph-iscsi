#!/usr/bin/env python

import rados
import time
import json
import os
import sys
import traceback

class ConfigTransaction(object):

    def __init__(self, cfg_type, element_name, txn_action='add', initial_value=None):

        self.type = cfg_type
        self.action = txn_action
        self.item_name = element_name

        init_state = {} if initial_value is None else initial_value
        self.item_content = init_state

    def __repr__(self):
        return str(self.__dict__)


class CephCluster(object):

    def __init__(self,
                 conf_file='/etc/ceph/ceph.conf',
                 conf_keyring='/etc/ceph/ceph.client.admin.keyring'):
        self.error = False
        self.error_msg = ''
        self.cluster = rados.Rados(conffile=conf_file,
                                   conf=dict(keyring=conf_keyring))
        try:
            self.cluster.connect()
        except rados.Error as err:
            self.error = True
            self.error_msg = "Unable to connect to the cluster (keyring missing?) - {}".format(err)


    def shutdown(self):
        self.cluster.shutdown()


class Config(object):

    seed_config = {
                    "disks": {},
                    "gateways": {},
                    "clients": {},
                    "epoch": 0
                    }

    lock_time_limit = 30

    def __init__(self, logger, cfg_name='gateway.conf', pool='rbd'):
        self.logger = logger
        self.config_name = cfg_name
        self.pool = pool
        self.ceph = None
        self.platform = Config.get_platform()
        self.error = False
        self.reset = False
        self.error_msg = ""
        self.txn_list = []
        self.config_locked = False

        # self.txn_ptr = 0

        if self.platform == 'rbd':
            self.ceph = CephCluster()
            if self.ceph.error:
                self.error = True
                self.error_msg = self.ceph.error_msg
                return
            else:
                # connection to the ceph cluster is OK to use
                self.get_config = self._get_rbd_config
                self.commit_config = self._commit_rbd
        else:
            self.error = True
            self.error_msg = "Unsupported platform - rbd only (for now!)"

        self.config = self.get_config()
        self.changed = False

    def _get_rbd_config(self):

        cfg_dict = {}

        try:
            self.logger.debug("(_get_rbd_config) Opening connection to {} pool".format(self.pool))
            ioctx = self.ceph.cluster.open_ioctx(self.pool)       # open connection to pool
        except rados.ObjectNotFound:
            self.error = True
            self.error_msg = "'{}' pool does not exist!".format(self.pool)
            self.logger.error("(Config._get_rbd_config) {}".format(self.error_msg))
            return {}

        try:
            cfg_data = ioctx.read(self.config_name)
            ioctx.close()
        except rados.ObjectNotFound:
            # config object is not there, create a seed config
            self.logger.debug("(_get_rbd_config) config object doesn't exist..seeding it")
            self._seed_rbd_config()
            if self.error:
                self.logger.error("(Config._get_rbd_config) Unable to seed the config object")
                return {}
            else:
                cfg_data = json.dumps(Config.seed_config)

        if cfg_data:
            self.logger.debug("(_get_rbd_config) config object contains '{}'".format(cfg_data))
            cfg_dict = json.loads(cfg_data)
        else:
            self.logger.debug("(_get_rbd_config) config object exists, but is empty '{}'".format(cfg_data))
            self._seed_rbd_config()
            if self.error:
                self.logger.error("(Config._get_rbd_config) Unable to seed the config object")
                return {}
            else:
                cfg_dict = Config.seed_config

        return cfg_dict

    def lock(self):

        ioctx = self.ceph.cluster.open_ioctx(self.pool)

        secs = 0

        while secs < Config.lock_time_limit:
            try:
                ioctx.lock_exclusive(self.config_name, 'lock', 'config')
                self.config_locked = True
                break
            except rados.ObjectBusy:
                self.logger.debug("(Config.lock) waiting for excl lock on {} object".format(self.config_name))
                time.sleep(1)
                secs += 1

        if secs >= Config.lock_time_limit:
            self.error = True
            self.error_msg = ("Timed out ({}) waiting for excl "
                              "lock on {} object".format(Config.lock_time_limit, self.config_name))
            self.logger.error("(Config.lock) {}".format(self.error_msg))

        ioctx.close()

    def unlock(self):
        ioctx = self.ceph.cluster.open_ioctx(self.pool)

        try:
            ioctx.unlock(self.config_name, 'lock', 'config')
            self.config_locked = False
        except Exception as e:
            self.error = True
            self.error_msg = ("Unable to unlock {} - {}".format(self.config_name,
                                                                traceback.format_exc()))
            self.logger.error("(Config.unlock) {}".format(self.error_msg))

        ioctx.close()

    def _seed_rbd_config(self):

        ioctx = self.ceph.cluster.open_ioctx(self.pool)

        self.lock()
        if self.error:
            return

        # if the config object is empty, seed it - if not just leave as is
        cfg_data = ioctx.read(self.config_name)
        if not cfg_data:
            self.logger.debug("_seed_rbd_config found empty config object")
            seed = json.dumps(Config.seed_config, sort_keys=True, indent=4, separators=(',', ': '))
            ioctx.write_full(self.config_name, seed)
            ioctx.set_xattr(self.config_name, "epoch", "0")
            self.changed = True

        self.unlock()

        ioctx.close()

    def _get_glfs_config(self):
        pass

    def refresh(self):
        self.logger.debug("config refresh - current config is {}".format(self.config))
        self.config = self.get_config()

    def add_item(self, cfg_type, element_name, initial_value=None):
        init_state = {} if initial_value is None else initial_value
        self.config[cfg_type][element_name] = init_state
        self.logger.debug("(Config.add_item) config updated to {}".format(self.config))
        self.changed = True

        txn = ConfigTransaction(cfg_type, element_name, initial_value=init_state)
        self.txn_list.append(txn)
        # self.txn_ptr = len(self.txn_list) - 1

    def del_item(self, cfg_type, element_name):
        self.changed = True
        del self.config[cfg_type][element_name]
        self.logger.debug("(Config.del_item) config updated to {}".format(self.config))

        txn = ConfigTransaction(cfg_type, element_name, 'delete')
        self.txn_list.append(txn)
        # self.txn_ptr = len(self.txn_list) - 1

    def update_item(self, cfg_type, element_name, element_value):
        self.config[cfg_type][element_name] = element_value
        self.logger.debug("(Config.update_item) config is {}".format(self.config))
        self.changed = True
        self.logger.debug("update_item: type={}, item={}, update={}".format(cfg_type, element_name, element_value))
        # self.logger.debug("update_item point ; txn list length is {}, ptr is set to {}".format(len(self.txn_list),
        #                                                                                            self.txn_ptr))
        txn = ConfigTransaction(cfg_type, element_name, 'add')
        txn.item_content = element_value
        self.txn_list.append(txn)
        # self.txn_ptr = len(self.txn_list) - 1

    def _commit_rbd(self, post_action):

        # self.logger.debug("_commit_rbd updating config with {}".format(config_str))

        ioctx = self.ceph.cluster.open_ioctx(self.pool)

        if not self.config_locked:
            self.lock()
            if self.error:
                return

        # reread the config to account for updates made by other systems
        # then apply this hosts update(s)
        current_config = json.loads(ioctx.read(self.config_name))
        for txn in self.txn_list:

            self.logger.debug("_commit_rbd transaction shows {}".format(txn))
            if txn.action == 'add':         # add's and updates
                current_config[txn.type][txn.item_name] = txn.item_content
            elif txn.action == 'delete':
                del current_config[txn.type][txn.item_name]
            else:
                self.error = True
                self.error_msg = "Unknown transaction type ({}} encountered in _commit_rbd".format(txn.action)

        if not self.error:
            if self.reset:
                current_config["epoch"] = 0
            else:
                current_config["epoch"] += 1        # Python will switch from plain to long int automagically

            config_str = json.dumps(current_config)
            self.logger.debug("_commit_rbd updating config to {}".format(config_str))
            config_str_fmtd = json.dumps(current_config, sort_keys=True, indent=4, separators=(',', ': '))
            ioctx.write_full(self.config_name, config_str_fmtd)
            ioctx.set_xattr(self.config_name, "epoch", str(current_config["epoch"]))
            del self.txn_list[:]                # emtpy the list of transactions

        self.unlock()
        ioctx.close()

        if post_action == 'close':
            self.ceph.shutdown()

    def _commit_glfs(self, config_str):
        pass

    def commit(self, post_action='close'):

        self.commit_config(post_action)


    @classmethod
    def get_platform(cls):

        """
        determine whether we have the rbd command in the current path to denote whether the
        envrionment is rbd or gluster based
        :return: rbd (future...gluster?)
        """
        if (any(os.access(os.path.join(path, 'rbd'), os.X_OK)
                for path in os.environ["PATH"].split(os.pathsep))):
            return 'rbd'

        return ''


def ansible_control():
    """
    establish whether ansible modules are in the current path to determine whether the code is called
    through ansible, or directly through a module import. This is done by looking at the call stack, and
    relies on the main method in the ansible custom module being prefixed by 'ansible' e.g. ansible_main()
    :return: Boolean
    """

    return sys._getframe(2).f_code.co_name.startswith('ansible')



def main():
    pass

if __name__ == '__main__':

    main()
