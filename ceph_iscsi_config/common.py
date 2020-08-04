import rados
import socket
import time
import json
import traceback

from ceph_iscsi_config.backstore import USER_RBD
import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.utils import encryption_available, get_time


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

    def __init__(self):

        self.error = False
        self.error_msg = ''
        self.cluster = None

        conf = settings.config.cephconf

        try:
            self.cluster = rados.Rados(conffile=conf,
                                       name=settings.config.cluster_client_name)
        except rados.Error as err:
            self.error = True
            self.error_msg = "Invaid cluster_client_name or setting in {} - {}".format(conf, err)
            return

        try:
            self.cluster.connect()
        except rados.Error as err:
            self.error = True
            self.error_msg = "Unable to connect to the cluster (keyring missing?) - {}".format(err)

    def __del__(self):
        if self.cluster:
            self.cluster.shutdown()

    def shutdown(self):
        self.cluster.shutdown()


class Config(object):

    seed_config = {"disks": {},
                   "gateways": {},
                   "targets": {},
                   "discovery_auth": {'username': '',
                                      'password': '',
                                      'password_encryption_enabled': False,
                                      'mutual_username': '',
                                      'mutual_password': '',
                                      'mutual_password_encryption_enabled': False},
                   "version": 11,
                   "epoch": 0,
                   "created": '',
                   "updated": ''
                   }

    lock_time_limit = 30

    def __init__(self, logger, cfg_name=None, pool=None):
        self.logger = logger
        self.config_name = cfg_name
        if self.config_name is None:
            self.config_name = settings.config.gateway_conf
        if pool is None:
            pool = settings.config.pool
        self.pool = pool
        self.ceph = None
        self.error = False
        self.reset = False
        self.error_msg = ""
        self.txn_list = []
        self.config_locked = False

        self.ceph = CephCluster()
        if self.ceph.error:
            self.error = True
            self.error_msg = self.ceph.error_msg
            return

        if self.init_config():
            self.config = self.get_config()
            self._upgrade_config()
            self.changed = False

    def _read_config_object(self, ioctx):
        """
        Return config string from the config object. The string is checked to
        see if it's valid json. If it's not the read is likely to be a against
        the object while it's being updated by another host - if this happens,
        we wait and reread until we get valid json.
        :param ioctx: rados ioctx
        :return: (str) current string.
        """

        try:
            size, mtime = ioctx.stat(self.config_name)
        except rados.ObjectNotFound:
            self.logger.error("_read_config_object object not found")
            raise
        else:
            self.logger.debug("_read_config_object reading the config object")
            size += 1
            cfg_str = ioctx.read(self.config_name, length=size)
            if cfg_str:
                valid = False
                while not valid:
                    try:
                        json.loads(cfg_str)
                    except ValueError:
                        #
                        self.logger.debug("_read_config_object not valid json, rereading")
                        time.sleep(1)
                        size, mtime = ioctx.stat(self.config_name)
                        cfg_str = ioctx.read(self.config_name, length=size)
                    else:
                        valid = True

        return cfg_str

    def _open_ioctx(self):
        try:
            self.logger.debug("(_open_ioctx) Opening connection to {} pool".format(self.pool))
            ioctx = self.ceph.cluster.open_ioctx(self.pool)
        except rados.ObjectNotFound:
            self.error = True
            self.error_msg = "'{}' pool does not exist!".format(self.pool)
            self.logger.error("(_open_ioctx) {} does not exist".format(self.pool))
            raise
        self.logger.debug("(_open_ioctx) connection opened")
        return ioctx

    def _get_ceph_config(self):

        cfg_dict = {}

        ioctx = self._open_ioctx()
        cfg_data = self._read_config_object(ioctx)
        ioctx.close()

        if not cfg_data:
            # attempt to read the object got nothing which means it's empty
            # so we seed the object
            self.logger.debug("(_get_rbd_config) config object is empty..seeding it")
            self._seed_rbd_config()
            if self.error:
                self.logger.error("(Config._get_rbd_config) Unable to seed the config object")
                return {}
            else:
                cfg_data = json.dumps(Config.seed_config)

        self.logger.debug("(_get_rbd_config) config object contains '{}'".format(cfg_data))

        cfg_dict = json.loads(cfg_data)

        return cfg_dict

    def needs_hostname_update(self):
        if self.config['version'] == 9:
            # No gateway has been updated yet.
            return True

        updated = self.config.get('gateways_upgraded')
        if updated is None:
            # Everything has been updated or we are < 9
            return False

        if socket.getfqdn() in updated:
            return False

        return True

    def _upgrade_config(self):
        update_hostname = self.needs_hostname_update()

        if self.config['version'] >= Config.seed_config['version'] and not update_hostname:
            return

        if self.config['version'] <= 2:
            self.add_item("groups", element_name=None, initial_value={})
            self.update_item("version", element_name=None, element_value=3)

        if self.config['version'] == 3:
            iqn = self.config['gateways'].get('iqn', None)
            gateways = {}
            portals = {}

            self.add_item("targets", None, {})
            self.add_item('discovery_auth', None, {
                'chap': '',
                'chap_mutual': ''
            })

            if iqn:
                for host, gateway_v3 in self.config['gateways'].items():
                    if isinstance(gateway_v3, dict):
                        portal = gateway_v3
                        portal.pop('iqn')
                        active_luns = portal.pop('active_luns')
                        updated = portal.pop('updated', None)
                        created = portal.pop('created', None)
                        gateway = {
                            'active_luns': active_luns
                        }
                        if created:
                            gateway['created'] = created
                        if updated:
                            gateway['updated'] = updated
                        gateways[host] = gateway
                        portals[host] = portal
                for _, client in self.config['clients'].items():
                    client.pop('created', None)
                    client.pop('updated', None)
                    client['auth']['chap_mutual'] = ''
                for _, group in self.config['groups'].items():
                    group.pop('created', None)
                    group.pop('updated', None)
                target = {
                    'disks': list(self.config['disks'].keys()),
                    'clients': self.config['clients'],
                    'portals': portals,
                    'groups': self.config['groups'],
                    'controls': self.config.get('controls', {}),
                    'ip_list': self.config['gateways']['ip_list']
                }
                self.add_item("targets", iqn, target)
                self.update_item("targets", iqn, target)

            self.update_item("gateways", None, gateways)

            if 'controls' in self.config:
                self.del_item('controls', None)
            self.del_item('clients', None)
            self.del_item('groups', None)

            self.update_item("version", None, 4)

        if self.config['version'] == 4:
            for disk_id, disk in self.config['disks'].items():
                disk['backstore'] = USER_RBD
                self.update_item("disks", disk_id, disk)
            self.update_item("version", None, 5)

        if self.config['version'] == 5:
            for target_iqn, target in self.config['targets'].items():
                target['acl_enabled'] = True
                self.update_item("targets", target_iqn, target)
            self.update_item("version", None, 6)

        if self.config['version'] == 6:
            new_disks = {}
            old_disks = []
            for disk_id, disk in self.config['disks'].items():
                disk['backstore_object_name'] = disk_id
                new_disk_id = disk_id.replace('.', '/')
                new_disks[new_disk_id] = disk
                old_disks.append(disk_id)
            for old_disk_id in old_disks:
                self.del_item('disks', old_disk_id)
            for new_disk_id, new_disk in new_disks.items():
                self.add_item("disks", new_disk_id, new_disk)
            for iqn, target in self.config['targets'].items():
                new_disk_ids = []
                for disk_id in target['disks']:
                    new_disk_id = disk_id.replace('.', '/')
                    new_disk_ids.append(new_disk_id)
                target['disks'] = new_disk_ids
                for _, client in target['clients'].items():
                    new_luns = {}
                    for lun_id, lun in client['luns'].items():
                        new_lun_id = lun_id.replace('.', '/')
                        new_luns[new_lun_id] = lun
                    client['luns'] = new_luns
                for _, group in target['groups'].items():
                    new_group_disks = {}
                    for group_disk_id, group_disk in group['disks'].items():
                        new_group_disk_id = group_disk_id.replace('.', '/')
                        new_group_disks[new_group_disk_id] = group_disk
                        group['disks'] = new_group_disks
                self.update_item("targets", iqn, target)
            self.update_item("version", None, 7)

        if self.config['version'] == 7:
            if '/' in self.config['discovery_auth']['chap']:
                duser, dpassword = self.config['discovery_auth']['chap'].split('/', 1)
            else:
                duser = ''
                dpassword = ''
            self.config['discovery_auth']['username'] = duser
            self.config['discovery_auth']['password'] = dpassword
            self.config['discovery_auth']['password_encryption_enabled'] = False
            self.config['discovery_auth'].pop('chap', None)
            if '/' in self.config['discovery_auth']['chap_mutual']:
                dmuser, dmpassword = self.config['discovery_auth']['chap_mutual'].split('/', 1)
            else:
                dmuser = ''
                dmpassword = ''
            self.config['discovery_auth']['mutual_username'] = dmuser
            self.config['discovery_auth']['mutual_password'] = dmpassword
            self.config['discovery_auth']['mutual_password_encryption_enabled'] = False
            self.config['discovery_auth'].pop('chap_mutual', None)
            self.update_item("discovery_auth", None, self.config['discovery_auth'])
            for target_iqn, target in self.config['targets'].items():
                for _, client in target['clients'].items():
                    if '/' in client['auth']['chap']:
                        user, password = client['auth']['chap'].split('/', 1)
                    else:
                        user = ''
                        password = ''
                    client['auth']['username'] = user
                    client['auth']['password'] = password
                    client['auth']['password_encryption_enabled'] = \
                        (len(password) > 16 and encryption_available())
                    client['auth'].pop('chap', None)
                    if '/' in client['auth']['chap_mutual']:
                        muser, mpassword = client['auth']['chap_mutual'].split('/', 1)
                    else:
                        muser = ''
                        mpassword = ''
                    client['auth']['mutual_username'] = muser
                    client['auth']['mutual_password'] = mpassword
                    client['auth']['mutual_password_encryption_enabled'] = \
                        (len(mpassword) > 16 and encryption_available())
                    client['auth'].pop('chap_mutual', None)

                self.update_item("targets", target_iqn, target)
            self.update_item("version", None, 8)

        if self.config['version'] == 8:
            for target_iqn, target in self.config['targets'].items():
                for _, portal in target['portals'].items():
                    portal['portal_ip_addresses'] = [portal['portal_ip_address']]
                    portal.pop('portal_ip_address')
                self.update_item("targets", target_iqn, target)
            self.update_item("version", None, 9)

        if self.config['version'] == 9 or update_hostname:
            # temporary field to store the gateways already upgraded from v9 to v10
            gateways_upgraded = self.config.get('gateways_upgraded')
            if not gateways_upgraded:
                gateways_upgraded = []
                self.add_item('gateways_upgraded', None, gateways_upgraded)
            this_shortname = socket.gethostname().split('.')[0]
            this_fqdn = socket.getfqdn()
            if this_fqdn not in gateways_upgraded:
                gateways_config = self.config['gateways']
                gateway_config = gateways_config.get(this_shortname)
                if gateway_config:
                    gateways_config.pop(this_shortname)
                    gateways_config[this_fqdn] = gateway_config
                    self.update_item("gateways", None, gateways_config)
                for target_iqn, target in self.config['targets'].items():
                    portals_config = target['portals']
                    portal_config = portals_config.get(this_shortname)
                    if portal_config:
                        portals_config.pop(this_shortname)
                        portals_config[this_fqdn] = portal_config
                        self.update_item("targets", target_iqn, target)
                for disk_id, disk in self.config['disks'].items():
                    if disk.get('allocating_host') == this_shortname:
                        disk['allocating_host'] = this_fqdn
                    if disk.get('owner') == this_shortname:
                        disk['owner'] = this_fqdn
                    self.update_item("disks", disk_id, disk)
                gateways_upgraded.append(this_fqdn)
                self.update_item("gateways_upgraded", None, gateways_upgraded)

            if any(gateway_name not in gateways_upgraded
                   for gateway_name in self.config['gateways'].keys()):
                self.logger.debug("gateways upgraded to 10: {}".
                                  format(gateways_upgraded))
            else:
                self.del_item("gateways_upgraded", None)

            if self.config['version'] == 9:
                # Upgrade from v9 to v10 is still in progress. Update the
                # version now, so we can update the other config fields and
                # setup the target to execute IO while the other gws upgrade.
                self.update_item("version", None, 10)

        # Currently, the versions below do not rely on fields being updated
        # in the 9->10 upgrade which needs to execute on every node before
        # completing. If this changes, we will need to fix how we handle
        # rolling upgrades, so new versions have access to the updated fields
        # on all gws before completing the upgrade.
        if self.config['version'] == 10:
            for target_iqn, target in self.config['targets'].items():
                target['auth'] = {
                    'username': '',
                    'password': '',
                    'password_encryption_enabled': False,
                    'mutual_username': '',
                    'mutual_password': '',
                    'mutual_password_encryption_enabled': False
                }
                disks = {}
                for disk_index, disk in enumerate(sorted(target['disks'])):
                    disks[disk] = {
                        'lun_id': disk_index
                    }
                target['disks'] = disks
                self.update_item("targets", target_iqn, target)
            self.update_item("version", None, 11)

        self.commit("retain")

    def init_config(self):
        try:
            ioctx = self._open_ioctx()
        except rados.ObjectNotFound:
            return False

        try:
            with rados.WriteOpCtx(ioctx) as op:
                # try to exclusively create the config object
                op.new(rados.LIBRADOS_CREATE_EXCLUSIVE)
                ioctx.operate_write_op(op, self.config_name)
                self.logger.debug("(init_config) created empty config object")
        except rados.ObjectExists:
            self.logger.debug("(init_config) using pre existing config object")
        ioctx.close()
        return True

    def get_config(self):
        return self._get_ceph_config()

    def lock(self):

        ioctx = self._open_ioctx()

        secs = 0
        self.logger.debug("config.lock attempting to acquire lock on {}".format(self.config_name))
        while secs < Config.lock_time_limit:
            try:
                ioctx.lock_exclusive(self.config_name, 'lock', 'config')
                self.config_locked = True
                break
            except (rados.ObjectBusy, rados.ObjectExists):
                self.logger.debug("(Config.lock) waiting for excl lock on "
                                  "{} object".format(self.config_name))
                time.sleep(1)
                secs += 1

        if secs >= Config.lock_time_limit:
            self.error = True
            self.error_msg = ("Timed out ({}s) waiting for excl "
                              "lock on {} object".format(Config.lock_time_limit, self.config_name))
            self.logger.error("(Config.lock) {}".format(self.error_msg))

        ioctx.close()

    def unlock(self):
        ioctx = self._open_ioctx()

        self.logger.debug("config.unlock releasing lock on {}".format(self.config_name))
        try:
            ioctx.unlock(self.config_name, 'lock', 'config')
            self.config_locked = False
        except Exception:
            self.error = True
            self.error_msg = ("Unable to unlock {} - {}".format(self.config_name,
                                                                traceback.format_exc()))
            self.logger.error("(Config.unlock) {}".format(self.error_msg))

        ioctx.close()

    def _seed_rbd_config(self):

        ioctx = self._open_ioctx()

        self.lock()
        if self.error:
            return

        # if the config object is empty, seed it - if not just leave as is
        cfg_data = self._read_config_object(ioctx)
        if not cfg_data:
            self.logger.debug("_seed_rbd_config found empty config object")
            seed_now = Config.seed_config
            seed_now['created'] = get_time()
            seed = json.dumps(seed_now, sort_keys=True, indent=4, separators=(',', ': '))
            ioctx.write_full(self.config_name, seed.encode('utf-8'))
            ioctx.set_xattr(self.config_name, "epoch", "0".encode('utf-8'))
            self.changed = True

        self.unlock()

    def refresh(self):
        self.logger.debug("config refresh - current config is {}".format(self.config))
        self.config = self.get_config()
        self._upgrade_config()

    def add_item(self, cfg_type, element_name=None, initial_value=None):
        now = get_time()

        if element_name:
            # ensure the initial state for this item has a 'created' date/time value
            if isinstance(initial_value, dict):
                if 'created' not in initial_value:
                    initial_value['created'] = now

            if initial_value is None:
                init_state = {"created": now}
            else:
                init_state = initial_value

            self.config[cfg_type][element_name] = init_state

            if isinstance(init_state, str) and 'created' not in self.config[cfg_type]:
                self.config[cfg_type]['created'] = now
                # add a separate transaction to capture the creation date to the section
                txn = ConfigTransaction(cfg_type, 'created', initial_value=now)
                self.txn_list.append(txn)

        else:
            # new section being added to the config object
            self.config[cfg_type] = initial_value
            init_state = initial_value
            txn = ConfigTransaction(cfg_type, None, initial_value=initial_value)
            self.txn_list.append(txn)

        self.logger.debug("(Config.add_item) config updated to {}".format(self.config))
        self.changed = True

        txn = ConfigTransaction(cfg_type, element_name, initial_value=init_state)
        self.txn_list.append(txn)

    def del_item(self, cfg_type, element_name):
        self.changed = True
        if element_name:
            del self.config[cfg_type][element_name]
        else:
            del self.config[cfg_type]
        self.logger.debug("(Config.del_item) config updated to {}".format(self.config))

        txn = ConfigTransaction(cfg_type, element_name, 'delete')
        self.txn_list.append(txn)

    def update_item(self, cfg_type, element_name, element_value):
        now = get_time()

        if element_name:
            current_values = self.config[cfg_type][element_name]
            self.logger.debug("prior to update, item contains {}".format(current_values))
            if isinstance(element_value, dict):
                merged = current_values.copy()
                new_dict = element_value
                new_dict['updated'] = now
                merged.update(new_dict)
                element_value = merged.copy()

            self.config[cfg_type][element_name] = element_value
        else:
            # update to a root level config element, like version
            self.config[cfg_type] = element_value

        self.logger.debug("(Config.update_item) config is {}".format(self.config))
        self.changed = True
        self.logger.debug("update_item: type={}, item={}, update={}".format(
            cfg_type, element_name, element_value))

        txn = ConfigTransaction(cfg_type, element_name, 'add')
        txn.item_content = element_value
        self.txn_list.append(txn)

    def set_item(self, cfg_type, element_name, element_value):
        self.logger.debug("(Config.update_item) config is {}".format(self.config))
        self.changed = True
        self.logger.debug("update_item: type={}, item={}, update={}".format(
            cfg_type, element_name, element_value))

        txn = ConfigTransaction(cfg_type, element_name, 'add')
        txn.item_content = element_value
        self.txn_list.append(txn)

    def _commit_rbd(self, post_action):

        ioctx = self._open_ioctx()

        if not self.config_locked:
            self.lock()
            if self.error:
                return

        # reread the config to account for updates made by other systems
        # then apply this hosts update(s)
        current_config = json.loads(self._read_config_object(ioctx))
        for txn in self.txn_list:

            self.logger.debug("_commit_rbd transaction shows {}".format(txn))
            if txn.action == 'add':         # add's and updates
                if txn.item_name:
                    current_config[txn.type][txn.item_name] = txn.item_content
                else:
                    current_config[txn.type] = txn.item_content

            elif txn.action == 'delete':
                if txn.item_name:
                    del current_config[txn.type][txn.item_name]
                else:
                    del current_config[txn.type]
            else:
                self.error = True
                self.error_msg = "Unknown transaction type ({}) encountered in " \
                                 "_commit_rbd".format(txn.action)

        if not self.error:
            if self.reset:
                current_config["epoch"] = 0
            else:
                # Python will switch from plain to long int automagically
                current_config["epoch"] += 1

            now = get_time()
            current_config['updated'] = now
            config_str = json.dumps(current_config)
            self.logger.debug("_commit_rbd updating config to {}".format(config_str))
            config_str_fmtd = json.dumps(current_config, sort_keys=True,
                                         indent=4, separators=(',', ': '))
            ioctx.write_full(self.config_name, config_str_fmtd.encode('utf-8'))
            ioctx.set_xattr(self.config_name, "epoch",
                            str(current_config["epoch"]).encode('utf-8'))
            del self.txn_list[:]                # empty the list of transactions

        self.unlock()
        ioctx.close()

        if post_action == 'close':
            self.ceph.shutdown()

    def commit(self, post_action='close'):
        self._commit_rbd(post_action)


def main():
    pass


if __name__ == '__main__':
    main()
