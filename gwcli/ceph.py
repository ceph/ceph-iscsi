from .node import UIGroup, UINode
import json
import rados

from gwcli.utils import console_message, os_cmd
import ceph_iscsi_config.settings as settings
from ceph_iscsi_config.utils import human_size


class CephGroup(UIGroup):
    """
    define an object to represent the ceph cluster. The methods use librados
    which means the host will need a valid ceph.conf and a valid keyring.
    """

    help_intro = '''
                 The ceph component of the shell is intended to provide
                 you with an overview of the ceph cluster. Information is
                 initially gathered when you start this shell, but can be
                 refreshed later using the 'refresh' subcommand. Data is shown
                 that covers the health of the ceph cluster(s), together with
                 an overview of the rados pools and overall topology.

                 The pools section is useful when performing allocation tasks
                 since it provides the current state of available space within
                 the pool(s), together with the current over-commit percentage.
                 '''

    def __init__(self, parent):
        UIGroup.__init__(self, 'cluster', parent)

        self.logger.debug("Adding ceph cluster '{}' to the UI"
                          .format(settings.config.cluster_name))
        self.cluster = CephCluster(self,
                                   settings.config.cluster_name,
                                   settings.config.cephconf,
                                   settings.config.cluster_client_name)

    @staticmethod
    def valid_conf(config_file):
        """
        Dummy check function
        :param config_file: (str) config file path
        :return: TRUE
        """

        return True

    def ui_command_refresh(self):
        """
        refresh command updates the health and capacity state of the ceph
        meta data shown within the interface
        """
        self.refresh()
        self.logger.info("ok")

    def refresh(self):

        for cluster in self.children:
            cluster.update_state()
            cluster.pools.refresh()

    def summary(self):
        """
        return the number of clusters
        :return:
        """
        return "Clusters: {}".format(len(self.children)), None


class CephCluster(UIGroup):

    def __init__(self, parent, cluster_name, conf_file, client_name):

        self.conf = conf_file
        self.client_name = client_name
        self.cluster_name = cluster_name
        UIGroup.__init__(self, cluster_name, parent)

        self.ceph_status = {}
        self.health_status = ''
        self.health_list = []
        self.version = self.cluster_version

        self.pools = CephPools(self)

        self.update_state()

        self.topology = CephTopology(self)

    def ui_command_refresh(self):
        """
        refresh command updates the health and capacity state of the ceph
        meta data shown within the interface
        """

        self.refresh()
        self.logger.info("ok")

    def ui_command_info(self):

        color = {"HEALTH_OK": "green",
                 "HEALTH_WARN": "yellow",
                 "HEALTH_ERR": "red"}

        status = self.ceph_status
        # backward compatibility (< octopus)
        if 'osdmap' in status['osdmap']:
            osdmap = status['osdmap']['osdmap']
        else:
            osdmap = status['osdmap']
        output = "Cluster name: {}\n".format(self.cluster_name)
        output += "Ceph version: {}\n".format(self.version)
        output += "Health      : {}\n".format(self.health_status)
        if self.health_status != 'HEALTH_OK':
            output += " - {}\n".format(','.join(self.health_list))

        # backward compatibility (< octopus)
        if 'mons' in status['monmap']:
            num_mons = len(status['monmap']['mons'])
        else:
            num_mons = status['monmap']['num_mons']
        num_quorum = len(status['quorum_names'])
        num_out_of_quorum = num_mons - num_quorum
        q_str = "quorum {}, out of quorum: {}".format(num_quorum, num_out_of_quorum)
        output += "\nMONs : {:>4} ({})\n".format(self.topology.num_mons,
                                                 q_str)
        output += "OSDs : {:>4} ({} up, {} in)\n".format(self.topology.num_osds,
                                                         osdmap['num_up_osds'],
                                                         osdmap['num_in_osds'])
        output += "Pools: {:>4}\n".format(self.num_pools)
        raw = status['pgmap']['bytes_total']
        output += "Raw capacity: {}\n".format(human_size(raw))
        output += "\nConfig : {}\n".format(self.conf)
        output += "Client Name: {}\n".format(self.client_name)

        console_message(output, color=color[self.health_status])

    @property
    def cluster_version(self):

        vers_out = os_cmd("ceph -c {} -n {} version".format(self.conf, self.client_name))

        # RHEL packages include additional info, that we don't need
        version_str = vers_out.split()[2].decode('utf-8')
        return '.'.join(version_str.split('.')[:3])

    def update_state(self):

        self.logger.debug("Querying ceph for state information")
        with rados.Rados(conffile=self.conf, name=self.client_name) as cluster:
            cluster.wait_for_latest_osdmap()

            cmd = {'prefix': 'status', 'format': 'json'}
            ret, buf_s, out = cluster.mon_command(json.dumps(cmd), b'')

        status = json.loads(buf_s)
        self.ceph_status = status

        # assume a luminous or above ceph cluster
        self.health_status = status['health'].get('status',
                                                  status['health'].get('overall_status'))
        self.health_list = [check.get('summary').get('message') for key, check in
                            status['health'].get('checks', {}).items()
                            if check.get('summary', {}).get('message')]

    @property
    def num_pools(self):
        return len([pool for pool in self.pools.children])

    def refresh(self):

        self.update_state()
        self.pools.refresh()

    def summary(self):

        color_lookup = {"HEALTH_OK": True,
                        "HEALTH_WARN": None,
                        "HEALTH_ERR": False}

        return self.health_status, color_lookup[self.health_status]

    @property
    def healthy_mon(self):
        """
        Return the first mon in quorum state
        :return: (str) name of the 1st monitor in a healthy state
        """

        quorum_mons = self.ceph_status.get('quorum_names', [])
        if quorum_mons:
            return quorum_mons[0]
        else:
            return "UNKNOWN"


class CephPools(UIGroup):
    help_intro = '''
                 Each pool within the ceph cluster is shown with the following
                 metrics;

                 - Commit .... this is a total of the logical space that has
                               been requested for all rbd images defined to
                               the gateways

                 - Avail ..... 'avail' shows the actual space that is available
                               for allocation after taking into account the
                               protection scheme of the pool (e.g. replication
                               level)

                 - Used ...... shows the physical space that has been consumed
                               within the pool

                 - Commit% ... is a ratio of the logical space allocated to
                               clients over the amount of space that can be
                               allocated. So when this value is <=100% the
                               physical backing store  capacity is available.
                               However, if this ratio is > 100%, you are
                               overcommiting capacity. Being able to overcommit
                               is a benefit of Ceph's thin provisioning - BUT
                               you must keep an eye on the capacity to protect
                               against out of space scenarios.

                 '''

    def __init__(self, parent):
        UIGroup.__init__(self, 'pools', parent)

        self.pool_lookup = {}  # pool_name -> pool object hash
        self.populate()

    def populate(self):

        # existing_pools = [pool.name for pool in self.children]

        # get a breakdown of the osd's to retrieve the pool types
        # i.e. is it replica 3 or EC 4+2 etc
        # This is overkill and hacky, but the bindings don't provide
        # pool type information...so it's SLEDGEHAMMER meets NUT time
        self.logger.debug("Fetching ceph osd information")
        with rados.Rados(conffile=self.parent.conf, name=self.parent.client_name) as cluster:
            cluster.wait_for_latest_osdmap()

            cmd = {'prefix': 'osd dump', 'format': 'json'}
            rc, buf_s, out = cluster.mon_command(json.dumps(cmd), b'')

        pools = {}
        for pool in json.loads(buf_s)['pools']:
            name = pool['pool_name']
            pools[name] = pool

        for pool_name in pools:
            # if pool_name not in existing_pools:
            new_pool = RadosPool(self, pool_name, pools[pool_name])
            self.pool_lookup[pool_name] = new_pool

    def refresh(self):

        self.logger.debug("Gathering pool stats for cluster "
                          "'{}'".format(self.parent.name))

        # unfortunately the rados python api does not expose all the needed
        # metrics through an ioctx call - specifically pool size is missing,
        # so stats need to be gathered at this level through the mon_command
        # interface, and pushed down to the child objects. Having a refresh
        # method within the child object would have been preferred!
        with rados.Rados(conffile=self.parent.conf, name=self.parent.client_name) as cluster:
            cluster.wait_for_latest_osdmap()

            cmd = {'prefix': 'df', 'format': 'json'}
            rc, buf_s, out = cluster.mon_command(json.dumps(cmd), b'')

            if rc == 0:
                pool_info = json.loads(buf_s)
                for pool_data in pool_info['pools']:
                    pool_name = pool_data['name']
                    self.pool_lookup[pool_name].update(pool_data)

    def summary(self):
        return "Pools: {}".format(self.parent.num_pools), True


class RadosPool(UINode):
    display_attributes = ["name", "commit", "overcommit_PCT", "max_bytes",
                          "used_bytes", "type", "desc"]

    def __init__(self, parent, pool_name, pool_md):
        UINode.__init__(self, pool_name, parent)
        self.pool_md = pool_md
        pool_type = {1: ("x{}".format(self.pool_md['size']),
                         'replicated'),
                     3: ("{}+{}".format(self.pool_md['min_size'],
                                        self.pool_md['size'] - self.pool_md['min_size']),
                         "erasure")}
        self.desc, self.type = pool_type[self.pool_md['type']]

    def _calc_overcommit(self):
        root = self.parent.parent.parent.parent
        potential_demand = 0
        for pool_child in root.disks.children:
            if pool_child.name == self.name:
                for image_child in pool_child.children:
                    potential_demand += image_child.size

        self.commit = potential_demand
        if self.max_bytes == 0:
            self.overcommit_PCT = 0
        else:
            self.overcommit_PCT = int(
                (potential_demand / float(self.max_bytes)) * 100)

    def update(self, pool_metadata):

        self.max_bytes = pool_metadata['stats']['max_avail']
        self.used_bytes = pool_metadata['stats']['bytes_used']

        self._calc_overcommit()

    def summary(self):
        msg = ["({})".format(self.desc)]
        msg.append("Commit: {}/{} ({}%)".format(human_size(self.commit),
                                                human_size(self.max_bytes),
                                                self.overcommit_PCT))
        msg.append("Used: {}".format(human_size(self.used_bytes)))

        return ', '.join(msg), True


class CephTopology(UINode):
    def __init__(self, parent):
        UINode.__init__(self, 'topology', parent)

        # backward compatibility (< octopus)
        if 'osdmap' in self.parent.ceph_status['osdmap']:
            self.num_osds = self.parent.ceph_status['osdmap']['osdmap']['num_osds']
        else:
            self.num_osds = self.parent.ceph_status['osdmap']['num_osds']

        # backward compatibility (< octopus)
        if 'mons' in self.parent.ceph_status['monmap']:
            self.num_mons = len(self.parent.ceph_status['monmap']['mons'])
        else:
            self.num_mons = self.parent.ceph_status['monmap']['num_mons']

    def summary(self):
        msg = ["OSDs: {}".format(self.num_osds)]
        msg.append("MONs: {}".format(self.num_mons))
        return ','.join(msg), True
