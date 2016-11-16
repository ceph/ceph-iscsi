#!/usr/bin/env python

__author__ = 'pcuzner@redhat.com'

from .node import UIGroup, UINode
import json
import rados
from gwcli.utils import human_size
import ceph_iscsi_config.settings as settings

class Ceph(UIGroup):
    """
    define an object to represent the ceph cluster. The methods use librados
    which means the host will need a valid ceph.conf and a valid keyring.
    """

    help_intro = '''
                 The ceph component of the shell is intended to provide
                 you with an overview of the ceph cluster. Information is
                 initially gathered when you start this shell, but can be
                 refreshed later using the refresh subcommand. Data is shown
                 that covers the health of the ceph cluster, together with
                 an overview of the rados pools and overall topology.

                 The pools section is useful when performing allocation tasks
                 since it provides the current state of available space within
                 the pool(s), together with the current over-commit percentage.
                 '''

    ceph_conf = '/etc/ceph/ceph.conf'

    def __init__(self, parent):
        UIGroup.__init__(self, 'ceph', parent)
        self.ceph_status = {}
        self.health_status = ''

        if settings.config.cephconf:
            self.conf = settings.config.cephconf
        else:
            self.conf = Ceph.ceph_conf

        self.pools = CephPools(self)

        self.update_state()

        self.topology = CephTopology(self)

    def ui_command_refresh(self):
        """
        refresh command updates the health and capacity state of the ceph
        meta data shown within the interface
        """

        self.refresh()

    def update_state(self):
        with rados.Rados(conffile=self.conf) as cluster:
            cmd = {'prefix': 'status', 'format': 'json'}
            ret, buf_s, out = cluster.mon_command(json.dumps(cmd), b'')

        self.ceph_status = json.loads(buf_s)
        self.health_status = self.ceph_status['health']['overall_status']

    def refresh(self):

        self.update_state()
        self.pools.refresh()

    def summary(self):
        return self.health_status, None

    def _get_healthy_mon(self):

        healthy_mon = 'UNKNOWN'

        if 'health' in self.ceph_status:
            mons = self.ceph_status['health']['timechecks']['mons']
            for mon in mons:
                if mon['health'] == 'HEALTH_OK':
                    healthy_mon = mon['name']
                    break

        return healthy_mon

    healthy_mon = property(_get_healthy_mon,
                           doc="Return the first mon in a healthy state")


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
        self.pool_lookup = {}           # pool_name -> pool object hash
        self.populate()

    def populate(self):

        existing_pools = [pool.name for pool in self.children]

        # Ensure we have all the pool child objects defined
        with rados.Rados(conffile=self.parent.conf) as cluster:
            pools = cluster.list_pools()
            for pool_name in pools:
                if pool_name not in existing_pools:
                    new_pool = RadosPool(self, pool_name)
                    self.pool_lookup[pool_name] = new_pool

    def refresh(self):

        # unfortunately the rados python api does not expose all the needed metrics through
        # an ioctx call - specifically pool size is missing, so stats need to be gathered at
        # this level through the mon_command interface, and pushed down to the child objects.
        # Having a refresh method within the child object would have been preferred!
        with rados.Rados(conffile=self.parent.conf) as cluster:
            cmd = {'prefix': 'df', 'format': 'json'}
            rc, buf_s, out = cluster.mon_command(json.dumps(cmd), b'')

            if rc == 0:
                pool_info = json.loads(buf_s)
                for pool_data in pool_info['pools']:
                    pool_name = pool_data['name']
                    self.pool_lookup[pool_name].update(pool_data)

    def summary(self):
        return "Pools: {}".format(len(self.children)), True


class RadosPool(UINode):

    display_attributes = ["name", "commit", "overcommit_PCT", "max_bytes", "used_bytes"]

    def __init__(self, parent, pool_name):
        UINode.__init__(self, pool_name, parent)

    def _calc_overcommit(self):
        root = self.parent.parent.parent
        potential_demand = 0
        for child in root.disks.children:
            if child.pool == self.name:
                potential_demand += child.size

        return potential_demand, int((potential_demand / float(self.max_bytes)) * 100)

    def update(self, pool_metadata):

        self.max_bytes = pool_metadata['stats']['max_avail']
        self.used_bytes = pool_metadata['stats']['bytes_used']

        self.commit, self.overcommit_PCT = self._calc_overcommit()


    def summary(self):
        msg = ["Commit: {}".format(human_size(self.commit))]
        msg.append("Avail: {}".format(human_size(self.max_bytes)))
        msg.append("Used: {}".format(human_size(self.used_bytes)))
        msg.append("Commit%: {}%".format(self.overcommit_PCT))
        return ', '.join(msg), True


class CephTopology(UINode):

    def __init__(self, parent):
        UINode.__init__(self, 'topology', parent)

        self.num_osds = self.parent.ceph_status['osdmap']['osdmap']['num_osds']
        self.num_mons = len(self.parent.ceph_status['monmap']['mons'])

    def summary(self):
        msg = ["OSDs: {}".format(self.num_osds)]
        msg.append("MONs: {}".format(self.num_mons))
        return ','.join(msg), True
