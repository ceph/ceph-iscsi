import threading
import time
import os

import rtslib_fb.tcm as tcm
from rtslib_fb.root import RTSRoot
from rtslib_fb.utils import fread

from .utils import this_host


class Metric(object):
    """ Metric object used to hold the metric, labels and value """

    def __init__(self, vhelp, vtype):
        self.var_help = vhelp
        self.var_type = vtype
        self.data = []

    def add(self, labels, value):
        _d = dict(labels=labels,
                  value=value)
        self.data.append(_d)


class TPGMapper(threading.Thread):
    """ thread which builds a list of LUNs mapped to a given TPG"""
    def __init__(self, tpg):
        self.tpg = tpg
        self.tpg_id = tpg.tag
        self.portal_ip = next(tpg.network_portals).ip_address
        self.owned_luns = dict()
        threading.Thread.__init__(self)

    def run(self):
        for lun in self.tpg.luns:
            if lun.alua_tg_pt_gp_name == 'ao':
                lun_name = lun.storage_object.name
                self.owned_luns[lun_name] = self.portal_ip


class GatewayStats(object):
    """ Gather and format gateway related performance data """

    def __init__(self):
        self.metrics = {}
        self._root = RTSRoot()

        # use utils.this_host
        self.gw_name = this_host()

    def formatted(self):
        s = ''
        for m_name in sorted(self.metrics.keys()):
            metric = self.metrics[m_name]
            s += "#HELP: {} {}\n".format(m_name,
                                         metric.var_help)
            s += "#TYPE: {} {}\n".format(m_name,
                                         metric.var_type)

            for v in metric.data:
                labels = []
                for n in v['labels'].items():
                    label_name = '{}='.format(n[0])
                    label_value = '"{}"'.format(n[1])

                    labels.append('{}{}'.format(label_name,
                                                label_value))

                s += "{}{{{}}} {}\n".format(m_name,
                                            ','.join(labels),
                                            v["value"])

        return s.rstrip()

    def collect(self):

        # the tcm module uses a global called bs_cache and performs lookups
        # against this to verify a storage object exists. However, if a change
        # is made the local copy of bs_cache in the rbd-target-gw scope is not
        # changed, so we reset it here to ensure it always starts empty
        tcm.bs_cache = {}

        stime = time.time()
        self._get_tpg()
        self._get_mapping()
        self._get_lun_sizes()
        self._get_lun_stats()
        self._get_client_details()
        etime = time.time()

        summary = Metric("time taken to scrape iscsi stats (secs)",
                         "gauge")
        labels = {"gw_name": self.gw_name}
        summary.add(labels, etime - stime)
        self.metrics['ceph_iscsi_scrape_duration_seconds'] = summary

    def _get_tpg(self):
        stat = Metric("target portal groups defined within gateway group",
                      "gauge")
        labels = {"gw_iqn": next(self._root.targets).wwn}
        v = len([tpg for tpg in self._root.tpgs])
        stat.add(labels, v)

        self.metrics["ceph_iscsi_gateway_tpg_total"] = stat

    def _get_mapping(self):
        mapping = Metric("LUN mapping state 0=unmapped, 1=mapped",
                         "gauge")
        mapped_devices = [l.tpg_lun.storage_object.name
                          for l in self._root.mapped_luns]

        tpg_mappers = []
        for tpg in self._root.tpgs:
            mapper = TPGMapper(tpg)
            mapper.start()
            tpg_mappers.append(mapper)

        for mapper in tpg_mappers:
            mapper.join()

        # merge the tpg lun maps
        all_devs = tpg_mappers[0].owned_luns.copy()
        for mapper in tpg_mappers[1:]:
            all_devs.update(mapper.owned_luns)

        for so in self._root.storage_objects:

            so_state = 1 if so.name in mapped_devices else 0
            owner = all_devs[so.name]
            mapping.add({"lun_name": so.name,
                         "gw_name": self.gw_name,
                         "gw_owner": owner}, so_state)

        self.metrics["ceph_iscsi_lun_mapped"] = mapping

    def _get_lun_sizes(self):
        size_bytes = Metric("LUN size (bytes)",
                            "gauge")
        for so in self._root.storage_objects:
            labels = {"lun_name": so.name,
                      "gw_name": self.gw_name}
            lun_size = so.size
            size_bytes.add(labels, lun_size)
        self.metrics["ceph_iscsi_lun_size_bytes"] = size_bytes

    def _get_lun_stats(self):
        iops = Metric("IOPS per LUN per client",
                      "counter")
        read_bytes = Metric("read bytes per LUN per client",
                            "counter")
        write_bytes = Metric("write bytes per LUN client",
                             "counter")

        for node_acl in self._root.node_acls:
            for lun in node_acl.mapped_luns:
                lun_path = lun.path
                lun_name = lun.tpg_lun.storage_object.name
                perf_labels = {"gw_name": self.gw_name,
                               "client_iqn": node_acl.node_wwn,
                               "lun_name": lun_name}

                lun_iops = int(fread(
                    os.path.join(lun_path,
                                 "statistics/scsi_auth_intr/num_cmds")))
                mbytes_read = int(fread(
                    os.path.join(lun_path,
                                 "statistics/scsi_auth_intr/read_mbytes")))
                mbytes_write = int(fread(
                    os.path.join(lun_path,
                                 "statistics/scsi_auth_intr/write_mbytes")))

                iops.add(perf_labels,
                         lun_iops)
                read_bytes.add(perf_labels,
                               mbytes_read * (1024 ** 2))
                write_bytes.add(perf_labels,
                                mbytes_write * (1024 ** 2))

        self.metrics["ceph_iscsi_lun_iops"] = iops
        self.metrics["ceph_iscsi_lun_read_bytes"] = read_bytes
        self.metrics["ceph_iscsi_lun_write_bytes"] = write_bytes

    def _get_client_details(self):
        logins = Metric("iscsi client session active (0=No, 1=Yes)",
                        "gauge")
        lun_map = Metric("LUN ID by client",
                         "gauge")
        logged_in_clients = [client['parent_nodeacl'].node_wwn
                             for client in self._root.sessions
                             if client['state'] == 'LOGGED_IN']

        for client in self._root.node_acls:

            login_labels = {"gw_name": self.gw_name,
                            "client_iqn": client.node_wwn
                            }

            v = 1 if client.node_wwn in logged_in_clients else 0
            logins.add(login_labels, v)

            for lun in client.mapped_luns:
                lun_labels = {"gw_name": self.gw_name,
                              "client_iqn": client.node_wwn,
                              "lun_name": lun.tpg_lun.storage_object.name}
                v = lun.mapped_lun
                lun_map.add(lun_labels, v)

        self.metrics["ceph_iscsi_client_login"] = logins
        self.metrics["ceph_iscsi_client_lun"] = lun_map
