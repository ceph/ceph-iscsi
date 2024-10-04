import json
import rados
import threading
import time
from datetime import datetime

import ceph_iscsi_config.settings as settings


class StatusCounter(object):
    def __init__(self, name, cnt):
        self.name = name
        self.cnt = cnt
        self.last_cnt = cnt


class TcmuDevStatusTracker(object):
    def __init__(self, image_name):
        self.image_name = image_name
        self.gw_counter_lookup = {}
        self.lock_owner = ""
        self.lock_owner_timestamp = None
        self.state = "Online"
        self.changed_state = False
        self.stable_cnt = 0

    def get_status_dict(self):
        status = {}

        status['state'] = self.state
        status['lock_owner'] = self.lock_owner
        status['gateways'] = {}

        for gw, stat_cnt_dict in self.gw_counter_lookup.items():
            status['gateways'][gw] = {}

            for name, stat_cnt in stat_cnt_dict.items():
                status['gateways'][gw][name] = stat_cnt.cnt

        return status

    def check_for_degraded_state(self, stat_cnt):
        if stat_cnt.name in ["cmd_timed_out_cnt", "conn_lost_cnt"]:
            if abs(stat_cnt.cnt - stat_cnt.last_cnt) >= 1:
                self.state = "Degraded - cluster access failure"
                self.changed_state = True
                self.stable_cnt = 0
                return

        if stat_cnt.name == "lock_lost_cnt" and \
           abs(stat_cnt.cnt - stat_cnt.last_cnt) >= \
           settings.config.lock_lost_cnt_threshhold:
            self.state = "Degraded - excessive failovers"
            self.changed_state = True
            self.stable_cnt = 0
            return

    def update_status(self, gw, status, status_stamp):
        if status is None:
            # Sometimes status calls will return empty statuses even though
            # there is valid data. We might not see it until the Nth call.
            return

        counter_dict = self.gw_counter_lookup.get(gw)
        if counter_dict is None:
            counter_dict = {}

        for name, val in status.items():
            if name == "lock_owner" and val == "true":
                dt = datetime.strptime(status_stamp, "%Y-%m-%dT%H:%M:%S.%f%z")
                if self.lock_owner_timestamp is None or dt > self.lock_owner_timestamp:
                    self.lock_owner_timestamp = dt
                    self.lock_owner = gw
                    self.stable_cnt = 0
                continue

            if name not in ["cmd_timed_out_cnt", "conn_lost_cnt", "lock_lost_cnt"]:
                continue

            stat_cnt = counter_dict.get(name)
            if stat_cnt is None:
                stat_cnt = StatusCounter(name, int(val))

            stat_cnt.cnt = int(val)
            # TODO:
            # If we detect a degraded state, we can throttle the path here.
            self.check_for_degraded_state(stat_cnt)
            stat_cnt.last_cnt = stat_cnt.cnt

            counter_dict[name] = stat_cnt

        self.gw_counter_lookup[gw] = counter_dict


class DeviceStatusWatcher(threading.Thread):
    def __init__(self, logger):
        threading.Thread.__init__(self)
        self.logger = logger
        self.daemon = True
        self.cluster = None
        self.status_lookup = {}

    def get_dev_status(self, image_name):
        return self.status_lookup.get(image_name)

    def exit(self):
        if self.cluster:
            self.cluster.shutdown()

    def run(self):
        self.cluster = rados.Rados(conffile=settings.config.cephconf,
                                   name=settings.config.cluster_client_name)
        self.cluster.connect()

        while True:
            time.sleep(settings.config.status_check_interval)

            cmd = json.dumps({"prefix": "service status", "format": "json"})

            ret, outb, outs = self.cluster.mgr_command(cmd, b'')
            if ret != 0:
                self.logger.error("mgr command failed {}".format(ret))
                continue

            svc = json.loads(outb).get('tcmu-runner')
            if svc is None:
                self.logger.warning("there is no tcmu-runner data available")
                continue

            image_names_dict = {}
            for daemon, daemon_info in svc.items():
                gw, image_name = daemon.split(":", 1)
                image_names_dict[image_name] = image_name

                dev_status = self.get_dev_status(image_name)
                if dev_status is None:
                    dev_status = TcmuDevStatusTracker(image_name)
                    self.status_lookup[image_name] = dev_status

                dev_status.update_status(gw, daemon_info.get('status'),
                                         daemon_info.get('status_stamp'))

            # cleanup stale entries and try to move to online if a dev
            # didn't not see any errors on every gateway for a while
            for image_name in list(self.status_lookup):
                if image_names_dict.get(image_name) is None:
                    del self.status_lookup[image_name]
                else:
                    dev_status = self.status_lookup[image_name]
                    if dev_status.changed_state is False:
                        dev_status.stable_cnt += 1

                        if dev_status.stable_cnt > settings.config.stable_state_reset_count:
                            dev_status.stable_cnt = 0
                            dev_status.state = "Online"
                    else:
                        dev_status.changed_state = False

            # debugging info
            dev_status = self.get_dev_status(image_name)
            stats_dict = dev_status.get_status_dict()
            self.logger.debug(stats_dict)
