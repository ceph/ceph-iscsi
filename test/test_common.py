# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json
import logging
import sys
import unittest

import mock

# We need to mock ceph libs python bindings because there's no
# updated package in pypy
sys.modules['rados'] = mock.Mock()
sys.modules['rbd'] = mock.Mock()

import ceph_iscsi_config.settings as settings  # noqa: E402
from ceph_iscsi_config.common import Config  # noqa: E402


class ChapTest(unittest.TestCase):

    def setUp(self):
        self.logger = logging.getLogger()
        settings.init()

    def test_upgrade_config_v4(self):
        gateway_conf_v3 = json.dumps(self.gateway_conf_v3)
        with mock.patch.object(Config, 'init_config', return_value=True), \
                mock.patch.object(Config, '_read_config_object', return_value=gateway_conf_v3), \
                mock.patch.object(Config, 'commit'):
            config = Config(self.logger)
            self.maxDiff = None
            iqn = 'iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw'
            self.assertGreater(config.config['targets'][iqn]['created'],
                               self.gateway_conf_v4['targets'][iqn]['created'])
            self.assertGreater(config.config['targets'][iqn]['updated'],
                               self.gateway_conf_v4['targets'][iqn]['updated'])
            config.config['targets'][iqn]['created'] = '2018/12/07 09:19:01'
            config.config['targets'][iqn]['updated'] = '2018/12/07 09:19:02'
            self.assertDictEqual(config.config, self.gateway_conf_v4)

    gateway_conf_v3 = {
        "clients": {
            "iqn.1994-05.com.redhat:rh7-client": {
                "auth": {
                    "chap": "myiscsiusername/myiscsipassword"
                },
                "created": "2018/12/07 09:18:01",
                "group_name": "mygroup",
                "luns": {
                    "rbd.disk_1": {
                        "lun_id": 0
                    }
                },
                "updated": "2018/12/07 09:18:02"
            }
        },
        "controls": {
            "immediate_data": False,
            "nopin_response_timeout": 17
        },
        "created": "2018/12/07 09:18:03",
        "disks": {
            "rbd.disk_1": {
                "controls": {
                    "qfull_timeout": 18
                },
                "created": "2018/12/07 09:18:04",
                "image": "disk_1",
                "owner": "node1",
                "pool": "rbd",
                "pool_id": 7,
                "updated": "2018/12/07 09:18:05",
                "wwn": "4fc1071d-7e2f-4df0-95c8-925a617e2d62"
            }
        },
        "epoch": 19,
        "gateways": {
            "created": "2018/12/07 09:18:06",
            "ip_list": [
                "192.168.100.201",
                "192.168.100.202"
            ],
            "iqn": "iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw",
            "node1": {
                "active_luns": 1,
                "created": "2018/12/07 09:18:07",
                "gateway_ip_list": [
                    "192.168.100.201",
                    "192.168.100.202"
                ],
                "inactive_portal_ips": [
                    "192.168.100.202"
                ],
                "iqn": "iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw",
                "portal_ip_address": "192.168.100.201",
                "tpgs": 2,
                "updated": "2018/12/07 09:18:08"
            },
            "node2": {
                "active_luns": 0,
                "created": "2018/12/07 09:18:09",
                "gateway_ip_list": [
                    "192.168.100.201",
                    "192.168.100.202"
                ],
                "inactive_portal_ips": [
                    "192.168.100.201"
                ],
                "iqn": "iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw",
                "portal_ip_address": "192.168.100.202",
                "tpgs": 2,
                "updated": "2018/12/07 09:18:10"
            }
        },
        "groups": {
            "mygroup": {
                "created": "2018/12/07 09:18:11",
                "disks": {
                    "rbd.disk_1": {
                        "lun_id": 0
                    }
                },
                "members": [
                    "iqn.1994-05.com.redhat:rh7-client"
                ],
                "updated": "2018/12/07 09:18:12"
            }
        },
        "updated": "2018/12/07 09:18:13",
        "version": 3
    }

    gateway_conf_v4 = {
        "created": "2018/12/07 09:18:03",
        "disks": {
            "rbd.disk_1": {
                "controls": {
                    "qfull_timeout": 18
                },
                "created": "2018/12/07 09:18:04",
                "image": "disk_1",
                "owner": "node1",
                "pool": "rbd",
                "pool_id": 7,
                "updated": "2018/12/07 09:18:05",
                "wwn": "4fc1071d-7e2f-4df0-95c8-925a617e2d62"
            }
        },
        "epoch": 19,
        "gateways": {
            "node1": {
                "active_luns": 1,
                "created": "2018/12/07 09:18:07",
                "updated": "2018/12/07 09:18:08"
            },
            "node2": {
                "active_luns": 0,
                "created": "2018/12/07 09:18:09",
                "updated": "2018/12/07 09:18:10"
            }
        },
        "targets": {
            "iqn.2003-01.com.redhat.iscsi-gw:iscsi-igw": {
                "clients": {
                    "iqn.1994-05.com.redhat:rh7-client": {
                        "auth": {
                            "chap": "myiscsiusername/myiscsipassword"
                        },
                        "group_name": "mygroup",
                        "luns": {
                            "rbd.disk_1": {
                                "lun_id": 0
                            }
                        }
                    }
                },
                "controls": {
                    "immediate_data": False,
                    "nopin_response_timeout": 17
                },
                "created": "2018/12/07 09:19:01",
                "disks": [
                    "rbd.disk_1"
                ],
                "groups": {
                    "mygroup": {
                        "disks": {
                            "rbd.disk_1": {
                                "lun_id": 0
                            }
                        },
                        "members": [
                            "iqn.1994-05.com.redhat:rh7-client"
                        ]
                    }
                },
                "ip_list": [
                    "192.168.100.201",
                    "192.168.100.202"
                ],
                "portals": {
                    "node1": {
                        "gateway_ip_list": [
                            "192.168.100.201",
                            "192.168.100.202"
                        ],
                        "inactive_portal_ips": [
                            "192.168.100.202"
                        ],
                        "portal_ip_address": "192.168.100.201",
                        "tpgs": 2
                    },
                    "node2": {
                        "gateway_ip_list": [
                            "192.168.100.201",
                            "192.168.100.202"
                        ],
                        "inactive_portal_ips": [
                            "192.168.100.201"
                        ],
                        "portal_ip_address": "192.168.100.202",
                        "tpgs": 2
                    }
                },
                "updated": "2018/12/07 09:19:02"
            }
        },
        "updated": "2018/12/07 09:18:13",
        "version": 4
    }
