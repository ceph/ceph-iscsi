#!/usr/bin/env python

from rtslib_fb.fabric import ISCSIFabricModule

from ceph_iscsi_config.client import CHAP


class Discovery(object):

    @staticmethod
    def validate_discovery_auth(chap_str, chap_mutual_str):
        if chap_str != '' and '/' not in chap_str:
            return 'CHAP format is invalid - must be a <username>/<password> format'
        if chap_mutual_str != '' and '/' not in chap_mutual_str:
            return 'CHAP_MUTUAL format is invalid - must be a <username>/<password> format'
        return None

    @staticmethod
    def set_discovery_auth_lio(chap_str, chap_mutual_str):
        iscsi_fabric = ISCSIFabricModule()
        if chap_str == '':
            iscsi_fabric.clear_discovery_auth_settings()
        else:
            chap = CHAP(chap_str)
            chap_mutual = CHAP(chap_mutual_str)
            iscsi_fabric.discovery_userid = chap.user
            iscsi_fabric.discovery_password = chap.password
            iscsi_fabric.discovery_mutual_userid = chap_mutual.user
            iscsi_fabric.discovery_mutual_password = chap_mutual.password
            iscsi_fabric.discovery_enable_auth = True

    @staticmethod
    def set_discovery_auth_config(chap_str, chap_mutual_str, config):
        discovery_auth_config = {
            'chap': '',
            'chap_mutual': ''
        }
        if chap_str != '':
            discovery_auth_config['chap'] = chap_str
            discovery_auth_config['chap_mutual'] = chap_mutual_str
        config.update_item('discovery_auth', '', discovery_auth_config)
