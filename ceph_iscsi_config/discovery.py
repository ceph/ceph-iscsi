from rtslib_fb.fabric import ISCSIFabricModule

from ceph_iscsi_config.client import CHAP
from ceph_iscsi_config.utils import encryption_available


class Discovery(object):

    @staticmethod
    def set_discovery_auth_lio(username, password, password_encryption_enabled, mutual_username,
                               mutual_password, mutual_password_encryption_enabled):
        iscsi_fabric = ISCSIFabricModule()
        if username == '':
            iscsi_fabric.clear_discovery_auth_settings()
        else:
            chap = CHAP(username, password, password_encryption_enabled)
            chap_mutual = CHAP(mutual_username, mutual_password,
                               mutual_password_encryption_enabled)
            iscsi_fabric.discovery_userid = chap.user
            iscsi_fabric.discovery_password = chap.password
            iscsi_fabric.discovery_mutual_userid = chap_mutual.user
            iscsi_fabric.discovery_mutual_password = chap_mutual.password
            iscsi_fabric.discovery_enable_auth = True

    @staticmethod
    def set_discovery_auth_config(username, password, mutual_username, mutual_password, config):
        encryption_enabled = encryption_available()
        discovery_auth_config = {
            'username': '',
            'password': '',
            'password_encryption_enabled': encryption_enabled,
            'mutual_username': '',
            'mutual_password': '',
            'mutual_password_encryption_enabled': encryption_enabled
        }
        if username != '':
            chap = CHAP(username, password, encryption_enabled)
            chap_mutual = CHAP(mutual_username, mutual_password, encryption_enabled)
            discovery_auth_config['username'] = chap.user
            discovery_auth_config['password'] = chap.encrypted_password(encryption_enabled)
            discovery_auth_config['mutual_username'] = chap_mutual.user
            discovery_auth_config['mutual_password'] = \
                chap_mutual.encrypted_password(encryption_enabled)
        config.update_item('discovery_auth', '', discovery_auth_config)
