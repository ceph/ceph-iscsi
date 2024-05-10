# -*- coding: utf-8 -*-
from __future__ import absolute_import

import tempfile
import sys
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# We need to mock ceph libs python bindings because there's no
# updated package in pypy
sys.modules['rados'] = mock.Mock()
sys.modules['rbd'] = mock.Mock()

from ceph_iscsi_config.client import CHAP  # noqa: E402
import ceph_iscsi_config.settings as settings  # noqa: E402
from base64 import b64encode  # noqa: E402


class ChapTest(unittest.TestCase):

    def setUp(self):
        settings.init()

    def test_chap_no_encryption(self):
        chap = CHAP("username", "password", False)
        self.assertEqual(chap.user, "username")
        self.assertEqual(chap.password, "password")
        self.assertEqual(chap.password_str, "password")

    def test_chap_encryption(self):
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=default_backend())
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        priv_key_file = tempfile.mkstemp()
        with open(priv_key_file[1], "wb") as kf:
            kf.write(priv_pem)

        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        pub_key_file = tempfile.mkstemp()
        with open(pub_key_file[1], "wb") as kf:
            kf.write(pub_pem)

        settings.config.priv_key = priv_key_file[1]
        settings.config.pub_key = pub_key_file[1]
        settings.config.ceph_config_dir = ""

        chap = CHAP("username", "passwordverylonglong", False)

        encrypted_password = chap.encrypted_password(True)
        chap2 = CHAP(chap.user, encrypted_password, True)
        self.assertEqual(chap2.user, "username")
        self.assertEqual(chap2.password, "passwordverylonglong")
        self.assertEqual(chap2.password_str, encrypted_password)
        self.assertNotEqual(encrypted_password, "passwordverylonglong")

    def test_chap_upgrade(self):
        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=default_backend())
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        priv_key_file = tempfile.mkstemp()
        with open(priv_key_file[1], "wb") as kf:
            kf.write(priv_pem)

        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        pub_key_file = tempfile.mkstemp()
        with open(pub_key_file[1], "wb") as kf:
            kf.write(pub_pem)

        settings.config.priv_key = priv_key_file[1]
        settings.config.pub_key = pub_key_file[1]
        settings.config.ceph_config_dir = ""

        key = private_key.public_key()
        encrypted_pw = b64encode(key.encrypt("passwordverylonglong".encode('utf-8'),
                                 padding.OAEP(
                                     mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                     algorithm=hashes.SHA1(),
                                     label=None))).decode('utf-8')

        chap2 = CHAP("username", encrypted_pw, True)
        self.assertEqual(chap2.user, "username")
        self.assertEqual(chap2.password, "passwordverylonglong")
