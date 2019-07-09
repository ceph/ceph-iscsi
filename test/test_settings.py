# -*- coding: utf-8 -*-
from __future__ import absolute_import

import unittest

from ceph_iscsi_config.settings import Settings
from ceph_iscsi_config.target import GWTarget


class SettingsTest(unittest.TestCase):

    @staticmethod
    def _normalize(controls):
        return Settings.normalize_controls(controls, GWTarget.SETTINGS)

    def test_normalize_controls_int(self):
        self.assertEqual(
            SettingsTest._normalize({'dataout_timeout': 3}), {'dataout_timeout': 3})
        self.assertEqual(
            SettingsTest._normalize({'dataout_timeout': '3'}), {'dataout_timeout': 3})

        with self.assertRaises(ValueError) as cm:
            SettingsTest._normalize({'dataout_timeout': 1})
        self.assertEqual('expected integer >= 2 for dataout_timeout', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            SettingsTest._normalize({'dataout_timeout': 64})
        self.assertEqual('expected integer <= 60 for dataout_timeout', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            SettingsTest._normalize({'dataout_timeout': '64'})
        self.assertEqual('expected integer <= 60 for dataout_timeout', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            SettingsTest._normalize({'dataout_timeout': 'abc'})
        self.assertEqual('expected integer for dataout_timeout', str(cm.exception))

    def test_normalize_controls_yes_no(self):
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': 'Yes'}), {'immediate_data': True})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': 'yes'}), {'immediate_data': True})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': True}), {'immediate_data': True})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': 'True'}), {'immediate_data': True})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': 'true'}), {'immediate_data': True})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': '1'}), {'immediate_data': True})

        self.assertEqual(
            SettingsTest._normalize({'immediate_data': 'No'}), {'immediate_data': False})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': 'no'}), {'immediate_data': False})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': False}), {'immediate_data': False})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': 'False'}), {'immediate_data': False})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': 'false'}), {'immediate_data': False})
        self.assertEqual(
            SettingsTest._normalize({'immediate_data': '0'}), {'immediate_data': False})

        with self.assertRaises(ValueError) as cm:
            SettingsTest._normalize({'immediate_data': 'abc'})
        self.assertEqual('expected yes or no for immediate_data', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            SettingsTest._normalize({'immediate_data': 123})
        self.assertEqual('expected yes or no for immediate_data', str(cm.exception))
