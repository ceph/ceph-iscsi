from ceph_iscsi_config import gateway
import logging
import mock
import subprocess
import unittest


class CephiSCSIGatewayTest(unittest.TestCase):

    def setUp(self):
        self.error = subprocess.CalledProcessError(
            returncode=2,
            cmd=["a command"],
            output=b'some output')
        self.run_ceph_mock_return = []
        self.settings = mock.MagicMock(),

        self.logger = logging.getLogger('rbd-target-api')
        self.gw = gateway.CephiSCSIGateway(
            self.logger,
            self.settings,
            'thishost')

    def mock_run_ceph_cmd(self, cmd, stderr=None, shell=True):
        return self.run_ceph_mock_return.pop()

    @mock.patch.object(gateway.subprocess, 'check_output')
    def test_run_ceph_cmd(self, check_output):
        self.gw = gateway.CephiSCSIGateway(
            None,
            {'a': 'b'},
            'thishost')
        check_output.return_value = 'The result'

        # Check a command runs with default settings
        self.assertEqual(
            self.gw._run_ceph_cmd('a command'),
            ('The result', None))
        check_output.assert_called_once_with(
            'a command',
            stderr=subprocess.STDOUT,
            shell=True)

        # Check a command runs with supplied stderr
        check_output.reset_mock()
        self.assertEqual(
            self.gw._run_ceph_cmd(
                'a command',
                stderr=5),
            ('The result', None))
        check_output.assert_called_once_with(
            'a command',
            stderr=5,
            shell=True),

        # Check a command without running through shell
        check_output.reset_mock()
        self.assertEqual(
            self.gw._run_ceph_cmd('a command', shell=False),
            ('The result', None))
        check_output.assert_called_once_with(
            'a command',
            stderr=subprocess.STDOUT,
            shell=False)

        # Check handling of CalledProcessError
        check_output.reset_mock()
        error = subprocess.CalledProcessError(
            returncode=2, cmd=["a command"])
        check_output.side_effect = error
        self.assertEqual(
            self.gw._run_ceph_cmd('a command'),
            (None, error))

    @mock.patch.object(gateway.CephiSCSIGateway, '_run_ceph_cmd')
    def test_ceph_rm_blocklist(self, run_ceph_mock):
        run_ceph_mock.side_effect = self.mock_run_ceph_cmd
        self.run_ceph_mock_return = [('Result', None)]
        self.assertTrue(self.gw.ceph_rm_blocklist('10.0.0.10'))
        run_ceph_mock.assert_called_once_with(
            ('ceph -n client.admin --conf /etc/ceph/ceph.conf osd '
             'blocklist rm 10.0.0.10'))

        # Test fallback from blocklist to blacklist
        run_ceph_mock.reset_mock()
        self.run_ceph_mock_return = [
            ('Result', None),
            (None, self.error)]
        self.assertTrue(self.gw.ceph_rm_blocklist('10.0.0.10'))
        run_ceph_mock.assert_has_calls([
            mock.call(
                ('ceph -n client.admin --conf /etc/ceph/ceph.conf osd '
                 'blocklist rm 10.0.0.10')),
            mock.call(
                ('ceph -n client.admin --conf /etc/ceph/ceph.conf osd '
                 'blacklist rm 10.0.0.10'))])

        # Test fallback failing too
        run_ceph_mock.reset_mock()
        self.run_ceph_mock_return = [
            (None, self.error),
            (None, self.error)]
        self.assertFalse(self.gw.ceph_rm_blocklist('10.0.0.10'))
        run_ceph_mock.assert_has_calls([
            mock.call(
                ('ceph -n client.admin --conf /etc/ceph/ceph.conf osd '
                 'blocklist rm 10.0.0.10')),
            mock.call(
                ('ceph -n client.admin --conf /etc/ceph/ceph.conf osd '
                 'blacklist rm 10.0.0.10'))])
