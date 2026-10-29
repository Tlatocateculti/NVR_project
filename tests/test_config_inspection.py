import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import json

spec = importlib.util.spec_from_file_location('config_inspection', Path(__file__).resolve().parents[1] / 'tools/inspect_recorder_config.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ConfigInspectionTests(unittest.TestCase):
    def test_read_only_probe_never_returns_credentials_or_stream_urls(self):
        xml = ET.fromstring('<envelope><error>0</error><channel><id>3</id><config><enabled>true</enabled><ipaddress>192.0.2.3</ipaddress><username>private-user</username><password>private-password</password><mainparam>rtsp://private-user:private-password@camera/</mainparam></config></channel></envelope>')
        with patch.object(probe.sqlite3, 'connect') as db, patch.object(probe.main, 'tdk_send_command', return_value=xml) as send:
            db.return_value.__enter__.return_value.execute.return_value.fetchone.return_value = ('device', 'user', 'secret')
            result = probe.inspect(1)
        self.assertEqual(send.call_args.args[3], 'get.channelmanagement.config')
        self.assertEqual(send.call_count, 1)
        text = json.dumps(result)
        self.assertNotIn('private-user', text)
        self.assertNotIn('private-password', text)
        self.assertNotIn('rtsp://', text)
        self.assertEqual(result['channels'][0]['id'], '3')

    def test_native_time_probe_sends_only_captured_read_block(self):
        import struct
        reply = bytearray(32)
        reply[0] = 0xb0
        clock = struct.pack('<II8I', 0x31, 32, 2026, 10, 29, 4, 1, 3, 30, 0)
        with patch.object(probe.socket, 'create_connection') as connect, patch('quii_archive.read_reply', side_effect=[(reply, b''), (bytearray(32), clock)]):
            result = probe.read_time('device', 34567, 'user', 'secret')
        conn = connect.return_value.__enter__.return_value
        writes = [call.args[0] for call in conn.sendall.call_args_list]
        self.assertEqual(len(writes), 3)
        self.assertEqual(writes[0][0], 0x0a)
        self.assertEqual(writes[1][0], 0xa0)
        self.assertEqual(writes[2], bytes(4) + struct.pack('<I', 8) + bytes(24) + struct.pack('<II', 0x31, 0))
        self.assertEqual(result['recorder_local_time'], '2026-10-29T01:03:30')

    def test_network_schema_and_unknown_write_blocks_are_rejected(self):
        import struct
        adapter = bytearray(80)
        adapter[48:60] = bytes([192,0,2,5,255,255,255,0,192,0,2,1])
        dns = b'192.0.2.1'.ljust(16, b'\0') + b'192.0.2.2'.ljust(16, b'\0')
        ntp = bytes([1,3]) + struct.pack('<H', 123) + struct.pack('<I', 10) + bytes(16)
        servers = struct.pack('<I', 0) + b'time.example'.ljust(80, b'\0')
        with patch.object(probe, 'read_native_blocks', return_value={0xd5: bytes(adapter), 0xd6: dns, 0x105: ntp, 0x106: servers}):
            network = probe.read_network('device', 34567, 'user', 'secret')
        self.assertEqual(network['ipv4'], '192.0.2.5')
        self.assertEqual(network['gateway'], '192.0.2.1')
        self.assertEqual(network['ntp']['port'], 123)
        self.assertEqual(network['ntp']['interval_minutes'], 10)
        with patch.object(probe.socket, 'create_connection') as connect:
            with self.assertRaises(ValueError):
                probe.read_native_blocks('device', 34567, 'user', 'secret', [0x32])
            connect.assert_not_called()
