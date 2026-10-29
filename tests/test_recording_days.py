import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import main

class RecordingDaysTests(unittest.TestCase):
    def test_calendar_queries_actual_channel_not_bitmask(self):
        for channel, days in [(3, [27, 28, 29]), (14, [])]:
            with self.subTest(channel=channel), patch('main.sqlite3.connect') as db, patch('main.tdk_send_command') as send:
                db.return_value.cursor.return_value.fetchone.return_value = ('device', 'user', 'secret')
                send.return_value = ET.fromstring('<envelope><error>0</error><daymask>' + ','.join(map(str, days)) + '</daymask></envelope>')
                result = main.get_recording_days(1, channel, 2026, 10)
                self.assertIn(f'<channelmask>{channel}</channelmask>', send.call_args.args[4])
                self.assertEqual(result['days'], days)

if __name__ == '__main__':
    unittest.main()
