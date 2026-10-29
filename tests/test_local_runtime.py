from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from local_runtime import LocalRelay
from live_proxy import MP4Proxy


class RelayTests(unittest.TestCase):
    def test_health_uses_actual_go2rtc_api_schema(self):
        relay = LocalRelay("http://127.0.0.1:1984", ".")
        response = BytesIO(json.dumps({"version": "1.9.15", "revision": "test"}).encode())
        with patch("local_runtime.urllib.request.urlopen", return_value=response):
            self.assertTrue(relay.healthy())

    def test_dead_owned_relay_is_restarted(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "go2rtc.exe"
            binary.touch()
            relay = LocalRelay("http://127.0.0.1:1984", folder)
            relay.enabled = True
            relay.binary = str(binary)
            child = MagicMock()
            child.poll.return_value = None
            with patch.object(relay, "healthy", side_effect=[False, True, False, True]), \
                    patch("local_runtime.subprocess.Popen", return_value=child) as spawn:
                relay.ensure()
                child.poll.return_value = 1
                relay.ensure()
                self.assertEqual(spawn.call_count, 2)
                config = json.loads((Path(folder) / "data/go2rtc-managed.yaml").read_text())
                self.assertEqual(config['api']['listen'], '127.0.0.1:1984')
                self.assertNotIn('streams', config)
            relay.stop()

    def test_existing_healthy_external_service_is_not_stopped(self):
        relay = LocalRelay("http://127.0.0.1:1984", ".")
        relay.enabled = True
        with patch.object(relay, "healthy", return_value=True), \
                patch("local_runtime.subprocess.Popen") as spawn:
            relay.ensure()
            relay.stop()
            spawn.assert_not_called()

    def test_docker_or_disabled_runtime_does_not_launch_local_process(self):
        relay = LocalRelay("http://go2rtc:1984", ".")
        with patch("local_runtime.subprocess.Popen") as spawn:
            relay.ensure()
            relay.start()
            spawn.assert_not_called()


class ProxyTests(unittest.TestCase):
    def test_disconnect_terminates_owned_copy_process(self):
        child = MagicMock()
        child.poll.return_value = None
        child.stdout = BytesIO(b"fragmented-mp4-bytes")
        with patch("live_proxy.subprocess.Popen", return_value=child):
            proxy = MP4Proxy("ffmpeg", "rtsp://127.0.0.1:8554/camera?video=h264")
            self.assertEqual(b"".join(proxy.chunks()), b"fragmented-mp4-bytes")
            proxy.close()
        child.terminate.assert_called_once()
        self.assertTrue(child.stdout.closed)

    def test_failed_input_does_not_leave_a_process_running(self):
        child = MagicMock()
        child.poll.return_value = None
        child.stdout = BytesIO(b"")
        with patch("live_proxy.subprocess.Popen", return_value=child):
            with self.assertRaises(OSError):
                MP4Proxy("ffmpeg", "rtsp://127.0.0.1:8554/camera?video=h264")
        child.terminate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
