import asyncio
from io import BytesIO
import json
import unittest
from unittest.mock import patch, MagicMock

import main


class LiveTests(unittest.TestCase):
    def setUp(self):
        main.LIVE_STREAM_SIGNATURES.clear()
        self.relay = patch.object(main.local_relay, "ensure")
        self.relay.start()
        self.addCleanup(self.relay.stop)

    def test_fallback_reuses_registration_and_recovers_after_go2rtc_restart(self):
        name = "nvr_3_ch_13_s_1"
        puts = []
        registered = set()

        def urlopen(request, **kwargs):
            if isinstance(request, str):
                return BytesIO(json.dumps({n: {} for n in registered}).encode())
            self.assertEqual(request.get_method(), "PUT")
            puts.append(request.full_url)
            registered.add(name)
            return BytesIO(b"")

        with patch("main.sqlite3.connect") as connect, \
                patch("main.urllib.request.urlopen", side_effect=urlopen):
            connect.return_value.cursor.return_value.fetchone.return_value = (
                "device", 34567, "user", "secret")
            main.ensure_go2rtc_stream(3, 13, 1)
            main.ensure_go2rtc_stream(3, 13, 1)
            self.assertEqual(len(puts), 1)  # fallback must not reset a starting producer
            registered.clear()
            main.ensure_go2rtc_stream(3, 13, 1)
            self.assertEqual(len(puts), 2)

    def test_hq_mp4_requests_browser_compatible_h264(self):
        with patch("main.ensure_go2rtc_stream", return_value="camera"), \
                patch("main.open_mp4_proxy", return_value=MagicMock()) as open_proxy, \
                patch.dict("os.environ", {"FFMPEG_BIN": "ffmpeg"}):
            main.proxy_mp4_stream(3, 13, 1)
            url = open_proxy.call_args.args[1]
            self.assertIn("video=h264", url)
            self.assertTrue(url.startswith("rtsp://"))

    def test_qualvision_camera_uses_main_profile_for_hq(self):
        substream = "/mode=real&idc=1&ids=2"
        self.assertEqual(main.camera_rtsp_path_for_stream(substream, 2), substream)
        self.assertEqual(main.camera_rtsp_path_for_stream(substream, 1), "/mode=real&idc=1&ids=1")

    def test_other_camera_rtsp_path_is_not_rewritten_for_hq(self):
        path = "/Streaming/Channels/101"
        self.assertEqual(main.camera_rtsp_path_for_stream(path, 1), path)

    def test_registered_nvr_credentials_do_not_replace_explicit_camera_password(self):
        camera = main.Camera(name="", ip="192.0.2.56", user="admin", password="camera-password")
        with patch("main.camera_connection_from_registered_nvr", return_value=("nvr-user", "nvr-password", "quvii")), \
                patch("main.detect_camera_rtsp_path", return_value="/mode=real&idc=1&ids=2"):
            main.resolve_camera_connection(camera)
        self.assertEqual((camera.user, camera.password), ("admin", "camera-password"))
        self.assertEqual(camera.rtsp_path, "/mode=real&idc=1&ids=2")

    def test_port_fingerprint_prefers_camera_media_port_and_recorder_https(self):
        self.assertEqual(main.classify_host("192.0.2.12", {80, 554, 5801, 49152}), "camera")
        self.assertEqual(main.classify_host("192.0.2.251", {80, 443, 554}), "nvr")

    def test_vendor_fingerprint_uses_public_http_metadata(self):
        self.assertEqual(main.vendor_from_http_fingerprint("Kenik -HTTPServer"), "Kenik")
        self.assertEqual(main.vendor_from_http_fingerprint("Server: Qualvision -HTTPServer"), "Qualvision")
        self.assertEqual(main.vendor_from_http_fingerprint("Hikvision Web Components"), "Hikvision")


if __name__ == "__main__":
    unittest.main()
