import asyncio
from io import BytesIO
import json
import unittest
import urllib.parse
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

    def test_hikvision_camera_uses_documented_profile_paths(self):
        self.assertEqual(main.camera_rtsp_path_for_stream("/Streaming/Channels/102", 1),
                         "/Streaming/Channels/101")
        self.assertEqual(main.hikvision_rtsp_path(14, 1), "/Streaming/Channels/1401")
        self.assertEqual(main.hikvision_rtsp_path(14, 2), "/Streaming/Channels/1402")

    def test_hikvision_channel_inventory_uses_isapi_xml(self):
        response = b'''<InputProxyChannelList xmlns="http://www.hikvision.com/ver20/XMLSchema"><InputProxyChannel><id>1</id><name>Brama</name></InputProxyChannel><InputProxyChannel><id>14</id></InputProxyChannel></InputProxyChannelList>'''
        nvr = main.NVR(name="Hikvision", ip="192.168.90.20", port=8000,
                       user="admin", password="secret")
        with patch("main.hikvision_isapi_get", return_value=response):
            self.assertEqual(main.fetch_hikvision_channels(nvr), [
                {"channel_number": 1, "name": "Brama"},
                {"channel_number": 14, "name": "Kanał 14"},
            ])

    def test_hikvision_archive_search_parses_isapi_segments(self):
        response = b'''<CMSearchResult xmlns="http://www.isapi.org/ver20/XMLSchema"><responseStatusStrg>OK</responseStatusStrg><matchList><searchMatchItem><timeSpan><startTime>2026-11-06T10:00:00Z</startTime><endTime>2026-11-06T10:05:00Z</endTime></timeSpan><mediaSegmentDescriptor><playbackURI>rtsp://192.0.2.37/Streaming/tracks/101?starttime=20261106T100000Z&amp;endtime=20261106T100500Z</playbackURI></mediaSegmentDescriptor></searchMatchItem></matchList></CMSearchResult>'''
        with patch("main.hikvision_isapi_post", return_value=response):
            segments = main.hikvision_search_recordings(
                "192.0.2.37", "admin", "secret", 1,
                main.datetime(2026, 11, 6), main.datetime(2026, 11, 7),
            )
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0]["start"], main.datetime(2026, 11, 6, 10))
        self.assertEqual(segments[0]["end"], main.datetime(2026, 11, 6, 10, 5))
        self.assertTrue(segments[0]["filename"].startswith("hikvision:"))

    def test_hikvision_device_info_distinguishes_camera_from_recorder(self):
        camera_xml = b"<DeviceInfo><deviceType>IPCamera</deviceType></DeviceInfo>"
        nvr_xml = b"<DeviceInfo><deviceType>Network Video Recorder</deviceType></DeviceInfo>"
        with patch("main.hikvision_isapi_get", return_value=camera_xml):
            self.assertEqual(main.hikvision_device_kind("192.0.2.15", "admin", "secret"), "camera")
        with patch("main.hikvision_isapi_get", return_value=nvr_xml):
            self.assertEqual(main.hikvision_device_kind("192.0.2.10", "admin", "secret"), "nvr")

    def test_hikvision_port_8000_without_authenticated_probe_is_not_assumed_to_be_nvr(self):
        self.assertEqual(main.classify_host("192.0.2.15", {80, 554, 8000}), "camera")

    def test_hikvision_legacy_web_ui_identifies_nvr_without_credentials(self):
        self.assertEqual(main.hikvision_web_kind("192.0.2.37", "<script src='/doc/page/playback.asp'></script>"), "nvr")
        self.assertEqual(main.hikvision_web_kind("192.0.2.15", "<a href='/doc/index.html#/preview'>IP Camera</a>"), "camera")

    def test_scan_uses_hikvision_web_ui_before_credentials_are_entered(self):
        def connect(address, timeout):
            if address[1] in {80, 554, 8000}:
                return MagicMock()
            raise OSError

        with patch("main.socket.create_connection", side_effect=connect), \
                patch("main.http_device_fingerprint", return_value="<script src='/doc/page/playback.asp'></script>"):
            result = main.scan_host("192.0.2.37")
        self.assertEqual(result["type"], "nvr")
        self.assertEqual(result["vendor"], "Hikvision")
        self.assertEqual(result["port"], 8000)

    def test_hikvision_nvr_stream_uses_its_rtsp_path(self):
        main.STREAM_RTSP_SOURCES.clear()
        main.LIVE_STREAM_SIGNATURES.clear()
        with patch("main.sqlite3.connect") as connect, \
                patch("main.is_hikvision_nvr", return_value=True), \
                patch("main.urllib.request.urlopen", return_value=BytesIO(b"{}")) as urlopen:
            connect.return_value.cursor.return_value.fetchone.return_value = (
                "192.168.90.20", 8000, "admin", "secret")
            main.ensure_go2rtc_stream(7, 14, 2)
            self.assertEqual(main.STREAM_RTSP_SOURCES["nvr_7_ch_14_s_2"],
                             "rtsp://admin:secret@192.168.90.20:554/Streaming/Channels/1402")
            self.assertIn("/Streaming/Channels/1402", urllib.parse.unquote(urlopen.call_args.args[0].full_url))

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

    def test_camera_webrtc_rejects_stream_needing_color_normalization(self):
        offer = main.WebRTCOffer(dvr_id=2, channel=1, sdp="offer", stream=2)
        request = MagicMock()
        request.url.hostname = "127.0.0.1"
        with patch("main.ensure_camera_stream", return_value="camera_2_s_2"), \
                patch("main.stream_needs_color_normalization", return_value=True):
            with self.assertRaises(main.HTTPException) as ctx:
                main.start_camera_webrtc_session(2, offer, request)
            self.assertEqual(ctx.exception.status_code, 409)

    def test_nvr_webrtc_rejects_stream_needing_color_normalization(self):
        offer = main.WebRTCOffer(dvr_id=4, channel=16, sdp="offer", stream=1)
        request = MagicMock()
        request.url.hostname = "127.0.0.1"
        with patch("main.ensure_go2rtc_stream", return_value="nvr_4_ch_16_s_1"), \
                patch("main.stream_needs_color_normalization", return_value=True):
            with self.assertRaises(main.HTTPException) as ctx:
                main.start_webrtc_session(offer, request)
            self.assertEqual(ctx.exception.status_code, 409)

    def test_camera_mp4_passes_color_normalization_flag(self):
        with patch("main.ensure_camera_stream", return_value="camera_2_s_1"), \
                patch("main.open_mp4_proxy", return_value=MagicMock()) as open_proxy, \
                patch("main.stream_needs_color_normalization", return_value=True), \
                patch("main.get_rtsp_url_for_stream", return_value="rtsp://camera:554/live"), \
                patch.dict("os.environ", {"FFMPEG_BIN": "ffmpeg"}):
            main.proxy_camera_mp4_stream(2, 1)
            open_proxy.assert_called_once_with("ffmpeg", "rtsp://camera:554/live", True)

    def test_nvr_mp4_passes_color_normalization_flag(self):
        with patch("main.ensure_go2rtc_stream", return_value="nvr_4_ch_16_s_1"), \
                patch("main.open_mp4_proxy", return_value=MagicMock()) as open_proxy, \
                patch("main.stream_needs_color_normalization", return_value=True), \
                patch("main.get_rtsp_url_for_stream", return_value="rtsp://admin:pwd@192.168.49.82:554/live"), \
                patch.dict("os.environ", {"FFMPEG_BIN": "ffmpeg"}):
            main.proxy_mp4_stream(4, 16, 1)
            open_proxy.assert_called_once_with("ffmpeg", "rtsp://admin:pwd@192.168.49.82:554/live", True)

    def test_stream_needs_color_normalization_detects_gbr_metadata(self):
        main.STREAM_COLOR_NORMALIZATION.clear()
        mock_output = "color_space=gbr\ncolor_transfer=reserved\ncolor_primaries=reserved\n"
        with patch("main.get_rtsp_url_for_stream", return_value="rtsp://test"), \
                patch("shutil.which", return_value="ffprobe"), \
                patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=mock_output)):
            self.assertTrue(main.stream_needs_color_normalization("camera_test"))

    def test_stream_needs_color_normalization_passes_normal_bt709(self):
        main.STREAM_COLOR_NORMALIZATION.clear()
        mock_output = "color_space=bt709\ncolor_transfer=bt709\ncolor_primaries=bt709\n"
        with patch("main.get_rtsp_url_for_stream", return_value="rtsp://test"), \
                patch("shutil.which", return_value="ffprobe"), \
                patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=mock_output)):
            self.assertFalse(main.stream_needs_color_normalization("camera_normal"))

    def test_nvr_stream_prefers_direct_camera_source_when_available(self):
        main.STREAM_RTSP_SOURCES.clear()
        main.LIVE_STREAM_SIGNATURES.clear()
        puts = []

        def fake_urlopen(request, **kwargs):
            if isinstance(request, str):
                return BytesIO(b"{}")
            puts.append(request.full_url)
            return BytesIO(b"")

        cam_config = {
            "enabled": True,
            "ip": "192.168.49.80",
            "port": 80,
            "user": "admin",
            "password": "pwd",
            "remoteid": "1",
            "protocol": "onvif",
        }
        with patch("main.sqlite3.connect") as connect, \
                patch("main.get_nvr_channel_camera_config", return_value=cam_config), \
                patch("main.urllib.request.urlopen", side_effect=fake_urlopen):
            connect.return_value.cursor.return_value.fetchone.return_value = (
                "192.168.49.252", 34567, "admin", "nvrpass")
            stream_name = main.ensure_go2rtc_stream(4, 14, 1)

            self.assertEqual(stream_name, "nvr_4_ch_14_s_1")
            self.assertEqual(
                main.STREAM_RTSP_SOURCES.get("nvr_4_ch_14_s_1"),
                "rtsp://admin:pwd@192.168.49.80:554/mode=real&idc=1&ids=1",
            )
            self.assertEqual(len(puts), 1)
            # Direct camera stream must be registered as primary source before NVR relay
            put_url = urllib.parse.unquote(puts[0])
            self.assertIn("src=rtsp://admin:pwd@192.168.49.80:554/mode=real&idc=1&ids=1#media=video", put_url)
            self.assertIn("src=rtsp://admin:nvrpass@192.168.49.252:554/mode=real&idc=14&ids=1#media=video", put_url)
            self.assertTrue(put_url.index("192.168.49.80") < put_url.index("192.168.49.252"))

    def test_get_rtsp_url_for_stream_uses_channel_camera_config(self):
        main.STREAM_RTSP_SOURCES.clear()
        cam_config = {
            "enabled": True,
            "ip": "192.168.49.80",
            "port": 80,
            "user": "admin",
            "password": "pwd",
            "remoteid": "1",
            "protocol": "onvif",
        }
        with patch("main.get_nvr_channel_camera_config", return_value=cam_config):
            url = main.get_rtsp_url_for_stream("nvr_4_ch_14_s_1")
            self.assertEqual(url, "rtsp://admin:pwd@192.168.49.80:554/mode=real&idc=1&ids=1")


if __name__ == "__main__":
    unittest.main()
