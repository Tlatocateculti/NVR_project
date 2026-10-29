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


if __name__ == "__main__":
    unittest.main()
