import unittest

from live_proxy import ffmpeg_command


class MP4ProxyCommandTests(unittest.TestCase):
    def test_regular_stream_is_copied_without_reencoding(self):
        command = ffmpeg_command("ffmpeg", "rtsp://relay/camera")
        self.assertIn("copy", command)
        self.assertNotIn("setparams=colorspace=bt709:color_primaries=bt709:color_trc=bt709:range=tv", command)

    def test_broken_color_metadata_is_normalized_to_bt709(self):
        command = ffmpeg_command("ffmpeg", "rtsp://relay/camera", normalize_color=True)
        self.assertIn("libx264", command)
        self.assertIn("setparams=colorspace=bt709:color_primaries=bt709:color_trc=bt709:range=tv", command)
        self.assertIn("bt709", command)
