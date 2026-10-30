"""Fragmented MP4 without go2rtc's crash-prone HTTP MP4 consumer."""
import subprocess
import threading


def ffmpeg_command(binary, source, normalize_color=False):
    command = [
        binary, "-hide_banner", "-loglevel", "error", "-nostdin",
        "-rtsp_transport", "tcp", "-timeout", "15000000", "-i", source,
        "-map", "0:v:0", "-an",
    ]
    if normalize_color:
        # Some older NVRs label Y'CbCr frames as GBR. Browsers then apply the
        # wrong conversion and show a green/magenta image. Decode and re-encode
        # with unambiguous BT.709 metadata only for those affected streams.
        command += [
            "-vf", "setparams=colorspace=bt709:color_primaries=bt709:color_trc=bt709:range=tv",
            "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
            "-pix_fmt", "yuv420p", "-color_range", "tv", "-colorspace", "bt709",
            "-color_trc", "bt709", "-color_primaries", "bt709",
        ]
    else:
        command += ["-c:v", "copy"]
    return command + [
        "-f", "mp4", "-movflags", "frag_keyframe+empty_moov+default_base_moof",
        "-flush_packets", "1", "pipe:1",
    ]


class MP4Proxy:
    def __init__(self, binary, source, normalize_color=False):
        self.lock = threading.Lock()
        self.closed = False
        self.process = subprocess.Popen(ffmpeg_command(binary, source, normalize_color),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            self.first = self.process.stdout.read1(16384)
            if not self.first:
                raise OSError("Brak danych obrazu z lokalnego przekaźnika.")
        except BaseException:
            self.close()
            raise

    def chunks(self):
        try:
            yield self.first
            while chunk := self.process.stdout.read1(65536):
                yield chunk
        finally:
            self.close()

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            self.process.stdout.close()


def open_mp4_proxy(binary, source, normalize_color=False):
    return MP4Proxy(binary, source, normalize_color)
