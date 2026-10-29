"""Fragmented MP4 without go2rtc's crash-prone HTTP MP4 consumer."""
import subprocess
import threading


class MP4Proxy:
    def __init__(self, binary, source):
        self.lock = threading.Lock()
        self.closed = False
        self.process = subprocess.Popen([
            binary, "-hide_banner", "-loglevel", "error", "-nostdin",
            "-rtsp_transport", "tcp", "-timeout", "15000000", "-i", source,
            "-map", "0:v:0", "-an", "-c:v", "copy", "-f", "mp4",
            "-movflags", "frag_keyframe+empty_moov+default_base_moof",
            "-flush_packets", "1", "pipe:1",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
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


def open_mp4_proxy(binary, source):
    return MP4Proxy(binary, source)
