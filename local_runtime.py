"""Own and supervise the local Windows relay; Docker uses its separate service."""
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
import urllib.request
from urllib.parse import urlparse


class LocalRelay:
    def __init__(self, api, root):
        self.api = api.rstrip("/")
        self.root = Path(root)
        self.binary = os.environ.get("GO2RTC_BIN") or str(self.root / "tools" / "go2rtc.exe")
        parsed = urlparse(api)
        self.enabled = (os.name == "nt" and parsed.scheme == "http"
                        and parsed.hostname in ("127.0.0.1", "localhost")
                        and os.environ.get("GO2RTC_MANAGED", "1") != "0")
        self.port = parsed.port or 1984
        self.process = None
        self.thread = None
        self.log_file = None
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.last_healthy = 0.0

    def healthy(self):
        try:
            with urllib.request.urlopen(self.api + "/api", timeout=1) as response:
                info = json.load(response)
                return isinstance(info, dict) and bool(info.get("version")) and "revision" in info
        except (OSError, ValueError):
            return False

    def ensure(self):
        if not self.enabled:
            return
        with self.lock:
            owned_alive = self.process is not None and self.process.poll() is None
            if owned_alive and time.monotonic() - self.last_healthy < 1:
                return
            if self.healthy():
                self.last_healthy = time.monotonic()
                return
            if not owned_alive:
                if not Path(self.binary).is_file():
                    raise OSError("Brak lokalnego go2rtc. Ustaw GO2RTC_BIN lub umieść program w tools/go2rtc.exe.")
                folder = self.root / "data"
                folder.mkdir(exist_ok=True)
                config = folder / "go2rtc-managed.yaml"
                # Rebuild only the owned runtime configuration. Streams are
                # registered again from the application after a relay restart.
                config.write_text(json.dumps({
                    "api": {"listen": f"127.0.0.1:{self.port}"},
                    "rtsp": {"listen": "127.0.0.1:8554"},
                    "webrtc": {"listen": "127.0.0.1:8555", "candidates": ["127.0.0.1:8555"]},
                    "ffmpeg": {"bin": os.environ.get("FFMPEG_BIN") or shutil.which("ffmpeg") or "ffmpeg"},
                    "log": {"level": "error"},
                }), encoding="utf-8")
                if self.log_file:
                    self.log_file.close()
                self.log_file = (folder / "go2rtc-runtime.log").open("ab")
                self.process = subprocess.Popen(
                    [self.binary, "-config", str(config)], cwd=self.root,
                    stdin=subprocess.DEVNULL, stdout=self.log_file, stderr=self.log_file,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and not self.stopping.is_set():
                if self.healthy():
                    self.last_healthy = time.monotonic()
                    return
                if self.process.poll() is not None:
                    break
                self.stopping.wait(0.2)
            raise OSError("Lokalny przekaźnik obrazu nie uruchomił się poprawnie.")

    def start(self):
        if not self.enabled or self.thread:
            return
        self.stopping.clear()
        try:
            self.ensure()
        except OSError:
            logging.getLogger(__name__).warning("Local relay unavailable; supervisor will retry")

        def monitor():
            while not self.stopping.wait(2):
                try:
                    self.ensure()
                except OSError:
                    logging.getLogger(__name__).warning("Local relay unavailable; retrying")

        self.thread = threading.Thread(target=monitor, name="nvr-relay-supervisor", daemon=True)
        self.thread.start()

    def stop(self):
        self.stopping.set()
        if self.thread:
            self.thread.join(timeout=4)
            self.thread = None
        with self.lock:
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            if self.log_file:
                self.log_file.close()
                self.log_file = None
