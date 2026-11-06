from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse, RedirectResponse
from starlette.background import BackgroundTask
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Literal
from threading import BoundedSemaphore, Event, Lock, Thread
from queue import Queue, Empty
from uuid import uuid4
import asyncio
import random
import time
import time as time_module
import shutil
import tempfile
import logging
import mimetypes
import html
from quii_archive import ArchiveError, ArchiveCancelled, Recording, save_video, convert_video, anonymize_faces
from local_runtime import LocalRelay
from live_proxy import open_mp4_proxy
from auth import callback_url, oauth, settings as auth_settings
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dvrip import DVRIPCam
from datetime import datetime, timedelta, timezone
import xml.etree.ElementTree as ET
import urllib.request
import urllib.parse
import urllib.error
import subprocess
import hashlib
import sqlite3
import secrets
import base64
import struct
import json
import re
import os
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

@asynccontextmanager
async def app_lifespan(app):
    local_relay.start()
    download_jobs.start()
    scheduler = asyncio.create_task(time_sync_scheduler())
    try:
        yield
    finally:
        scheduler.cancel()
        download_jobs.stop()
        local_relay.stop()


app = FastAPI(lifespan=app_lifespan)
templates = Jinja2Templates(directory="templates")
mimetypes.add_type("text/javascript", ".mjs")
app.mount("/static", StaticFiles(directory="static"), name="static")

GO2RTC_API = os.environ.get(
    "GO2RTC_API", "http://127.0.0.1:1984" if os.name == "nt" else "http://go2rtc:1984"
).rstrip("/")
local_relay = LocalRelay(GO2RTC_API, Path(__file__).resolve().parent)
GO2RTC_RTSP = os.environ.get(
    "GO2RTC_RTSP", f"rtsp://{urllib.parse.urlparse(GO2RTC_API).hostname}:8554"
).rstrip("/")
LIVE_STREAM_LOCK = Lock()
LIVE_STREAM_SIGNATURES = {}
STREAM_RTSP_SOURCES: dict[str, str] = {}
STREAM_COLOR_NORMALIZATION: dict[str, bool] = {}
HIKVISION_NVR_CACHE: dict[tuple[str, str], tuple[float, bool]] = {}
# Some NVR firmwares silently cap ContentMgmt/search at 64 matches even when
# maxResults is higher.  Keep this explicit so calendar search can split a
# saturated time range instead of silently omitting later days.
HIKVISION_SEARCH_RESULT_LIMIT = 64
DISCOVERY_JOB_LOCK = Lock()
DISCOVERY_CANCEL = Event()
DISCOVERY_JOB: dict = {"running": False, "cancelled": False, "network": "", "completed": 0,
                       "total": 0, "devices": [], "error": "", "networks": [], "network_index": 0}

os.makedirs("data", exist_ok=True)


@app.middleware("http")
async def require_login_for_application(request: Request, call_next):
    """Keep the login callback public; protect every application/API route."""
    if not auth_settings.enabled:
        return await call_next(request)
    path = request.url.path
    public = path.startswith("/login") or path.startswith("/auth/") or path.startswith("/static/")
    if public or request.session.get("user"):
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse(status_code=401, content={"detail": "Wymagane jest zalogowanie."})
    return RedirectResponse(url="/login", status_code=303)


# Register after the function middleware so the session is available to it.
app.add_middleware(
    SessionMiddleware,
    secret_key=auth_settings.session_secret or secrets.token_urlsafe(48),
    same_site="lax",
    https_only=auth_settings.cookie_secure,
)


class NVR(BaseModel):
    name: str
    ip: str
    port: int
    user: str
    password: str
    vendor: str | None = None


class NVRUpdate(BaseModel):
    name: str
    ip: str
    port: int
    user: str
    password: str = ""
    vendor: str | None = None


class WebRTCOffer(BaseModel):
    dvr_id: int
    channel: int
    sdp: str
    stream: int = 2  # 2 = Substream (zapasowy), 1 = Mainstream (HQ)


class Camera(BaseModel):
    name: str
    ip: str
    port: int = 554
    user: str = "admin"
    password: str = ""
    rtsp_path: str = "/"
    vendor: str | None = None
    category_ids: list[int] = []


class DeviceScanRequest(BaseModel):
    targets: str = ""
    user: str = ""
    password: str = ""
    networks: list[str] = []


class DiscoveryNetworkSelection(BaseModel):
    networks: list[str] = []


class DeviceCategory(BaseModel):
    name: str
    hidden: bool = False


class TimeSyncSettings(BaseModel):
    source: Literal["container", "ntp", "manual"] = "container"
    ntp_server: str = "pool.ntp.org"
    manual_time: str = ""
    interval_minutes: int = 10
    target_keys: list[str] = []
    enabled: bool = True
    hidden: bool = False


class CategoryMembers(BaseModel):
    device_keys: list[str] = []


class DeviceAssignments(BaseModel):
    assignments: dict[str, int | None] = {}


def tdk_aes_encrypt(password: str, user: str, nc: str) -> str:
    """Szyfrowanie hasła AES-256-CBC (ZeroPadding) dla protokołu Qualvision/TDK (/tdkcgi)."""
    key_hex = hashlib.sha256(f"{user}:{nc}".encode("utf-8")).hexdigest()
    iv_hex = b"0000000000000000".hex()
    raw = password.encode("utf-8")
    if len(raw) > 0:
        rem = len(raw) % 16
        raw += b"\x00" * (16 - rem if rem != 0 else 16)
    else:
        raw = b"\x00" * 16
    encrypted = subprocess.check_output(
        ["openssl", "enc", "-aes-256-cbc", "-nopad", "-K", key_hex, "-iv", iv_hex],
        input=raw,
    )
    return base64.b64encode(encrypted).decode("ascii")


def tdk_send_command(ip: str, user: str, password: str, command: str, content: str = "", timeout: float = 12.0) -> ET.Element | None:
    nc = secrets.token_hex(16)
    enc_pwd = tdk_aes_encrypt(password, user, nc)
    xml_payload = (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<envelope><header>"
        "<security>usernametoken</security>"
        f"<username>{user}</username>"
        f"<password>{enc_pwd}</password>"
        f"<nc>{nc}</nc>"
        "</header><body>"
        f"<command>{command}</command>"
        f"<content>{content}</content>"
        "</body></envelope>"
    ).encode("utf-8")

    req = urllib.request.Request(
        f"http://{ip}/tdkcgi",
        data=xml_payload,
        headers={"Content-Type": "application/xml"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            xml_text = resp.read().decode("utf-8", errors="replace")
        return ET.fromstring(xml_text)
    except (urllib.error.URLError, TimeoutError, OSError, ET.ParseError):
        return None


def fetch_tdkcgi_channels(nvr: NVR) -> list[dict] | None:
    """Pobiera listę, nazwy oraz status połączenia kanałów z rejestratora Qualvision/TDK (/tdkcgi)."""
    root = tdk_send_command(nvr.ip, nvr.user, nvr.password, "g.enc.chname")
    if root is None:
        return None

    err_el = root.find(".//error")
    err_code = err_el.text.strip() if err_el is not None and err_el.text else "-1"

    if err_code != "0":
        if err_code in ("-2", "-3", "-4"):
            raise HTTPException(
                status_code=401,
                detail=f"Rejestrator odrzucił logowanie (błędny użytkownik lub hasło, kod={err_code}).",
            )
        raise HTTPException(
            status_code=400,
            detail=f"Rejestrator zwrócił błąd autoryzacji/komendy (kod={err_code}).",
        )

    channels = []
    for idx, ch_el in enumerate(root.findall(".//ch")):
        id_text = ch_el.findtext("id")
        name_text = ch_el.findtext("name")
        ch_num = int(id_text) if id_text and id_text.isdigit() else (idx + 1)
        ch_name = (name_text or "").strip() or f"Kanał {ch_num}"
        channels.append({"channel_number": ch_num, "name": ch_name})

    return channels


def fetch_tdkcgi_channel_status(nvr: NVR) -> dict[int, bool] | None:
    """Read transient camera connection state without changing stored names."""
    root = tdk_send_command(nvr.ip, nvr.user, nvr.password, "get.channelmanagement.status")
    if root is None:
        return None

    states: dict[int, bool] = {}
    for channel in root.findall(".//channel"):
        channel_id = channel.findtext("id")
        connection = (channel.findtext(".//connection") or "").strip().lower()
        if channel_id and channel_id.isdigit():
            states[int(channel_id)] = connection == "connected"
    return states


class SafeDVRIPCam(DVRIPCam):
    """Rozszerzenie DVRIPCam z python-dvr dla rejestratorów Xiongmai (XM NETIP)."""

    def _recv_exact(self, length: int) -> bytes:
        buf = b""
        while len(buf) < length:
            chunk = self.socket.recv(length - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def send(self, msg, data=None):
        if self.socket is None:
            return {"Ret": 101}

        if data is None:
            data = {}

        payload = json.dumps(data, ensure_ascii=False).encode("utf-8") if isinstance(data, dict) else b""
        pkt = (
            struct.pack(
                "<BB2xII2xHI",
                255,
                0,
                self.session,
                self.packet_count,
                msg,
                len(payload) + 2,
            )
            + payload
            + b"\x0a\x00"
        )
        self.socket.sendall(pkt)
        self.packet_count += 1

        header = self._recv_exact(20)
        if len(header) < 20:
            return {"Ret": 101, "Error": "Brak nagłówka odpowiedzi z NVR"}

        head, version, session_id, seq, msgid, len_data = struct.unpack("<BB2xII2xHI", header)
        if head != 255:
            return {"Ret": 101, "Error": f"Nieznany protokół binarny (nagłówek=0x{head:02x})"}

        if session_id:
            self.session = session_id

        if len_data <= 0:
            return {"Ret": 101, "MsgId": msgid}

        raw_body = self._recv_exact(len_data)
        cleaned = raw_body.rstrip(b"\x00\x0a\r ")
        if not cleaned:
            return {"Ret": 101, "MsgId": msgid}

        text = cleaned.decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            last_brace = text.rfind("}")
            if last_brace != -1:
                try:
                    return json.loads(text[: last_brace + 1])
                except json.JSONDecodeError:
                    pass
            return {"Ret": 101, "Raw": text}

    def safe_login(self) -> tuple[bool, str]:
        self.connect()
        self.socket.settimeout(5.0)
        res = self.send(
            1000,
            {
                "EncryptType": "MD5",
                "LoginType": "DVRIP-Web",
                "PassWord": self.hash_pass,
                "UserName": self.user,
            },
        )
        if not isinstance(res, dict):
            return False, "Nieprawidłowa odpowiedź logowania z NVR"

        ret = res.get("Ret", 0)
        if ret not in (100, 515):
            return False, f"Rejestrator odrzucił logowanie (kod Ret={ret})"

        session_str = res.get("SessionID")
        if isinstance(session_str, str) and session_str.startswith("0x"):
            self.session = int(session_str, 16)

        return True, "OK"


def init_db():
    conn = sqlite3.connect('data/dvrs.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS dvrs
                 (id INTEGER PRIMARY KEY, name TEXT, ip TEXT, port INTEGER, user TEXT, password TEXT,
                  vendor TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS channels
                 (id INTEGER PRIMARY KEY,
                  dvr_id INTEGER,
                  channel_number INTEGER,
                  name TEXT,
                  FOREIGN KEY(dvr_id) REFERENCES dvrs(id) ON DELETE CASCADE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS cameras
                 (id INTEGER PRIMARY KEY, name TEXT NOT NULL, ip TEXT NOT NULL,
                  port INTEGER NOT NULL DEFAULT 554, user TEXT, password TEXT,
                  rtsp_path TEXT NOT NULL DEFAULT '/')''')
    c.execute('''CREATE TABLE IF NOT EXISTS device_categories
                 (id INTEGER PRIMARY KEY, name TEXT NOT NULL, hidden INTEGER NOT NULL DEFAULT 0,
                  system_key TEXT UNIQUE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS device_category_items
                 (category_id INTEGER NOT NULL, device_type TEXT NOT NULL,
                  device_id INTEGER NOT NULL,
                 PRIMARY KEY(category_id, device_type, device_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS time_sync_settings
                 (id INTEGER PRIMARY KEY CHECK (id = 1), source TEXT NOT NULL,
                  ntp_server TEXT NOT NULL, manual_time TEXT NOT NULL,
                  interval_minutes INTEGER NOT NULL, target_keys TEXT NOT NULL,
                  enabled INTEGER NOT NULL, last_run_at REAL NOT NULL DEFAULT 0)''')
    c.execute("INSERT OR IGNORE INTO time_sync_settings VALUES (1, 'container', 'pool.ntp.org', '', 10, '[]', 1, 0)")
    c.execute('''CREATE TABLE IF NOT EXISTS discovery_networks
                 (cidr TEXT PRIMARY KEY, first_seen_at REAL NOT NULL, last_seen_at REAL NOT NULL,
                  devices_seen INTEGER NOT NULL DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS discovery_scan_networks
                 (cidr TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1, hidden INTEGER NOT NULL DEFAULT 0,
                 custom INTEGER NOT NULL DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS download_jobs
                 (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, created_at REAL NOT NULL,
                  started_at REAL, finished_at REAL, dvr_id INTEGER NOT NULL,
                  dvr_name TEXT NOT NULL, channel INTEGER NOT NULL, camera_name TEXT NOT NULL,
                  recording_date TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT NOT NULL,
                  filename TEXT, output_format TEXT NOT NULL, quality TEXT NOT NULL,
                  anonymized INTEGER NOT NULL, status TEXT NOT NULL, stage TEXT NOT NULL,
                  progress REAL NOT NULL DEFAULT 0, result_path TEXT, result_name TEXT,
                  error TEXT, duration_seconds REAL NOT NULL DEFAULT 0)''')
    c.execute('''CREATE INDEX IF NOT EXISTS download_jobs_owner_created
                 ON download_jobs(owner_id, created_at DESC)''')
    try:
        c.execute("ALTER TABLE download_jobs ADD COLUMN fps TEXT NOT NULL DEFAULT 'original'")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE discovery_scan_networks ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE discovery_scan_networks ADD COLUMN custom INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE dvrs ADD COLUMN vendor TEXT")
    except sqlite3.OperationalError:
        pass
    # A category is a folder, not a tag: a device can belong to one custom
    # category at most. Existing experimental rows are normalised on upgrade.
    c.execute('''DELETE FROM device_category_items WHERE rowid NOT IN
                 (SELECT MIN(rowid) FROM device_category_items GROUP BY device_type, device_id)''')
    c.execute('''CREATE UNIQUE INDEX IF NOT EXISTS one_custom_category_per_device
                 ON device_category_items(device_type, device_id)''')
    # The system group is permanent. It is a virtual group, so it needs no rows
    # in device_category_items and always contains every recorder and camera.
    c.execute("INSERT OR IGNORE INTO device_categories (name, hidden, system_key) VALUES ('Wszystkie urządzenia', 0, 'all')")
    # Connection state is transient and must never be persisted as part of a
    # channel name. Remove labels written by older versions of the application.
    c.execute("UPDATE channels SET name = REPLACE(name, ' [offline]', '') WHERE name LIKE '% [offline]'")
    conn.commit()
    conn.close()


init_db()


def fetch_nvr_channels(nvr: NVR) -> list[dict]:
    """Pobiera listę kanałów z Hikvision ISAPI, Qualvision/TDK lub Xiongmai NETIP."""
    hikvision_channels = fetch_hikvision_channels(nvr)
    if hikvision_channels is not None:
        return hikvision_channels
    tdk_channels = fetch_tdkcgi_channels(nvr)
    if tdk_channels is not None and len(tdk_channels) > 0:
        return tdk_channels

    cam = SafeDVRIPCam(nvr.ip, user=nvr.user, password=nvr.password, port=nvr.port)
    try:
        ok, msg = cam.safe_login()
        if not ok:
            raise HTTPException(status_code=401, detail=msg)

        session_hex = f"0x{cam.session:08X}"

        res = cam.send(1048, {"Name": "ChannelTitle", "SessionID": session_hex})
        titles = res.get("ChannelTitle") if isinstance(res, dict) else None

        if not titles or not isinstance(titles, list):
            res_cfg = cam.send(1042, {"Name": "ChannelTitle", "SessionID": session_hex})
            if isinstance(res_cfg, dict):
                titles = res_cfg.get("ChannelTitle")

        if not titles or not isinstance(titles, list):
            res_sys = cam.send(1020, {"Name": "SystemInfo", "SessionID": session_hex})
            sys_info = res_sys.get("SystemInfo", {}) if isinstance(res_sys, dict) else {}
            total_ch = int(sys_info.get("VideoInChannel", 0)) + int(sys_info.get("DigChannel", 0))
            if total_ch > 0:
                titles = [f"Kanał {i + 1}" for i in range(total_ch)]

        if not titles or not isinstance(titles, list):
            raise ValueError(f"Urządzenie nie zwróciło listy kanałów (odpowiedź: {res})")

        channels = []
        for idx, item in enumerate(titles):
            if isinstance(item, dict):
                ch_name = item.get("Name") or item.get("Title") or f"Kanał {idx + 1}"
            else:
                ch_name = str(item).strip() or f"Kanał {idx + 1}"
            channels.append({"channel_number": idx + 1, "name": ch_name})

        return channels
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Błąd komunikacji z NVR: {str(e)}")
    finally:
        try:
            cam.close()
        except Exception:
            pass


def xml_local_name(element: ET.Element) -> str:
    """Return an XML tag name without its optional namespace."""
    return element.tag.rsplit("}", 1)[-1]


def hikvision_isapi_get(ip: str, user: str, password: str, path: str,
                        timeout: float = 5) -> bytes | None:
    """Read a Hikvision ISAPI endpoint using its standard Digest authentication."""
    url = f"http://{ip}{path}"
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, user, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(password_manager),
        urllib.request.HTTPBasicAuthHandler(password_manager),
    )
    try:
        with opener.open(url, timeout=timeout) as response:
            return response.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def hikvision_isapi_post(ip: str, user: str, password: str, path: str, payload: bytes,
                         timeout: float = 15) -> bytes | None:
    """POST to Hikvision ISAPI with the device's Digest authentication."""
    url = f"http://{ip}{path}"
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, user, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(password_manager),
        urllib.request.HTTPBasicAuthHandler(password_manager),
    )
    request = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/xml; charset=utf-8"}, method="POST")
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def xml_descendant_text(element: ET.Element, name: str) -> str:
    """Read a descendant regardless of the ISAPI XML namespace variant."""
    for child in element.iter():
        if xml_local_name(child) == name:
            return (child.text or "").strip()
    return ""


def hikvision_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def hikvision_recording_token(start: datetime, end: datetime) -> str:
    payload = f"{start.isoformat()}|{end.isoformat()}".encode("utf-8")
    return "hikvision:" + base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def hikvision_search_recordings(ip: str, user: str, password: str, channel: int,
                                start: datetime, end: datetime) -> list[dict]:
    """Search archive segments through Hikvision ISAPI ContentMgmt.

    Hikvision numbers the main recording track as ``channel * 100 + 1``.  The
    search response supplies the playback URI required by its download API.
    """
    track_id = channel * 100 + 1
    search_id = str(uuid4())
    start_iso, end_iso = (value.strftime("%Y-%m-%dT%H:%M:%SZ") for value in (start, end))
    body = f'''<?xml version="1.0" encoding="UTF-8"?>
<CMSearchDescription version="1.0" xmlns="http://www.isapi.org/ver20/XMLSchema">
  <searchID>{search_id}</searchID>
  <trackIDList><trackID>{track_id}</trackID></trackIDList>
  <timeSpanList><timeSpan><startTime>{start_iso}</startTime><endTime>{end_iso}</endTime></timeSpan></timeSpanList>
  <contentTypeList><contentType>video</contentType></contentTypeList>
  <maxResults>1000</maxResults><searchResultPostion>0</searchResultPostion>
</CMSearchDescription>'''.encode("utf-8")
    payload = hikvision_isapi_post(ip, user, password, "/ISAPI/ContentMgmt/search", body, timeout=20)
    if not payload:
        raise ArchiveError("Rejestrator Hikvision nie odpowiedział na wyszukiwanie archiwum.")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ArchiveError("Hikvision zwrócił nieprawidłową odpowiedź archiwum.") from exc
    status = xml_descendant_text(root, "responseStatusStrg").upper()
    if status in {"NO MATCHES", "NO MATCH"}:
        return []
    if status and status not in {"OK", "MORE"}:
        raise ArchiveError(f"Hikvision odrzucił wyszukiwanie archiwum ({status}).")
    results = []
    for item in root.iter():
        if xml_local_name(item) != "searchMatchItem":
            continue
        start_at = hikvision_datetime(xml_descendant_text(item, "startTime"))
        end_at = hikvision_datetime(xml_descendant_text(item, "endTime"))
        playback_uri = xml_descendant_text(item, "playbackURI")
        if not start_at or not end_at or end_at <= start_at or not playback_uri:
            continue
        results.append({"start": start_at, "end": end_at, "playback_uri": playback_uri,
                        "filename": hikvision_recording_token(start_at, end_at)})
    return sorted(results, key=lambda item: item["start"])


def hikvision_search_all_recordings(ip: str, user: str, password: str, channel: int,
                                    start: datetime, end: datetime) -> list[dict]:
    """Search every segment, splitting ranges which hit the NVR's result cap."""
    segments = hikvision_search_recordings(ip, user, password, channel, start, end)
    if len(segments) >= HIKVISION_SEARCH_RESULT_LIMIT and end - start > timedelta(minutes=1):
        midpoint = start + (end - start) / 2
        # ISAPI uses whole-second timestamps; a precise midpoint avoids gaps
        # and duplicate result pages while preserving the complete interval.
        midpoint = midpoint.replace(microsecond=0)
        if midpoint > start and midpoint < end:
            segments = [
                *hikvision_search_all_recordings(ip, user, password, channel, start, midpoint),
                *hikvision_search_all_recordings(ip, user, password, channel, midpoint, end),
            ]
    unique = {item["filename"]: item for item in segments}
    return sorted(unique.values(), key=lambda item: item["start"])


def hikvision_recording_files(ip: str, user: str, password: str, channel: int, date: str) -> list[dict]:
    day_start = datetime.strptime(date, "%Y-%m-%d")
    segments = hikvision_search_recordings(ip, user, password, channel, day_start,
                                           day_start + timedelta(days=1))
    files = []
    for index, segment in enumerate(segments, start=1):
        duration = round((segment["end"] - segment["start"]).total_seconds())
        files.append({
            "filename": segment["filename"],
            "start_time": segment["start"].strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": segment["end"].strftime("%Y-%m-%d %H:%M:%S"),
            "time_only_start": segment["start"].strftime("%H:%M:%S"),
            "time_only_end": segment["end"].strftime("%H:%M:%S"),
            "duration_seconds": duration,
            "duration_formatted": str(timedelta(seconds=duration)),
            "size_kb": 0, "size_mb": 0, "index": index,
        })
    return files


def select_hikvision_recordings(ip: str, user: str, password: str, channel: int, date: str,
                                filename: str | None, start_time: str, end_time: str) -> list[dict]:
    day_start = datetime.strptime(date, "%Y-%m-%d")
    begin = datetime.fromisoformat(f"{date}T{start_time}")
    finish = datetime.fromisoformat(f"{date}T{end_time}")
    matches = hikvision_search_recordings(ip, user, password, channel, day_start,
                                           day_start + timedelta(days=1))
    if filename:
        matches = [item for item in matches if item["filename"] == filename]
        if not matches:
            raise HTTPException(status_code=404, detail="Wybrany plik nie jest już dostępny w archiwum Hikvision.")
        return matches
    # A new search for the exact requested range gives the recorder a
    # playback URI whose embedded name/size remain valid for download.
    selected = hikvision_search_recordings(ip, user, password, channel, begin, finish)
    if not selected:
        raise HTTPException(status_code=404, detail="Brak nagrań w wybranym zakresie.")
    # ISAPI download is based on a single returned playback URI. Do not merge
    # unrelated archive fragments: the UI supplies one file at a time.
    if len(selected) > 1:
        raise HTTPException(status_code=422,
                            detail="Wybrany zakres obejmuje kilka segmentów Hikvision. Pobierz je osobno z listy.")
    return selected


def hikvision_playback_uri_for_span(playback_uri: str, start: datetime, end: datetime) -> str:
    """Constrain a returned ISAPI playback URI to the requested interval."""
    parts = urllib.parse.urlsplit(playback_uri)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    replacements = {
        "starttime": start.strftime("%Y%m%dT%H%M%SZ"),
        "endtime": end.strftime("%Y%m%dT%H%M%SZ"),
    }
    updated, seen = [], set()
    for key, value in query:
        lower = key.lower()
        if lower in replacements:
            updated.append((key, replacements[lower]))
            seen.add(lower)
        else:
            updated.append((key, value))
    for key, value in replacements.items():
        if key not in seen:
            updated.append((key, value))
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urllib.parse.urlencode(updated), parts.fragment))


def hikvision_download_video(ip: str, user: str, password: str, playback_uri: str,
                             target: Path, is_cancelled=None) -> tuple[str, float, int]:
    """Download a Hikvision archive segment returned by ISAPI search.

    The ``ContentMgmt/download`` endpoint returns a media container; FFmpeg is
    subsequently used in container mode, preserving the user's output choice.
    """
    url = f"http://{ip}/ISAPI/ContentMgmt/download"
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, user, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(password_manager),
        urllib.request.HTTPBasicAuthHandler(password_manager),
    )
    payload = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
               "<downloadRequest version=\"1.0\" xmlns=\"http://www.isapi.org/ver20/XMLSchema\">"
               f"<playbackURI>{html.escape(playback_uri)}</playbackURI>"
               "</downloadRequest>").encode("utf-8")
    request = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/xml; charset=utf-8"}, method="POST")
    total = 0
    limit = int(os.environ.get("ARCHIVE_MAX_BYTES", str(4 * 1024**3)))
    try:
        with opener.open(request, timeout=30) as response, target.open("wb") as output:
            while True:
                if is_cancelled and is_cancelled():
                    raise ArchiveCancelled("Pobieranie materiału zostało anulowane przez użytkownika.")
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ArchiveError("Nagranie przekracza limit rozmiaru. Wybierz krótszy zakres.")
                output.write(chunk)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        raise ArchiveError("Nie udało się pobrać nagrania z Hikvision przez ISAPI.") from exc
    if total == 0:
        raise ArchiveError("Hikvision nie zwrócił danych nagrania.")
    # The container input does not need an exact rate for copy/remux; it is
    # retained for code paths which request re-encoding.
    return "h264", 25.0, 1


def fetch_hikvision_channels(nvr: NVR) -> list[dict] | None:
    """List IP-input channels exposed by a Hikvision recorder through ISAPI.

    ``None`` means that the endpoint is not available, allowing the legacy
    recorder protocols to be tried. An empty list is a valid ISAPI response
    from a recorder with no connected cameras.
    """
    payload = hikvision_isapi_get(nvr.ip, nvr.user, nvr.password,
                                  "/ISAPI/ContentMgmt/InputProxy/channels", timeout=2)
    if not payload:
        return None
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return None
    if xml_local_name(root) != "InputProxyChannelList":
        return None
    HIKVISION_NVR_CACHE[(nvr.ip, nvr.user)] = (time.time(), True)

    channels: list[dict] = []
    for item in root.iter():
        if xml_local_name(item) != "InputProxyChannel":
            continue
        values = {xml_local_name(child): (child.text or "").strip() for child in item}
        try:
            channel_number = int(values.get("id", ""))
        except ValueError:
            continue
        channels.append({"channel_number": channel_number,
                         "name": values.get("name") or f"Kanał {channel_number}"})
    return channels


def hikvision_device_kind(ip: str, user: str, password: str) -> str | None:
    """Use Hikvision's deviceInfo endpoint to distinguish camera from NVR."""
    if not user:
        return None
    payload = hikvision_isapi_get(ip, user, password, "/ISAPI/System/deviceInfo", timeout=2)
    if not payload:
        return None
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return None
    values = " ".join((element.text or "") for element in root.iter()).lower()
    if any(marker in values for marker in ("ipcamera", "ip camera", "network camera")):
        return "camera"
    if any(marker in values for marker in ("nvr", "network video recorder", "digital video recorder")):
        return "nvr"
    return None


def is_hikvision_nvr(ip: str, user: str, password: str) -> bool:
    """Recognise a Hikvision recorder once and cache the result briefly."""
    key = (ip, user)
    cached = HIKVISION_NVR_CACHE.get(key)
    now = time.time()
    if cached and now - cached[0] < 300:
        return cached[1]
    payload = hikvision_isapi_get(ip, user, password, "/ISAPI/ContentMgmt/InputProxy/channels")
    try:
        result = bool(payload and xml_local_name(ET.fromstring(payload)) == "InputProxyChannelList")
    except ET.ParseError:
        result = False
    HIKVISION_NVR_CACHE[key] = (now, result)
    return result


def hikvision_rtsp_path(channel: int, stream: int) -> str:
    """Return the documented Hikvision RTSP path for a recorder channel."""
    profile = 1 if stream == 1 else 2
    return f"/Streaming/Channels/{channel}0{profile}"


def nvr_rtsp_url(ip: str, user: str, password: str, channel: int, stream: int,
                 hikvision: bool) -> str:
    u_enc = urllib.parse.quote(user, safe="")
    p_enc = urllib.parse.quote(password, safe="")
    path = hikvision_rtsp_path(channel, stream) if hikvision else f"/mode=real&idc={channel}&ids={stream}"
    return f"rtsp://{u_enc}:{p_enc}@{ip}:554{path}#media=video"


NVR_CHANNEL_CONFIGS_CACHE: dict[int, tuple[float, dict[int, dict]]] = {}
NVR_CHANNEL_CONFIGS_TTL = 300  # seconds


def get_nvr_channel_camera_config(dvr_id: int, channel: int) -> dict | None:
    """Retrieve direct camera connection parameters for an NVR channel if available."""
    now = time.time()
    cached = NVR_CHANNEL_CONFIGS_CACHE.get(dvr_id)
    if cached and (now - cached[0] < NVR_CHANNEL_CONFIGS_TTL):
        return cached[1].get(channel)

    try:
        conn = sqlite3.connect("data/dvrs.db")
        try:
            row = conn.execute("SELECT ip, port, user, password FROM dvrs WHERE id = ?", (dvr_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        ip, port, user, password = row
        root = tdk_send_command(ip, user, password, "get.channelmanagement.config", timeout=3)
        configs: dict[int, dict] = {}
        if root is not None and root.findtext(".//error") in (None, "0"):
            for ch_elem in root.findall(".//channel"):
                ch_id_str = ch_elem.findtext("id")
                if not ch_id_str or not ch_id_str.isdigit():
                    continue
                ch_num = int(ch_id_str)
                cfg = ch_elem.find("config")
                if cfg is None:
                    continue
                cam_ip = (cfg.findtext("ipaddress") or "").strip()
                if not cam_ip or cam_ip in ("0.0.0.0", "127.0.0.1", ip):
                    continue
                enabled_str = (cfg.findtext("enabled") or "").strip().lower()
                configs[ch_num] = {
                    "enabled": enabled_str in ("true", "1"),
                    "ip": cam_ip,
                    "port": int(cfg.findtext("port") or 554) if (cfg.findtext("port") or "").isdigit() else 554,
                    "user": (cfg.findtext("username") or "").strip(),
                    "password": cfg.findtext("password") or "",
                    "remoteid": (cfg.findtext("remoteid") or "1").strip() or "1",
                    "protocol": (cfg.findtext("protocol") or "").strip().lower(),
                }
        NVR_CHANNEL_CONFIGS_CACHE[dvr_id] = (now, configs)
        return configs.get(channel)
    except Exception:
        return None


def ensure_go2rtc_stream(dvr_id: int, channel: int, stream: int = 2) -> str:
    try:
        local_relay.ensure()
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Przekaźnik obrazu jest uruchamiany. Spróbuj ponownie za chwilę.") from exc
    conn = sqlite3.connect("data/dvrs.db")
    c = conn.cursor()
    c.execute("SELECT ip, port, user, password FROM dvrs WHERE id = ?", (dvr_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora w bazie.")

    ip, port, user, password = row
    stream_id = stream if stream in (1, 2) else 2
    hikvision = is_hikvision_nvr(ip, user, password)
    rtsp_qv = nvr_rtsp_url(ip, user, password, channel, stream_id, hikvision)
    stream_name = f"nvr_{dvr_id}_ch_{channel}_s_{stream_id}"

    # Prefer direct camera connection if channel is mapped to a known camera on the LAN
    direct_rtsp = None
    cam_cfg = None if hikvision else get_nvr_channel_camera_config(dvr_id, channel)
    if cam_cfg and cam_cfg.get("enabled", True) and cam_cfg.get("ip"):
        cam_ip = cam_cfg["ip"]
        cam_user = urllib.parse.quote(cam_cfg.get("user") or "", safe="")
        cam_pass = urllib.parse.quote(cam_cfg.get("password") or "", safe="")
        cam_cred = f"{cam_user}:{cam_pass}@" if cam_user or cam_pass else ""
        remote_id = cam_cfg.get("remoteid") or "1"
        direct_rtsp = f"rtsp://{cam_cred}{cam_ip}:554/mode=real&idc={remote_id}&ids={stream_id}#media=video"

    primary_url = direct_rtsp if direct_rtsp else rtsp_qv
    STREAM_RTSP_SOURCES[stream_name] = primary_url.split("#")[0]

    params = [("name", stream_name)]
    if direct_rtsp:
        params.append(("src", direct_rtsp))
        if stream_id == 1:
            params.append(("src", f"ffmpeg:{direct_rtsp}#video=h264#timeout=15"))

    params.append(("src", rtsp_qv))
    # Dla strumienia głównego (HQ, ids=1), który często jest kodowany w H.265 (HEVC),
    # dodajemy drugie źródło ffmpeg->H.264, aby WebRTC działało w przeglądarkach bez wsparcia HEVC.
    if stream_id == 1:
        # This must use the camera/NVR RTSP URL, not ``stream_name`` itself.
        # Referencing the stream being constructed creates a loop, so go2rtc
        # never gets a decodable H.264 track for HEVC-only HQ sources.
        params.append(("src", f"ffmpeg:{rtsp_qv}#video=h264#timeout=15"))

    signature = hashlib.sha256(repr(params).encode("utf-8")).digest()
    with LIVE_STREAM_LOCK:
        if LIVE_STREAM_SIGNATURES.get(stream_name) == signature:
            with urllib.request.urlopen(f"{GO2RTC_API}/api/streams", timeout=5.0) as response:
                if stream_name in json.load(response):
                    return stream_name
        query = urllib.parse.urlencode(params)
        put_req = urllib.request.Request(f"{GO2RTC_API}/api/streams?{query}", method="PUT")
        urllib.request.urlopen(put_req, timeout=5.0).read()
        LIVE_STREAM_SIGNATURES[stream_name] = signature
    return stream_name


def camera_rtsp_url(ip: str, port: int, user: str, password: str, path: str) -> str:
    """Build a generic RTSP URL for an independently added camera."""
    u_enc = urllib.parse.quote(user or "", safe="")
    p_enc = urllib.parse.quote(password or "", safe="")
    credentials = f"{u_enc}:{p_enc}@" if user or password else ""
    normalized_path = path.strip() or "/"
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    return f"rtsp://{credentials}{ip}:{port}{normalized_path}#media=video"


def camera_rtsp_path_for_stream(path: str, stream: int) -> str:
    """Select the main profile for known Qualvision camera URLs.

    Qualvision exposes its two live profiles at the same endpoint: ``ids=2``
    is the substream and ``ids=1`` is the main (HQ) stream. Other vendors'
    paths are left unchanged, so a manual RTSP path stays valid.
    """
    if stream != 1:
        return path
    if re.search(r"/Streaming/Channels/\d+02(?:$|[/?])", path, re.I):
        return re.sub(r"(Streaming/Channels/\d+)02(?=$|[/?])", r"\g<1>01", path,
                      count=1, flags=re.I)
    return re.sub(r"([?&]ids=)2(?=(&|$))", r"\g<1>1", path, count=1)


def vendor_from_http_fingerprint(value: str) -> str | None:
    """Recognise common CCTV/network vendors from public HTTP metadata."""
    fingerprint = value.lower()
    for marker, vendor in (
        ("hikvision", "Hikvision"),
        ("dahua", "Dahua"),
        ("ubiquiti", "Ubiquiti"),
        ("kenik", "Kenik"),
        ("qualvision", "Qualvision"),
    ):
        if marker in fingerprint:
            return vendor
    return None


def http_device_vendor(ip: str) -> str | None:
    """Identify a device from its public HTTP banner or landing page.

    This works independently of ARP/MAC visibility, so Docker deployment does
    not change the discovery result. HTTP 401 pages are useful too because
    they commonly include the same vendor banner.
    """
    return vendor_from_http_fingerprint(http_device_fingerprint(ip))


def http_device_fingerprint(ip: str) -> str:
    """Return public HTTP metadata without requiring device credentials."""
    try:
        with urllib.request.urlopen(f"http://{ip}/", timeout=3) as response:
            return response.headers.get("Server", "") + "\n" + response.read(32768).decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:
        fingerprint = exc.headers.get("Server", "")
        try:
            return fingerprint + "\n" + exc.read(32768).decode("utf-8", "ignore")
        except OSError:
            return fingerprint
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


def hikvision_web_kind(ip: str, fingerprint: str | None = None) -> str | None:
    """Recognise Hikvision camera/NVR web UIs before credentials are entered.

    The legacy NVR interface uses the ``/doc/page/`` application (including
    ``playback.asp``); current standalone cameras use ``/doc/index.html``.
    This only supplies a type when a Hikvision-specific marker is present, so
    generic web pages are never promoted to recorders.
    """
    fingerprint = (fingerprint if fingerprint is not None else http_device_fingerprint(ip)).lower()
    if any(marker in fingerprint for marker in (
        "network video recorder", "digital video recorder", "/doc/page/", "playback.asp",
    )):
        return "nvr"
    if any(marker in fingerprint for marker in (
        "ip camera", "ipcamera", "network camera", "/doc/index.html",
    )):
        return "camera"
    return None


def camera_vendor(ip: str) -> str | None:
    """Backward-compatible vendor lookup used by camera RTSP detection."""
    return http_device_vendor(ip)


def detect_camera_rtsp_path(ip: str, current_path: str = "/") -> str:
    """Choose a known vendor RTSP path only when the generic path was used."""
    if current_path.strip() not in ("", "/"):
        return current_path
    if camera_vendor(ip) in {"Qualvision", "Kenik"}:
        # Qualvision/TDK and Kenik use the same channel-style RTSP endpoint
        # for an independent camera; channel 1 and substream are the safe default.
        return "/mode=real&idc=1&ids=2"
    if camera_vendor(ip) == "Hikvision":
        # Hikvision documents channel 1 / substream as 102 (101 is main).
        return "/Streaming/Channels/102"
    return current_path


def camera_vendor_from_rtsp_path(path: str) -> str | None:
    """Keep the saved-device label useful without probing every camera on refresh."""
    if "/streaming/channels/" in (path or "").lower():
        return "Hikvision"
    return None


def camera_connection_from_registered_nvr(ip: str) -> tuple[str, str, str] | None:
    """Read the proven per-channel credentials from a saved NVR, if present.

    Qualvision cameras are often connected to an NVR through QUVII/34567 while
    exposing their direct live feed over RTSP/554. The channel configuration is
    the authoritative source for that camera's account; it is never returned
    from an API or logged.
    """
    conn = sqlite3.connect("data/dvrs.db")
    try:
        recorders = conn.execute("SELECT ip, user, password FROM dvrs").fetchall()
    finally:
        conn.close()
    for nvr_ip, nvr_user, nvr_password in recorders:
        root = tdk_send_command(nvr_ip, nvr_user, nvr_password, "get.channelmanagement.config", timeout=5)
        if root is None or root.findtext(".//error") != "0":
            continue
        for channel in root.findall(".//channel"):
            config = channel.find("config")
            if config is None or (config.findtext("ipaddress") or "").strip() != ip:
                continue
            user = (config.findtext("username") or "").strip()
            password = config.findtext("password") or ""
            if user:
                return user, password, (config.findtext("protocol") or "").strip().lower()
    return None


def onvif_soap_request(url: str, user: str, password: str, action: str, body: str) -> ET.Element:
    """Issue an authenticated ONVIF SOAP request without logging credentials."""
    nonce = os.urandom(16)
    created = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    digest = base64.b64encode(hashlib.sha1(nonce + created.encode() + password.encode()).digest()).decode()
    security = (
        '<wsse:Security s:mustUnderstand="1"><wsse:UsernameToken>'
        f'<wsse:Username>{html.escape(user)}</wsse:Username>'
        '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
        f'{digest}</wsse:Password><wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/'
        'oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
        f'{base64.b64encode(nonce).decode()}</wsse:Nonce><wsu:Created>{created}</wsu:Created>'
        '</wsse:UsernameToken></wsse:Security>'
    )
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        f'<s:Header>{security}</s:Header><s:Body>{body}</s:Body></s:Envelope>'
    ).encode()
    request = urllib.request.Request(url, data=envelope, method="POST", headers={
        "Content-Type": "application/soap+xml; charset=utf-8",
        "SOAPAction": action,
    })
    with urllib.request.urlopen(request, timeout=8) as response:
        return ET.fromstring(response.read())


def onvif_rtsp_connection(ip: str, user: str, password: str) -> tuple[int, str] | None:
    """Resolve an independent camera's RTSP URI from its ONVIF media profile."""
    device_url = f"http://{ip}/onvif/device_service"
    capabilities = (
        '<tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        '<tds:Category>Media</tds:Category></tds:GetCapabilities>'
    )
    try:
        root = onvif_soap_request(device_url, user, password,
                                  "http://www.onvif.org/ver10/device/wsdl/GetCapabilities", capabilities)
        media_url = next((node.text for node in root.iter() if node.tag.endswith("XAddr")
                          and node.text and "media" in node.text.lower()), None)
        if not media_url:
            return None
        profiles = onvif_soap_request(
            media_url, user, password, "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
            '<trt:GetProfiles xmlns:trt="http://www.onvif.org/ver10/media/wsdl"/>')
        token = next((node.attrib.get("token") for node in profiles.iter()
                      if node.tag.endswith("Profiles") and node.attrib.get("token")), None)
        if not token:
            return None
        stream_body = (
            '<trt:GetStreamUri xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
            'xmlns:tt="http://www.onvif.org/ver10/schema"><trt:StreamSetup>'
            '<tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol>'
            '</tt:Transport></trt:StreamSetup>'
            f'<trt:ProfileToken>{html.escape(token)}</trt:ProfileToken></trt:GetStreamUri>'
        )
        stream = onvif_soap_request(media_url, user, password,
                                    "http://www.onvif.org/ver10/media/wsdl/GetStreamUri", stream_body)
        uri = next((node.text for node in stream.iter() if node.tag.endswith("Uri") and node.text), None)
        if not uri:
            return None
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme.lower() != "rtsp" or not parsed.hostname:
            return None
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return parsed.port or 554, path
    except (urllib.error.URLError, urllib.error.HTTPError, ET.ParseError, TimeoutError, OSError):
        return None


def onvif_read_device_time(ip: str, user: str, password: str) -> dict[str, str]:
    """Read an ONVIF camera clock without exposing credentials."""
    root = onvif_soap_request(
        f"http://{ip}/onvif/device_service", user, password,
        "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime",
        '<tds:GetSystemDateAndTime xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>',
    )
    allowed = {"Year", "Month", "Day", "Hour", "Minute", "Second", "DateTimeType", "TZ", "DaylightSavings"}
    return {node.tag.split("}")[-1]: (node.text or "") for node in root.iter()
            if node.tag.split("}")[-1] in allowed}


def onvif_set_device_time(ip: str, user: str, password: str, value: datetime,
                          timezone_name: str = "CET-1") -> dict[str, str]:
    """Set an ONVIF camera clock from an aware UTC datetime and verify it."""
    utc = value.astimezone(timezone.utc)
    date_time = (
        "<tt:Date><tt:Year>{}</tt:Year><tt:Month>{}</tt:Month><tt:Day>{}</tt:Day></tt:Date>"
        "<tt:Time><tt:Hour>{}</tt:Hour><tt:Minute>{}</tt:Minute><tt:Second>{}</tt:Second></tt:Time>"
    ).format(utc.year, utc.month, utc.day, utc.hour, utc.minute, utc.second)
    body = (
        '<tds:SetSystemDateAndTime xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
        'xmlns:tt="http://www.onvif.org/ver10/schema">'
        "<tds:DateTimeType>Manual</tds:DateTimeType><tds:DaylightSavings>false</tds:DaylightSavings>"
        f"<tds:TimeZone><tt:TZ>{html.escape(timezone_name)}</tt:TZ></tds:TimeZone>"
        f"<tds:UTCDateTime>{date_time}</tds:UTCDateTime></tds:SetSystemDateAndTime>"
    )
    onvif_soap_request(f"http://{ip}/onvif/device_service", user, password,
                       "http://www.onvif.org/ver10/device/wsdl/SetSystemDateAndTime", body)
    return onvif_read_device_time(ip, user, password)


def resolve_camera_connection(camera: Camera) -> None:
    """Use the NVR metadata as a fallback, never over explicit camera credentials."""
    inherited = camera_connection_from_registered_nvr(camera.ip)
    if inherited:
        inherited_user, inherited_password, protocol = inherited
        # The credentials stored in an NVR channel are not necessarily the
        # camera's RTSP credentials (and some recorders mask/rewrite them).
        # A password supplied while adding/editing a camera is authoritative.
        if not camera.password:
            camera.user, camera.password = inherited_user, inherited_password
        elif not camera.user:
            camera.user = inherited_user
        if protocol == "quvii":
            camera.rtsp_path = "/mode=real&idc=1&ids=2"
        elif camera.rtsp_path.strip() in ("", "/"):
            resolved = onvif_rtsp_connection(camera.ip, camera.user, camera.password)
            if resolved:
                camera.port, camera.rtsp_path = resolved
    if camera.rtsp_path.strip() in ("", "/"):
        camera.rtsp_path = detect_camera_rtsp_path(camera.ip, camera.rtsp_path)


def verify_camera_rtsp(camera: Camera) -> None:
    """Verify authentication and a video track without exposing credentials."""
    ffprobe = os.environ.get("FFPROBE_BIN") or shutil.which("ffprobe")
    if not ffprobe:
        return
    url = camera_rtsp_url(camera.ip, camera.port, camera.user, camera.password, camera.rtsp_path)
    try:
        result = subprocess.run(
            [ffprobe, "-v", "error", "-rtsp_transport", "tcp", "-timeout", "5000000",
             "-show_entries", "stream=codec_type", "-of", "default=noprint_wrappers=1", url],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(status_code=400, detail="Nie udało się połączyć ze strumieniem RTSP kamery.") from exc
    if result.returncode != 0 or "codec_type=video" not in result.stdout:
        detail = result.stderr.lower()
        if "401" in detail or "unauthorized" in detail or "authorization" in detail:
            message = "Kamera odrzuciła logowanie RTSP — sprawdź użytkownika i hasło urządzenia."
        elif "404" in detail or "not found" in detail or "describe" in detail:
            message = "Kamera nie zaakceptowała ścieżki RTSP. Sprawdź profil/ścieżkę producenta."
        else:
            message = "Kamera nie zwróciła strumienia wideo RTSP."
        raise HTTPException(status_code=400, detail=message)


def ensure_camera_stream(camera_id: int, stream: int = 2) -> str:
    try:
        local_relay.ensure()
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Przekaźnik obrazu jest uruchamiany. Spróbuj ponownie za chwilę.") from exc
    conn = sqlite3.connect("data/dvrs.db")
    try:
        row = conn.execute("SELECT ip, port, user, password, rtsp_path FROM cameras WHERE id = ?", (camera_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono kamery w bazie.")
    ip, port, user, password, path = row
    camera = Camera(name="", ip=ip, port=port, user=user or "", password=password or "", rtsp_path=path)
    resolve_camera_connection(camera)
    if (camera.port, camera.user, camera.password, camera.rtsp_path) != (port, user, password, path):
        conn = sqlite3.connect("data/dvrs.db")
        try:
            conn.execute("UPDATE cameras SET port = ?, user = ?, password = ?, rtsp_path = ? WHERE id = ?",
                         (camera.port, camera.user, camera.password, camera.rtsp_path, camera_id))
            conn.commit()
        finally:
            conn.close()
    stream_id = stream if stream in (1, 2) else 2
    profile_path = camera_rtsp_path_for_stream(camera.rtsp_path, stream_id)
    rtsp = camera_rtsp_url(camera.ip, camera.port, camera.user, camera.password, profile_path)
    name = f"camera_{camera_id}_s_{stream_id}"
    STREAM_RTSP_SOURCES[name] = rtsp.split("#")[0]
    params = [("name", name), ("src", rtsp)]
    if stream_id == 1:
        params.append(("src", f"ffmpeg:{rtsp}#video=h264#timeout=15"))
    signature = hashlib.sha256(repr(params).encode("utf-8")).digest()
    with LIVE_STREAM_LOCK:
        if LIVE_STREAM_SIGNATURES.get(name) == signature:
            try:
                with urllib.request.urlopen(f"{GO2RTC_API}/api/streams", timeout=5.0) as response:
                    if name in json.load(response):
                        return name
            except Exception:
                pass
        query = urllib.parse.urlencode(params)
        request = urllib.request.Request(f"{GO2RTC_API}/api/streams?{query}", method="PUT")
        try:
            urllib.request.urlopen(request, timeout=12).read()
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Nie udało się zarejestrować strumienia kamery: {exc}") from exc
        LIVE_STREAM_SIGNATURES[name] = signature
    return name


def classify_host(ip: str, ports: set[int], ws_types: str = "") -> str:
    lower_types = ws_types.lower()
    if "networkvideorecorder" in lower_types or "network_video_recorder" in lower_types:
        return "nvr"
    if "networkvideotransmitter" in lower_types or "camera" in lower_types:
        return "camera"
    # Passive network fingerprinting. Cameras commonly expose RTSP/554 plus
    # their media service on 49152 (and often 5801); recorders in this estate
    # typically expose HTTP(S) + RTSP but not 49152. Authenticated channel
    # inventory below remains the final authority for an ambiguous host.
    if 49152 in ports:
        return "camera"
    # Native ports alone are not definitive: XM/Kenik cameras use 34567 and
    # Dahua cameras commonly expose 37777 too. A media service on 49152 is a
    # strong camera marker; otherwise the recorder pattern is RTSP + its
    # legacy media port without that camera service.
    if 554 in ports and 5801 in ports and 34567 in ports:
        return "nvr"
    if 554 in ports and 443 in ports:
        return "nvr"
    if 554 in ports:
        return "camera"
    return "camera"


def parse_scan_targets(value: str) -> list[str]:
    """Accept IPs, CIDR networks and inclusive IPv4 ranges, with a safe cap."""
    result: list[str] = []
    for raw in re.split(r"[,;\s]+", value.strip()):
        if not raw:
            continue
        if "-" in raw:
            first, last = (ipaddress.ip_address(x.strip()) for x in raw.split("-", 1))
            if first.version != 4 or last.version != 4 or int(last) < int(first):
                raise ValueError(f"Nieprawidłowy zakres IP: {raw}")
            hosts = [str(ipaddress.ip_address(n)) for n in range(int(first), int(last) + 1)]
        else:
            network = ipaddress.ip_network(raw, strict=False)
            hosts = [str(host) for host in network.hosts()] if network.num_addresses > 1 else [str(network.network_address)]
        result.extend(hosts)
        if len(result) > 1024:
            raise ValueError("Zakres wykrywania jest zbyt duży (maksymalnie 1024 adresy).")
    return list(dict.fromkeys(result))


def configured_discovery_networks() -> list[ipaddress.IPv4Network]:
    """Read administrator-defined routed discovery scopes from the environment.

    A Docker bridge cannot see the host's routing table. These CIDRs make
    additional LAN/VLAN routes explicit without requiring an address range in
    every scan request (for example ``192.168.49.0/24,10.20.0.0/24``).
    """
    networks: list[ipaddress.IPv4Network] = []
    for raw in re.split(r"[,;\s]+", os.environ.get("DISCOVERY_NETWORKS", "").strip()):
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
            if network.version == 4 and network.is_private:
                networks.append(network)
        except ValueError:
            logging.warning("Pomijam nieprawidłową podsieć DISCOVERY_NETWORKS: %s", raw)
    return networks


def targets_from_networks(networks: list[ipaddress.IPv4Network], limit: int = 1024) -> list[str]:
    targets: list[str] = []
    for network in networks:
        for host in network.hosts():
            targets.append(str(host))
            if len(targets) >= limit:
                return list(dict.fromkeys(targets))
    return list(dict.fromkeys(targets))


def routed_ipv4_networks() -> list[ipaddress.IPv4Network]:
    """Private, directly routed IPv4 networks visible to this process."""
    networks = configured_discovery_networks()
    try:
        with open("/proc/net/route", encoding="ascii") as routes:
            next(routes, None)
            for line in routes:
                fields = line.split()
                if len(fields) < 8 or fields[1] == "00000000":
                    continue
                if fields[0].startswith(("docker", "br-", "veth")):
                    continue
                destination = socket.inet_ntoa(struct.pack("<L", int(fields[1], 16)))
                mask = socket.inet_ntoa(struct.pack("<L", int(fields[7], 16)))
                network = ipaddress.ip_network(f"{destination}/{mask}", strict=False)
                if network.version == 4 and network.is_private:
                    networks.append(network)
    except OSError:
        pass
    return list(dict.fromkeys(networks))


def routed_ipv4_targets(limit: int = 1024) -> list[str]:
    """Return a bounded host sample from directly reachable IPv4 routes.

    Explicit user ranges remain authoritative. This is only the no-input
    fallback after ONVIF multicast and intentionally excludes the default
    route, which is not a network discovery scope.
    """
    return targets_from_networks(routed_ipv4_networks(), limit)


def known_device_network_targets(limit: int = 1024) -> list[str]:
    """Expand private /24 networks containing saved devices.

    The web app may run in Docker, where ``/proc/net/route`` only exposes the
    Docker bridge. Saved recorder/camera addresses are therefore the most
    reliable discovery scope for the user's actual LAN.
    """
    conn = sqlite3.connect("data/dvrs.db")
    try:
        ips = [row[0] for row in conn.execute("SELECT ip FROM dvrs UNION SELECT ip FROM cameras")]
    finally:
        conn.close()
    networks = configured_discovery_networks()
    for value in ips:
        try:
            address = ipaddress.ip_address(value)
            if address.version != 4 or not address.is_private:
                continue
            network = ipaddress.ip_network(f"{address}/24", strict=False)
        except ValueError:
            continue
        networks.append(network)
    return targets_from_networks(list(dict.fromkeys(networks)), limit)


def known_device_networks() -> list[ipaddress.IPv4Network]:
    """Return /24s inferred from saved devices, without expanding them yet."""
    conn = sqlite3.connect("data/dvrs.db", timeout=0.2)
    try:
        ips = [row[0] for row in conn.execute("SELECT ip FROM dvrs UNION SELECT ip FROM cameras")]
    finally:
        conn.close()
    networks = []
    for value in ips:
        try:
            address = ipaddress.ip_address(value)
            if address.version == 4 and address.is_private:
                networks.append(ipaddress.ip_network(f"{address}/24", strict=False))
        except ValueError:
            continue
    return list(dict.fromkeys(networks))


def saved_discovery_networks() -> list[ipaddress.IPv4Network]:
    conn = sqlite3.connect("data/dvrs.db", timeout=0.2)
    try:
        rows = conn.execute("SELECT cidr FROM discovery_networks").fetchall()
    finally:
        conn.close()
    result = []
    for (value,) in rows:
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.version == 4 and network.is_private:
                result.append(network)
        except ValueError:
            continue
    return result


def remember_discovery_network(ip: str) -> None:
    try:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return
    now = time_module.time()
    conn = sqlite3.connect("data/dvrs.db")
    try:
        conn.execute("""INSERT INTO discovery_networks (cidr, first_seen_at, last_seen_at, devices_seen)
                        VALUES (?, ?, ?, 1)
                        ON CONFLICT(cidr) DO UPDATE SET last_seen_at = excluded.last_seen_at,
                            devices_seen = discovery_networks.devices_seen + 1""",
                     (str(network), now, now))
        conn.commit()
    finally:
        conn.close()


def scan_host(ip: str, user: str = "", password: str = "", known_nvr: bool = False) -> dict | None:
    open_ports: set[int] = set()
    # Include native management services, not only RTSP. Some recorders have
    # RTSP disabled, yet expose Hikvision/Uniview 8000, Dahua 37777/37778 or
    # XM/Kenik 34567.
    ports_to_test = (80, 443, 554, 5800, 5801, 8000, 8080, 8081, 8443, 8899, 9000,
                     34567, 37777, 37778, 49152)
    for port in ports_to_test:
        try:
            with socket.create_connection((ip, port), timeout=0.2):
                open_ports.add(port)
        except OSError:
            pass
    if not open_ports:
        return None
    # HTTP/HTTPS alone identifies far too many unrelated devices (routers,
    # printers, switches). Keep discovery results limited to hosts exposing a
    # CCTV/ONVIF/native-video service; HTTP is used only as a vendor hint.
    cctv_ports = {554, 8000, 8899, 34567, 37777, 37778, 49152}
    if not open_ports.intersection(cctv_ports):
        return None
    http_fingerprint = http_device_fingerprint(ip) if 80 in open_ports else ""
    vendor = vendor_from_http_fingerprint(http_fingerprint)
    kind = classify_host(ip, open_ports)
    channels_count: int | None = None
    detected_hikvision_kind = hikvision_web_kind(ip, http_fingerprint) if http_fingerprint else None
    if detected_hikvision_kind:
        vendor = "Hikvision"
        kind = detected_hikvision_kind
    # The XM NETIP service (34567) is shared by cameras and recorders, so it
    # is not a type marker. A successful authenticated channel inventory is.
    if known_nvr:
        kind = "nvr"
    elif user and 34567 in open_ports:
        try:
            channels_count = len(fetch_nvr_channels(NVR(name="", ip=ip, port=34567, user=user, password=password)))
            kind = "nvr" if channels_count > 1 else "camera"
        except (HTTPException, OSError):
            pass
    if user and 8000 in open_ports:
        # Hikvision uses port 8000 on both cameras and NVRs. Its recorder
        # endpoint returns the actual channel inventory, unlike port guessing.
        hikvision_channels = fetch_hikvision_channels(
            NVR(name="", ip=ip, port=8000, user=user, password=password))
        if hikvision_channels is not None:
            vendor = "Hikvision"
            kind = "nvr"
            channels_count = len(hikvision_channels)
    if vendor == "Hikvision" and kind != "nvr":
        # Port 8000 is used by both Hikvision cameras and recorders. ISAPI is
        # authoritative when credentials were supplied; otherwise prefer the
        # safer camera classification instead of adding an IP camera as NVR.
        kind = hikvision_device_kind(ip, user, password) or detected_hikvision_kind or "camera"
    rtsp_path = ("/mode=real&idc=1&ids=2" if vendor in {"Qualvision", "Kenik"}
                 else "/Streaming/Channels/102" if vendor == "Hikvision" else "/")
    name_prefix = f"{('Rejestrator' if kind == 'nvr' else 'Kamera')} {vendor}" if vendor else ('Rejestrator' if kind == 'nvr' else 'Kamera')
    return {"ip": ip, "type": kind, "name": f"{name_prefix} {ip}",
            "port": (34567 if kind == "nvr" and 34567 in open_ports
                     else 8000 if kind == "nvr" and 8000 in open_ports
                     else 554 if 554 in open_ports else min(open_ports)),
            "ports": sorted(open_ports), "channels_count": channels_count, "vendor": vendor,
            "rtsp_path": rtsp_path, "method": "Skan IP"}


def ws_discover() -> list[dict]:
    """Best-effort ONVIF WS-Discovery (plug-and-play multicast)."""
    message_id = f"uuid:{secrets.token_hex(16)}"
    probe = f'''<?xml version="1.0" encoding="UTF-8"?><e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://docs.oasis-open.org/ws-dd/ns/discovery"><e:Header><w:MessageID>{message_id}</w:MessageID><w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action>http://docs.oasis-open.org/ws-dd/ns/discovery/Probe</w:Action></e:Header><e:Body><d:Probe/></e:Body></e:Envelope>'''.encode()
    found: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(1.2)
        sock.sendto(probe, ("239.255.255.250", 3702))
        while True:
            try:
                payload, _ = sock.recvfrom(65535)
            except socket.timeout:
                break
            text = payload.decode("utf-8", errors="ignore")
            locations = re.findall(r"<[^>]*:?(?:XAddrs|Scopes)[^>]*>(.*?)</", text, re.I | re.S)
            urls = re.findall(r"https?://([^/:\s]+)", " ".join(locations))
            types = " ".join(re.findall(r"<[^>]*:Types[^>]*>(.*?)</", text, re.I | re.S))
            for ip in urls:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                kind = classify_host(ip, set(), types)
                found[ip] = {"ip": ip, "type": kind, "name": f"{'Rejestrator' if kind == 'nvr' else 'Kamera'} {ip}", "port": 554 if kind == "camera" else 34567, "ports": [], "method": "ONVIF Plug & Play"}
    except OSError:
        pass
    finally:
        try: sock.close()
        except UnboundLocalError: pass
    return list(found.values())


def ssdp_discover() -> list[dict]:
    """Discover UPnP devices through the actual SSDP M-SEARCH protocol."""
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    found: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(2.5)
        sock.sendto(message, ("239.255.255.250", 1900))
        while True:
            try:
                payload, sender = sock.recvfrom(65535)
            except socket.timeout:
                break
            text = payload.decode("utf-8", errors="ignore")
            headers = dict(line.split(":", 1) for line in text.splitlines()[1:] if ":" in line)
            location = next((value.strip() for key, value in headers.items() if key.lower() == "location"), "")
            host = urllib.parse.urlsplit(location).hostname or sender[0]
            try:
                ipaddress.ip_address(host)
            except ValueError:
                continue
            found[host] = {"ip": host, "method": "UPnP/SSDP"}
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except UnboundLocalError:
            pass
    return list(found.values())


def full_local_scan_worker(networks: list[ipaddress.IPv4Network], user: str, password: str) -> None:
    found: dict[str, dict] = {}
    try:
        for network in networks:
            with DISCOVERY_JOB_LOCK:
                if DISCOVERY_CANCEL.is_set():
                    DISCOVERY_JOB["cancelled"] = True
                    break
                DISCOVERY_JOB["network"] = str(network)
                DISCOVERY_JOB["network_index"] = networks.index(network) + 1
            hosts = (str(host) for host in network.hosts())
            while not DISCOVERY_CANCEL.is_set():
                batch = []
                try:
                    for _ in range(96):
                        batch.append(next(hosts))
                except StopIteration:
                    pass
                if not batch:
                    break
                with ThreadPoolExecutor(max_workers=48) as pool:
                    futures = [pool.submit(scan_host, ip, user, password) for ip in batch]
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            found[result["ip"]] = result
                            remember_discovery_network(result["ip"])
                            with DISCOVERY_JOB_LOCK:
                                DISCOVERY_JOB["devices"] = sorted(found.values(), key=lambda item: item["ip"])
                with DISCOVERY_JOB_LOCK:
                    DISCOVERY_JOB["completed"] += len(batch)
        with DISCOVERY_JOB_LOCK:
            DISCOVERY_JOB["devices"] = sorted(found.values(), key=lambda item: item["ip"])
    except Exception as exc:
        logging.exception("Pełne skanowanie lokalnych sieci nie powiodło się")
        with DISCOVERY_JOB_LOCK:
            DISCOVERY_JOB["error"] = "Skanowanie zostało przerwane przez błąd."
    finally:
        with DISCOVERY_JOB_LOCK:
            DISCOVERY_JOB["running"] = False


def full_local_scan_networks() -> list[ipaddress.IPv4Network]:
    """Use configured, known and previously confirmed reachable LANs."""
    networks = [*configured_discovery_networks(), *known_device_networks(),
                *saved_discovery_networks()]
    return list(dict.fromkeys(network for network in networks if network.num_addresses > 2))


def discovery_network_candidates() -> list[dict]:
    """Build a compact, editable chooser covering all private IPv4 ranges.

    This endpoint feeds a modal dialog, so an unrelated writer holding the
    SQLite file must never leave its UI waiting. Saved network hints are
    optional; the three standard private ranges are always available.
    """
    configured = {str(network) for network in configured_discovery_networks()}
    try:
        known_networks = [*known_device_networks(), *saved_discovery_networks()]
    except sqlite3.Error:
        known_networks = []
    known = {str(network) for network in known_networks}
    try:
        conn = sqlite3.connect("data/dvrs.db", timeout=0.2)
        try:
            preferences = {cidr: (bool(enabled), bool(hidden), bool(custom)) for cidr, enabled, hidden, custom in
                           conn.execute("SELECT cidr, enabled, hidden, custom FROM discovery_scan_networks").fetchall()}
        finally:
            conn.close()
    except sqlite3.Error:
        preferences = {}
    base = [ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    candidates = {str(network): network for network in [*base, *configured_discovery_networks(),
                  *known_networks]}
    for cidr, (_, _, custom) in preferences.items():
        if not custom:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.version == 4 and network.is_private:
                candidates[cidr] = network
        except ValueError:
            continue
    return [{"cidr": cidr, "enabled": preferences.get(cidr, (cidr in configured or cidr in known, False, False))[0],
             "known": cidr in configured or cidr in known}
            for cidr, network in sorted(candidates.items(), key=lambda item: (int(item[1].network_address), item[1].prefixlen))
            if not preferences.get(cidr, (False, False, False))[1]]


def save_discovery_network_preferences(networks: list[str]) -> list[ipaddress.IPv4Network]:
    selected: list[ipaddress.IPv4Network] = []
    for value in networks:
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4 or not network.is_private:
                raise ValueError
            selected.append(network)
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Nieprawidłowa podsieć skanowania: {value}")
    if len(selected) > 256:
        raise HTTPException(status_code=422, detail="Można wybrać maksymalnie 256 podsieci.")
    known_candidates = [item["cidr"] for item in discovery_network_candidates()]
    conn = sqlite3.connect("data/dvrs.db")
    try:
        conn.executemany("INSERT INTO discovery_scan_networks (cidr, enabled, hidden) VALUES (?, 0, 0) ON CONFLICT(cidr) DO UPDATE SET enabled = 0, hidden = 0",
                         [(cidr,) for cidr in known_candidates])
        conn.executemany("INSERT INTO discovery_scan_networks (cidr, enabled, hidden) VALUES (?, 1, 0) ON CONFLICT(cidr) DO UPDATE SET enabled = 1, hidden = 0",
                         [(str(network),) for network in selected])
        conn.commit()
    finally:
        conn.close()
    return list(dict.fromkeys(selected))


def get_rtsp_url_for_stream(stream_name: str) -> str | None:
    """Resolve the direct RTSP source URL for a given stream name."""
    url = STREAM_RTSP_SOURCES.get(stream_name)
    if url:
        return url.split("#")[0]

    try:
        m_cam = re.match(r"^camera_(\d+)_s_(\d+)$", stream_name)
        if m_cam:
            cam_id, stream_id = int(m_cam.group(1)), int(m_cam.group(2))
            conn = sqlite3.connect("data/dvrs.db")
            try:
                row = conn.execute("SELECT ip, port, user, password, rtsp_path FROM cameras WHERE id = ?", (cam_id,)).fetchone()
            finally:
                conn.close()
            if row:
                ip, port, user, password, path = row
                prof_path = camera_rtsp_path_for_stream(path, stream_id)
                clean_url = camera_rtsp_url(ip, port, user, password, prof_path).split("#")[0]
                STREAM_RTSP_SOURCES[stream_name] = clean_url
                return clean_url

        m_nvr = re.match(r"^nvr_(\d+)_ch_(\d+)_s_(\d+)$", stream_name)
        if m_nvr:
            dvr_id, ch, stream_id = int(m_nvr.group(1)), int(m_nvr.group(2)), int(m_nvr.group(3))
            cam_cfg = get_nvr_channel_camera_config(dvr_id, ch)
            if cam_cfg and cam_cfg.get("enabled", True) and cam_cfg.get("ip"):
                cam_ip = cam_cfg["ip"]
                cam_user = urllib.parse.quote(cam_cfg.get("user") or "", safe="")
                cam_pass = urllib.parse.quote(cam_cfg.get("password") or "", safe="")
                cam_cred = f"{cam_user}:{cam_pass}@" if cam_user or cam_pass else ""
                remote_id = cam_cfg.get("remoteid") or "1"
                clean_url = f"rtsp://{cam_cred}{cam_ip}:554/mode=real&idc={remote_id}&ids={stream_id}"
                STREAM_RTSP_SOURCES[stream_name] = clean_url
                return clean_url

            conn = sqlite3.connect("data/dvrs.db")
            try:
                row = conn.execute("SELECT ip, port, user, password FROM dvrs WHERE id = ?", (dvr_id,)).fetchone()
            finally:
                conn.close()
            if row:
                ip, port, user, password = row
                clean_url = nvr_rtsp_url(ip, user, password, ch, stream_id,
                                         is_hikvision_nvr(ip, user, password)).split("#")[0]
                STREAM_RTSP_SOURCES[stream_name] = clean_url
                return clean_url
    except Exception:
        pass
    return None


def stream_needs_color_normalization(stream_name: str) -> bool:
    """Detect broken H.264/HEVC VUI colour metadata (e.g. GBR matrix on YUV streams) once per active stream."""
    cached = STREAM_COLOR_NORMALIZATION.get(stream_name)
    if cached is not None:
        return cached

    ffprobe = os.environ.get("FFPROBE_BIN") or shutil.which("ffprobe")
    if not ffprobe:
        return False

    candidate_sources = []
    direct = get_rtsp_url_for_stream(stream_name)
    if direct:
        candidate_sources.append(direct)
    candidate_sources.append(f"{GO2RTC_RTSP}/{urllib.parse.quote(stream_name)}")

    normalize = False
    probed_successfully = False

    for source in candidate_sources:
        try:
            probe = subprocess.run(
                [
                    ffprobe, "-v", "error", "-rtsp_transport", "tcp", "-timeout", "5000000",
                    "-read_intervals", "%+#1",
                    "-show_entries", "stream=color_space,color_transfer,color_primaries:frame=color_space,color_transfer,color_primaries",
                    "-of", "default=noprint_wrappers=1", source,
                ],
                capture_output=True, text=True, timeout=8, check=False,
            )
            lines = [line.strip() for line in probe.stdout.splitlines() if "=" in line]
            if lines:
                probed_successfully = True
                color_spaces = {v.lower().strip() for k, v in (line.split("=", 1) for line in lines) if k == "color_space"}
                color_transfers = {v.lower().strip() for k, v in (line.split("=", 1) for line in lines) if k == "color_transfer"}
                color_primaries = {v.lower().strip() for k, v in (line.split("=", 1) for line in lines) if k == "color_primaries"}

                normalize = bool(
                    {"gbr", "reserved"}.intersection(color_spaces)
                    or any("gbr" in cs for cs in color_spaces)
                    or {"reserved", "reserved0"}.intersection(color_transfers)
                    or {"reserved", "reserved0"}.intersection(color_primaries)
                )
                break
        except (OSError, subprocess.TimeoutExpired):
            continue

    if probed_successfully:
        STREAM_COLOR_NORMALIZATION[stream_name] = normalize
    return normalize


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/login")
async def login_page(request: Request, error: str | None = None):
    if not auth_settings.enabled:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"providers": auth_settings.providers, "error": error},
    )


@app.get("/login/{provider}")
async def start_login(request: Request, provider: str):
    if not auth_settings.enabled or provider not in auth_settings.providers:
        raise HTTPException(status_code=404, detail="Wybrany dostawca logowania nie jest skonfigurowany.")
    client = oauth.create_client(provider)
    return await client.authorize_redirect(request, callback_url(request, provider))


@app.get("/auth/{provider}/callback", name="auth_callback")
async def auth_callback(request: Request, provider: str):
    if not auth_settings.enabled or provider not in auth_settings.providers:
        raise HTTPException(status_code=404, detail="Wybrany dostawca logowania nie jest skonfigurowany.")
    try:
        client = oauth.create_client(provider)
        token = await client.authorize_access_token(request)
        userinfo = token.get("userinfo") or await client.userinfo(token=token)
        email = userinfo.get("email") or userinfo.get("preferred_username")
        subject = userinfo.get("sub")
        if not email or not subject:
            raise ValueError("Dostawca nie przekazał wymaganych danych konta.")
    except Exception:
        return RedirectResponse(url="/login?error=Nie+udało+się+potwierdzić+logowania.", status_code=303)
    request.session.clear()
    request.session["user"] = {
        "provider": provider,
        "subject": str(subject),
        "email": str(email),
        "name": str(userinfo.get("name") or email),
    }
    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login" if auth_settings.enabled else "/", status_code=303)


@app.get("/api/session")
async def get_session(request: Request):
    """Return only the currently signed-in user's display information."""
    return {"user": request.session.get("user")}


@app.get("/api/dvrs")
def get_dvrs():
    conn = sqlite3.connect('data/dvrs.db')
    c = conn.cursor()
    c.execute("SELECT id, name, ip, port FROM dvrs")
    dvr_rows = c.fetchall()

    result = []
    for r in dvr_rows:
        dvr_id = r[0]
        c.execute(
            "SELECT channel_number, name FROM channels WHERE dvr_id = ? ORDER BY channel_number ASC",
            (dvr_id,)
        )
        channels = [{"channel_number": ch[0], "name": ch[1]} for ch in c.fetchall()]
        result.append({
            "id": dvr_id,
            "name": r[1],
            "ip": r[2],
            "port": r[3],
            "channels": channels
        })

    conn.close()
    return result


@app.get("/api/dvrs/{dvr_id}/channels")
def get_dvr_channels(dvr_id: int):
    conn = sqlite3.connect('data/dvrs.db')
    c = conn.cursor()
    c.execute(
        "SELECT channel_number, name FROM channels WHERE dvr_id = ? ORDER BY channel_number ASC",
        (dvr_id,)
    )
    rows = c.fetchall()
    conn.close()
    return [{"channel_number": r[0], "name": r[1]} for r in rows]


@app.get("/api/dvrs/status")
def get_dvr_channel_status():
    """Return the current NVR-reported state; it is never persisted."""
    conn = sqlite3.connect("data/dvrs.db")
    try:
        rows = conn.execute("SELECT id, ip, port, user, password FROM dvrs").fetchall()
    finally:
        conn.close()

    result: dict[str, dict[str, bool]] = {}
    for dvr_id, ip, port, user, password in rows:
        if port == 8000 and is_hikvision_nvr(ip, user, password):
            # Hikvision does not understand the legacy TDK status command.
            # Skipping it prevents one slow timeout for every UI refresh.
            continue
        statuses = fetch_tdkcgi_channel_status(
            NVR(name="", ip=ip, port=port, user=user, password=password)
        )
        if statuses is not None:
            result[str(dvr_id)] = {str(channel): online for channel, online in statuses.items()}
    return {"channels": result}


@app.post("/api/dvrs/test")
def test_dvr_connection(nvr: NVR):
    channels = fetch_nvr_channels(nvr)
    return {"status": "ok", "channels_count": len(channels), "channels": channels}


@app.post("/api/dvrs")
def add_dvr(nvr: NVR):
    channels = fetch_nvr_channels(nvr)
    vendor = nvr.vendor or ("Hikvision" if is_hikvision_nvr(nvr.ip, nvr.user, nvr.password) else None)

    conn = sqlite3.connect('data/dvrs.db')
    c = conn.cursor()
    c.execute(
        "INSERT INTO dvrs (name, ip, port, user, password, vendor) VALUES (?, ?, ?, ?, ?, ?)",
        (nvr.name, nvr.ip, nvr.port, nvr.user, nvr.password, vendor)
    )
    dvr_id = c.lastrowid

    for ch in channels:
        c.execute(
            "INSERT INTO channels (dvr_id, channel_number, name) VALUES (?, ?, ?)",
            (dvr_id, ch["channel_number"], ch["name"])
        )

    conn.commit()
    conn.close()
    return {"status": "success", "dvr_id": dvr_id, "channels_count": len(channels)}


@app.get("/api/devices/{device_type}/{device_id}/config")
def get_device_config(device_type: Literal["nvr", "camera"], device_id: int):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        if device_type == "nvr":
            row = conn.execute("SELECT name, ip, port, user FROM dvrs WHERE id = ?", (device_id,)).fetchone()
            fields = ["name", "ip", "port", "user"]
        else:
            row = conn.execute("SELECT name, ip, port, user, rtsp_path FROM cameras WHERE id = ?", (device_id,)).fetchone()
            fields = ["name", "ip", "port", "user", "rtsp_path"]
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia.")
    return {"id": device_id, "type": device_type, **dict(zip(fields, row))}


def device_time(device_type: Literal["nvr", "camera"], device_id: int) -> dict:
    conn = sqlite3.connect("data/dvrs.db")
    try:
        table = "cameras" if device_type == "camera" else "dvrs"
        row = conn.execute(f"SELECT ip, port, user, password FROM {table} WHERE id = ?", (device_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono urządzenia.")
    ip, port, user, password = row
    try:
        if device_type == "camera":
            return {"source": "ONVIF", "time": onvif_read_device_time(ip, user, password)}
        from tools.inspect_recorder_config import read_time
        return {"source": "natywny protokół rejestratora", "time": read_time(ip, port, user, password)}
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Nie udało się odczytać czasu urządzenia.") from exc


@app.get("/api/devices/{device_type}/{device_id}/time")
def get_device_time(device_type: Literal["nvr", "camera"], device_id: int):
    return device_time(device_type, device_id)


@app.post("/api/devices/{device_type}/{device_id}/time/sync")
def sync_device_time(device_type: Literal["nvr", "camera"], device_id: int):
    if device_type != "camera":
        raise HTTPException(status_code=501, detail="Zapis czasu rejestratora wymaga jeszcze potwierdzenia natywnej komendy urządzenia.")
    conn = sqlite3.connect("data/dvrs.db")
    try:
        row = conn.execute("SELECT ip, user, password FROM cameras WHERE id = ?", (device_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono kamery.")
    ip, user, password = row
    try:
        return {"status": "ok", "source": "czas aplikacji", "time": onvif_set_device_time(ip, user, password, datetime.now(timezone.utc))}
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Kamera nie przyjęła ustawienia czasu ONVIF.") from exc


def load_time_sync_settings() -> dict:
    conn = sqlite3.connect("data/dvrs.db")
    try:
        row = conn.execute("""SELECT source, ntp_server, manual_time, interval_minutes,
                              target_keys, enabled, last_run_at
                           FROM time_sync_settings WHERE id = 1""").fetchone()
    finally:
        conn.close()
    if not row:
        return {"source": "container", "ntp_server": "pool.ntp.org", "manual_time": "",
                "interval_minutes": 10, "target_keys": [], "enabled": True, "last_run_at": 0}
    try:
        targets = json.loads(row[4])
    except (TypeError, json.JSONDecodeError):
        targets = []
    return {"source": row[0], "ntp_server": row[1], "manual_time": row[2],
            "interval_minutes": row[3], "target_keys": targets if isinstance(targets, list) else [],
            "enabled": bool(row[5]), "last_run_at": row[6]}


def resolve_time_source(settings: dict) -> datetime:
    source = settings["source"]
    if source == "container":
        return datetime.now(timezone.utc)
    if source == "manual":
        value = settings["manual_time"].strip()
        if not value:
            raise ValueError("Podaj ręcznie ustawianą datę i godzinę.")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            # The settings form expresses manual time in the operator's local time.
            parsed = parsed.astimezone()
        return parsed.astimezone(timezone.utc)
    if source == "ntp":
        server = settings["ntp_server"].strip()
        if not server:
            raise ValueError("Podaj adres serwera NTP.")
        packet = b"\x1b" + 47 * b"\0"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(4)
            client.sendto(packet, (server, 123))
            response, _ = client.recvfrom(48)
        if len(response) < 48:
            raise ValueError("Serwer NTP zwrócił niepełną odpowiedź.")
        seconds = struct.unpack("!Q", response[40:48])[0] / 2 ** 32 - 2208988800
        return datetime.fromtimestamp(seconds, timezone.utc)
    raise ValueError("Nieznane źródło czasu.")


def selected_time_sync_devices(target_keys: list[str]) -> list[tuple[str, int, str, str, int, str, str]]:
    conn = sqlite3.connect("data/dvrs.db")
    try:
        devices = [("nvr", *row) for row in conn.execute("SELECT id, name, ip, port, user, password FROM dvrs").fetchall()]
        devices += [("camera", *row) for row in conn.execute("SELECT id, name, ip, port, user, password FROM cameras").fetchall()]
    finally:
        conn.close()
    requested = set(target_keys)
    return [device for device in devices if not requested or f"{device[0]}:{device[1]}" in requested]


def run_time_sync(settings: dict | None = None) -> dict:
    settings = settings or load_time_sync_settings()
    source_time = resolve_time_source(settings)
    devices = selected_time_sync_devices(settings["target_keys"])
    results = []
    for index, (device_type, device_id, name, ip, _port, user, password) in enumerate(devices):
        if device_type != "camera":
            results.append({"key": f"{device_type}:{device_id}", "name": name, "ip": ip,
                            "status": "unsupported", "detail": "Brak potwierdzonej natywnej komendy zapisu czasu rejestratora."})
        else:
            try:
                set_time = onvif_set_device_time(ip, user, password, source_time)
                results.append({"key": f"camera:{device_id}", "name": name, "ip": ip,
                                "status": "ok", "time": set_time})
            except Exception as exc:
                logging.warning("Time sync failed for camera %s (%s): %s", name, ip, exc)
                results.append({"key": f"camera:{device_id}", "name": name, "ip": ip,
                                "status": "error", "detail": "Kamera nie przyjęła ustawienia czasu ONVIF."})
        if index < len(devices) - 1:
            # Baseline one second, with ±1 second jitter, prevents simultaneous bursts.
            time_module.sleep(random.uniform(0, 2))
    now = time_module.time()
    conn = sqlite3.connect("data/dvrs.db")
    try:
        conn.execute("UPDATE time_sync_settings SET last_run_at = ? WHERE id = 1", (now,))
        conn.commit()
    finally:
        conn.close()
    return {"source": settings["source"], "time": source_time.isoformat(), "results": results}


async def time_sync_scheduler():
    while True:
        try:
            settings = load_time_sync_settings()
            due = time_module.time() - float(settings["last_run_at"]) >= max(1, settings["interval_minutes"]) * 60
            if settings["enabled"] and due:
                await asyncio.to_thread(run_time_sync, settings)
        except asyncio.CancelledError:
            raise
        except Exception:
            logging.exception("Automatyczna synchronizacja czasu nie powiodła się")
        await asyncio.sleep(15)


@app.get("/api/time-sync/settings")
def get_time_sync_settings():
    return load_time_sync_settings()


@app.put("/api/time-sync/settings")
def update_time_sync_settings(update: TimeSyncSettings):
    if not 1 <= update.interval_minutes <= 1440:
        raise HTTPException(status_code=422, detail="Interwał musi mieścić się w zakresie 1–1440 minut.")
    settings = update.model_dump()
    try:
        # Validate eagerly, so a bad manual date or NTP hostname is reported on save.
        if settings["source"] == "manual":
            resolve_time_source(settings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    conn = sqlite3.connect("data/dvrs.db")
    try:
        conn.execute("""UPDATE time_sync_settings
                        SET source = ?, ntp_server = ?, manual_time = ?, interval_minutes = ?,
                            target_keys = ?, enabled = ? WHERE id = 1""",
                     (settings["source"], settings["ntp_server"], settings["manual_time"],
                      settings["interval_minutes"], json.dumps(settings["target_keys"]), int(settings["enabled"])))
        conn.commit()
    finally:
        conn.close()
    return load_time_sync_settings()


@app.post("/api/time-sync/run")
def run_time_sync_now():
    try:
        return run_time_sync()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=502, detail="Nie udało się pobrać czasu ze wskazanego serwera.") from exc


@app.put("/api/dvrs/{dvr_id}")
def update_dvr(dvr_id: int, update: NVRUpdate):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        current = conn.execute("SELECT password FROM dvrs WHERE id = ?", (dvr_id,)).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora.")
        nvr = NVR(name=update.name, ip=update.ip, port=update.port, user=update.user,
                  password=update.password or current[0])
        channels = fetch_nvr_channels(nvr)
        vendor = update.vendor or ("Hikvision" if is_hikvision_nvr(nvr.ip, nvr.user, nvr.password) else None)
        conn.execute("UPDATE dvrs SET name = ?, ip = ?, port = ?, user = ?, password = ?, vendor = ? WHERE id = ?",
                     (nvr.name, nvr.ip, nvr.port, nvr.user, nvr.password, vendor, dvr_id))
        conn.execute("DELETE FROM channels WHERE dvr_id = ?", (dvr_id,))
        conn.executemany("INSERT INTO channels (dvr_id, channel_number, name) VALUES (?, ?, ?)",
                         [(dvr_id, channel["channel_number"], channel["name"]) for channel in channels])
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "channels_count": len(channels)}


def sync_dvr_channel_names(dvr_id: int) -> dict:
    conn = sqlite3.connect("data/dvrs.db")
    try:
        row = conn.execute("SELECT name, ip, port, user, password FROM dvrs WHERE id = ?", (dvr_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora.")
        name, ip, port, user, password = row
        nvr = NVR(name=name, ip=ip, port=port, user=user, password=password)
        channels = fetch_nvr_channels(nvr)
        for ch in channels:
            ch_num = ch["channel_number"]
            ch_name = ch["name"]
            existing = conn.execute("SELECT 1 FROM channels WHERE dvr_id = ? AND channel_number = ?",
                                    (dvr_id, ch_num)).fetchone()
            if existing:
                conn.execute("UPDATE channels SET name = ? WHERE dvr_id = ? AND channel_number = ?",
                             (ch_name, dvr_id, ch_num))
            else:
                conn.execute("INSERT INTO channels (dvr_id, channel_number, name) VALUES (?, ?, ?)",
                             (dvr_id, ch_num, ch_name))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "dvr_id": dvr_id, "channels": channels}


@app.post("/api/dvrs/{dvr_id}/sync-names")
def endpoint_sync_dvr_names(dvr_id: int):
    return sync_dvr_channel_names(dvr_id)


@app.post("/api/dvrs/sync-names")
def endpoint_sync_all_dvr_names():
    conn = sqlite3.connect("data/dvrs.db")
    try:
        dvr_ids = [r[0] for r in conn.execute("SELECT id FROM dvrs").fetchall()]
    finally:
        conn.close()
    results = {}
    for did in dvr_ids:
        try:
            results[str(did)] = sync_dvr_channel_names(did)
        except Exception as e:
            results[str(did)] = {"status": "error", "detail": str(e)}
    return {"status": "success", "results": results}


@app.delete("/api/dvrs/{dvr_id}")
def delete_dvr(dvr_id: int):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        exists = conn.execute("SELECT 1 FROM dvrs WHERE id = ?", (dvr_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora.")
        conn.execute("DELETE FROM device_category_items WHERE device_type = 'nvr' AND device_id = ?", (dvr_id,))
        conn.execute("DELETE FROM channels WHERE dvr_id = ?", (dvr_id,))
        conn.execute("DELETE FROM dvrs WHERE id = ?", (dvr_id,))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "deleted_id": dvr_id, "type": "nvr"}


@app.delete("/api/cameras/{camera_id}")
def delete_camera(camera_id: int):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        exists = conn.execute("SELECT 1 FROM cameras WHERE id = ?", (camera_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="Nie znaleziono kamery.")
        conn.execute("DELETE FROM device_category_items WHERE device_type = 'camera' AND device_id = ?", (camera_id,))
        conn.execute("DELETE FROM cameras WHERE id = ?", (camera_id,))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "deleted_id": camera_id, "type": "camera"}


@app.delete("/api/dvrs/{dvr_id}/channels/{channel_number}")
def delete_dvr_channel(dvr_id: int, channel_number: int):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        cursor = conn.execute("DELETE FROM channels WHERE dvr_id = ? AND channel_number = ?", (dvr_id, channel_number))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Nie znaleziono kanału.")
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "dvr_id": dvr_id, "channel_number": channel_number}


@app.delete("/api/devices/{device_type}/{device_id}")
def delete_device(device_type: Literal["nvr", "camera"], device_id: int):
    if device_type == "nvr":
        return delete_dvr(device_id)
    elif device_type == "camera":
        return delete_camera(device_id)
    raise HTTPException(status_code=400, detail="Nieobsługiwany typ urządzenia.")


@app.get("/api/cache/info")
def get_cache_info():
    total_bytes = 0
    file_count = 0
    for folder in [Path("data/archive-tmp"), Path("data/archive-jobs")]:
        if folder.exists():
            for root, _, files in os.walk(folder):
                for f in files:
                    try:
                        total_bytes += os.path.getsize(os.path.join(root, f))
                        file_count += 1
                    except OSError:
                        pass
    return {
        "total_bytes": total_bytes,
        "total_mb": round(total_bytes / (1024 * 1024), 1),
        "total_gb": round(total_bytes / (1024 * 1024 * 1024), 2),
        "file_count": file_count
    }


@app.post("/api/cache/clean")
def clean_cache():
    freed_bytes = 0
    deleted_files = 0
    tmp_dir = Path("data/archive-tmp")
    if tmp_dir.exists():
        for item in tmp_dir.iterdir():
            try:
                if item.is_file():
                    freed_bytes += item.stat().st_size
                    item.unlink()
                    deleted_files += 1
                elif item.is_dir():
                    size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
                    freed_bytes += size
                    shutil.rmtree(item, ignore_errors=True)
            except Exception:
                pass

    conn = sqlite3.connect("data/dvrs.db")
    try:
        active_paths = [r[0] for r in conn.execute("SELECT result_path FROM download_jobs WHERE status = 'processing'").fetchall() if r[0]]
    finally:
        conn.close()

    jobs_dir = Path("data/archive-jobs")
    if jobs_dir.exists():
        for item in jobs_dir.iterdir():
            if item.is_dir():
                is_active = any(str(item) in str(ap) for ap in active_paths)
                if not is_active:
                    try:
                        size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
                        freed_bytes += size
                        shutil.rmtree(item, ignore_errors=True)
                        deleted_files += 1
                    except Exception:
                        pass

    return {
        "status": "success",
        "freed_bytes": freed_bytes,
        "freed_mb": round(freed_bytes / (1024 * 1024), 1),
        "freed_gb": round(freed_bytes / (1024 * 1024 * 1024), 2),
        "deleted_files": deleted_files
    }


@app.get("/api/devices")
def get_devices():
    conn = sqlite3.connect("data/dvrs.db")
    try:
        rows = conn.execute("SELECT id, name, ip, port, vendor FROM dvrs ORDER BY name").fetchall()
        devices = [{"id": r[0], "type": "nvr", "name": r[1], "ip": r[2], "port": r[3], "vendor": r[4],
                    "channels_count": conn.execute("SELECT COUNT(*) FROM channels WHERE dvr_id = ?", (r[0],)).fetchone()[0]} for r in rows]
        devices += [{"id": r[0], "type": "camera", "name": r[1], "ip": r[2], "port": r[3],
                     "channels_count": 1, "vendor": camera_vendor_from_rtsp_path(r[4])}
                    for r in conn.execute("SELECT id, name, ip, port, rtsp_path FROM cameras ORDER BY name").fetchall()]
        memberships = conn.execute("SELECT category_id, device_type, device_id FROM device_category_items").fetchall()
        categories = [{"id": r[0], "name": r[1], "hidden": bool(r[2]), "system": r[3] == "all", "device_keys": []}
                      for r in conn.execute("SELECT id, name, hidden, system_key FROM device_categories ORDER BY system_key DESC, name").fetchall()]
    finally:
        conn.close()
    by_id = {c["id"]: c for c in categories}
    for category_id, kind, item_id in memberships:
        if category_id in by_id:
            by_id[category_id]["device_keys"].append(f"{kind}:{item_id}")
    return {"devices": devices, "categories": categories}


@app.post("/api/devices/scan")
def scan_devices(request: DeviceScanRequest):
    # Explicitly supplied addresses are the priority; ONVIF multicast is the
    # fallback when no scope was provided.
    try:
        targets = parse_scan_targets(request.targets) if request.targets.strip() else []
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    found: dict[str, dict] = {}
    conn = sqlite3.connect("data/dvrs.db")
    try:
        known_nvr_ips = {row[0] for row in conn.execute("SELECT ip FROM dvrs")}
    finally:
        conn.close()
    if targets:
        with ThreadPoolExecutor(max_workers=min(48, len(targets))) as pool:
            futures = [pool.submit(scan_host, ip, request.user, request.password, ip in known_nvr_ips) for ip in targets]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found[result["ip"]] = result
                    remember_discovery_network(result["ip"])
    else:
        pnp_methods: dict[str, str] = {}
        for result in ws_discover():
            pnp_methods[result["ip"]] = "ONVIF WS-Discovery"
        for result in ssdp_discover():
            pnp_methods[result["ip"]] = (
                "ONVIF WS-Discovery + UPnP/SSDP" if result["ip"] in pnp_methods else "UPnP/SSDP"
            )
        # Prefer real LANs learned from saved devices. Container routes are a
        # fallback when no device has been saved yet.
        routed_targets = list(dict.fromkeys([*pnp_methods, *(known_device_network_targets() or routed_ipv4_targets())]))
        with ThreadPoolExecutor(max_workers=min(48, len(routed_targets) or 1)) as pool:
            futures = [pool.submit(scan_host, ip, request.user, request.password, ip in known_nvr_ips) for ip in routed_targets]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    result["method"] = pnp_methods.get(result["ip"], "Skan dostępnej podsieci")
                    found.setdefault(result["ip"], result)
                    remember_discovery_network(result["ip"])
    return {"devices": sorted(found.values(), key=lambda item: item["ip"]),
            "method": "Skan wskazanego zakresu IP" if targets else "ONVIF + UPnP/SSDP + podsieci zapisanych urządzeń"}


@app.post("/api/devices/full-scan/start")
def start_full_local_scan(request: DeviceScanRequest):
    networks = save_discovery_network_preferences(request.networks) if request.networks else full_local_scan_networks()
    if not networks:
        raise HTTPException(status_code=422, detail="Nie znaleziono lokalnej prywatnej podsieci do przeskanowania.")
    total = sum(network.num_addresses - 2 for network in networks)
    with DISCOVERY_JOB_LOCK:
        if DISCOVERY_JOB["running"]:
            raise HTTPException(status_code=409, detail="Pełne skanowanie już trwa.")
        DISCOVERY_CANCEL.clear()
        DISCOVERY_JOB.update({"running": True, "cancelled": False, "network": str(networks[0]),
                              "completed": 0, "total": total, "devices": [], "error": "",
                              "networks": [str(network) for network in networks], "network_index": 1})
        Thread(target=full_local_scan_worker, args=(networks, request.user, request.password), daemon=True).start()
    return {"networks": [str(network) for network in networks], "total": total}


@app.get("/api/devices/full-scan/candidates")
def get_full_local_scan_candidates():
    return {"networks": discovery_network_candidates()}


@app.post("/api/devices/full-scan/candidates")
def add_full_local_scan_candidates(selection: DiscoveryNetworkSelection):
    existing = [item["cidr"] for item in discovery_network_candidates() if item["enabled"]]
    save_discovery_network_preferences([*existing, *selection.networks])
    custom_networks = [str(ipaddress.ip_network(value, strict=False)) for value in selection.networks]
    conn = sqlite3.connect("data/dvrs.db")
    try:
        conn.executemany("UPDATE discovery_scan_networks SET custom = 1, hidden = 0 WHERE cidr = ?",
                         [(network,) for network in custom_networks])
        conn.commit()
    finally:
        conn.close()
    return {"networks": discovery_network_candidates()}


@app.delete("/api/devices/full-scan/candidates")
def remove_full_local_scan_candidates(selection: DiscoveryNetworkSelection):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        conn.executemany("INSERT INTO discovery_scan_networks (cidr, enabled, hidden) VALUES (?, 0, 1) ON CONFLICT(cidr) DO UPDATE SET enabled = 0, hidden = 1",
                         [(value,) for value in selection.networks])
        conn.commit()
    finally:
        conn.close()
    return {"networks": discovery_network_candidates()}


@app.get("/api/devices/full-scan/status")
def full_local_scan_status():
    with DISCOVERY_JOB_LOCK:
        return dict(DISCOVERY_JOB)


@app.post("/api/devices/full-scan/cancel")
def cancel_full_local_scan():
    DISCOVERY_CANCEL.set()
    return {"status": "cancelling"}


@app.post("/api/cameras/test")
def test_camera(camera: Camera):
    try:
        with socket.create_connection((camera.ip, camera.port), timeout=3):
            pass
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Nie można połączyć się z kamerą RTSP: {exc}") from exc
    resolve_camera_connection(camera)
    verify_camera_rtsp(camera)
    return {"status": "ok", "type": "camera", "rtsp_path": camera.rtsp_path}


@app.post("/api/cameras")
def add_camera(camera: Camera):
    test_camera(camera)
    conn = sqlite3.connect("data/dvrs.db")
    try:
        cursor = conn.execute("INSERT INTO cameras (name, ip, port, user, password, rtsp_path) VALUES (?, ?, ?, ?, ?, ?)",
                              (camera.name, camera.ip, camera.port, camera.user, camera.password, camera.rtsp_path))
        camera_id = cursor.lastrowid
        for category_id in set(camera.category_ids):
            exists = conn.execute("SELECT 1 FROM device_categories WHERE id = ?", (category_id,)).fetchone()
            if exists:
                conn.execute("INSERT OR IGNORE INTO device_category_items VALUES (?, 'camera', ?)", (category_id, camera_id))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "device_id": camera_id, "type": "camera"}


@app.put("/api/cameras/{camera_id}")
def update_camera(camera_id: int, camera: Camera):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        current = conn.execute("SELECT password FROM cameras WHERE id = ?", (camera_id,)).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="Nie znaleziono kamery.")
        camera.password = camera.password or current[0]
        test_camera(camera)
        conn.execute("""UPDATE cameras SET name = ?, ip = ?, port = ?, user = ?, password = ?, rtsp_path = ?
                        WHERE id = ?""",
                     (camera.name, camera.ip, camera.port, camera.user, camera.password, camera.rtsp_path, camera_id))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "device_id": camera_id, "type": "camera"}


@app.post("/api/devices/nvr/{dvr_id}/convert-to-camera")
def convert_nvr_to_camera(dvr_id: int, camera: Camera):
    """Move a falsely classified recorder into the independent-camera list."""
    conn = sqlite3.connect("data/dvrs.db")
    try:
        row = conn.execute("SELECT name, ip, port, user, password FROM dvrs WHERE id = ?", (dvr_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora.")
        old_name, old_ip, old_port, old_user, old_password = row
        camera.name = camera.name or old_name
        camera.ip = camera.ip or old_ip
        camera.port = camera.port or old_port
        camera.user = camera.user or old_user
        camera.password = camera.password or old_password
        test_camera(camera)
        cursor = conn.execute(
            "INSERT INTO cameras (name, ip, port, user, password, rtsp_path) VALUES (?, ?, ?, ?, ?, ?)",
            (camera.name, camera.ip, camera.port, camera.user, camera.password, camera.rtsp_path),
        )
        camera_id = cursor.lastrowid
        conn.execute("UPDATE device_category_items SET device_type = 'camera', device_id = ? WHERE device_type = 'nvr' AND device_id = ?",
                     (camera_id, dvr_id))
        conn.execute("DELETE FROM channels WHERE dvr_id = ?", (dvr_id,))
        conn.execute("DELETE FROM dvrs WHERE id = ?", (dvr_id,))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "device_id": camera_id, "type": "camera"}


@app.post("/api/device-categories")
def add_device_category(category: DeviceCategory):
    name = category.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Nazwa kategorii nie może być pusta.")
    conn = sqlite3.connect("data/dvrs.db")
    try:
        cursor = conn.execute("INSERT INTO device_categories (name, hidden) VALUES (?, ?)", (name, category.hidden))
        conn.commit()
        return {"id": cursor.lastrowid, "name": name, "hidden": category.hidden}
    finally:
        conn.close()


@app.put("/api/device-categories/{category_id}")
def update_device_category(category_id: int, category: DeviceCategory):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        if not conn.execute("SELECT 1 FROM device_categories WHERE id = ?", (category_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Nie znaleziono kategorii.")
        conn.execute("UPDATE device_categories SET name = ?, hidden = ? WHERE id = ?", (category.name.strip(), category.hidden, category_id))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success"}


@app.delete("/api/device-categories/{category_id}")
def delete_device_category(category_id: int):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        system = conn.execute("SELECT system_key FROM device_categories WHERE id = ?", (category_id,)).fetchone()
        if not system:
            raise HTTPException(status_code=404, detail="Nie znaleziono kategorii.")
        if system[0] == "all":
            raise HTTPException(status_code=400, detail="Kategoria „Wszystkie urządzenia” jest stała i nie może zostać usunięta.")
        conn.execute("DELETE FROM device_category_items WHERE category_id = ?", (category_id,))
        conn.execute("DELETE FROM device_categories WHERE id = ?", (category_id,))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success"}


@app.put("/api/device-categories/{category_id}/members")
def update_category_members(category_id: int, members: CategoryMembers):
    conn = sqlite3.connect("data/dvrs.db")
    try:
        row = conn.execute("SELECT system_key FROM device_categories WHERE id = ?", (category_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Nie znaleziono kategorii.")
        if row[0] == "all":
            raise HTTPException(status_code=400, detail="Stała kategoria zawiera zawsze wszystkie urządzenia.")
        for key in set(members.device_keys):
            try:
                kind, raw_id = key.split(":", 1)
                item_id = int(raw_id)
            except ValueError:
                continue
            if kind not in {"nvr", "camera"}:
                continue
            table = "dvrs" if kind == "nvr" else "cameras"
            if conn.execute(f"SELECT 1 FROM {table} WHERE id = ?", (item_id,)).fetchone():
                conn.execute("DELETE FROM device_category_items WHERE device_type = ? AND device_id = ?", (kind, item_id))
                conn.execute("INSERT INTO device_category_items VALUES (?, ?, ?)", (category_id, kind, item_id))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success"}


@app.put("/api/device-category-assignments")
def update_device_category_assignments(data: DeviceAssignments):
    """Assign every device to at most one custom category (folder semantics)."""
    conn = sqlite3.connect("data/dvrs.db")
    try:
        valid_categories = {r[0] for r in conn.execute("SELECT id FROM device_categories WHERE system_key IS NULL")}
        for key, category_id in data.assignments.items():
            try:
                kind, raw_id = key.split(":", 1)
                device_id = int(raw_id)
            except ValueError:
                continue
            if kind not in {"nvr", "camera"}:
                continue
            table = "dvrs" if kind == "nvr" else "cameras"
            if not conn.execute(f"SELECT 1 FROM {table} WHERE id = ?", (device_id,)).fetchone():
                continue
            conn.execute("DELETE FROM device_category_items WHERE device_type = ? AND device_id = ?", (kind, device_id))
            if category_id in valid_categories:
                conn.execute("INSERT INTO device_category_items VALUES (?, ?, ?)", (category_id, kind, device_id))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success"}


@app.post("/api/webrtc")
def start_webrtc_session(offer: WebRTCOffer, request: Request):
    """Rejestruje strumień RTSP (#media=video) w go2rtc i zwraca SDP Answer z lokalnym kandydatem ICE."""
    try:
        stream_name = ensure_go2rtc_stream(offer.dvr_id, offer.channel, offer.stream)
        if stream_needs_color_normalization(stream_name):
            raise HTTPException(
                status_code=409,
                detail="Ten strumień wymaga zgodnej konwersji kolorów.",
            )

        w_req = urllib.request.Request(
            f"{GO2RTC_API}/api/webrtc?src={urllib.parse.quote(stream_name)}",
            data=offer.sdp.encode("utf-8"),
            headers={"Content-Type": "application/sdp"},
            method="POST",
        )
        with urllib.request.urlopen(w_req, timeout=30.0 if offer.stream == 1 else 15.0) as w_resp:
            answer_sdp = w_resp.read().decode("utf-8")

        ufrag_match = re.search(r"a=ice-ufrag:([^\r\n]+)", answer_sdp)
        ufrag_part = f" ufrag {ufrag_match.group(1)}" if ufrag_match else ""

        host_ip = request.url.hostname or "127.0.0.1"
        if host_ip == "localhost":
            host_ip = "127.0.0.1"

        local_candidates = (
            f"a=candidate:1001 1 udp 2130706431 {host_ip} 8555 typ host{ufrag_part}\r\n"
            f"a=candidate:1002 1 tcp 2105524479 {host_ip} 8555 typ host tcptype passive{ufrag_part}\r\n"
        )
        answer_sdp = answer_sdp.rstrip("\r\n") + "\r\n" + local_candidates

        return {"type": "answer", "sdp": answer_sdp}
    except HTTPException:
        raise
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=502, detail=f"Błąd go2rtc ({e.code}): {err_body}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Błąd połączenia z go2rtc: {str(e)}")


@app.post("/api/cameras/{camera_id}/webrtc")
def start_camera_webrtc_session(camera_id: int, offer: WebRTCOffer, request: Request):
    """The offer shape stays compatible with the NVR endpoint; channel is ignored."""
    try:
        stream_name = ensure_camera_stream(camera_id, offer.stream)
        if stream_needs_color_normalization(stream_name):
            raise HTTPException(
                status_code=409,
                detail="Stream requires color space normalization; use MP4 fallback instead.",
            )
        w_req = urllib.request.Request(
            f"{GO2RTC_API}/api/webrtc?src={urllib.parse.quote(stream_name)}", data=offer.sdp.encode("utf-8"),
            headers={"Content-Type": "application/sdp"}, method="POST")
        with urllib.request.urlopen(w_req, timeout=20.0) as response:
            answer_sdp = response.read().decode("utf-8")
        host_ip = request.url.hostname or "127.0.0.1"
        if host_ip == "localhost": host_ip = "127.0.0.1"
        return {"type": "answer", "sdp": answer_sdp.rstrip("\r\n") + f"\r\na=candidate:1001 1 udp 2130706431 {host_ip} 8555 typ host\r\n"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Błąd połączenia z kamerą: {exc}") from exc


@app.get("/api/stream.mp4")
def proxy_mp4_stream(dvr_id: int, channel: int, stream: int = 2):
    """Copy H.264 from the relay into fMP4 without its HTTP MP4 consumer."""
    stream_name = ensure_go2rtc_stream(dvr_id, channel, stream)
    binary = os.environ.get("FFMPEG_BIN") or shutil.which("ffmpeg")
    if not binary:
        raise HTTPException(status_code=503, detail="Brak FFmpeg do podglądu obrazu.")
    needs_norm = stream_needs_color_normalization(stream_name)
    source = (get_rtsp_url_for_stream(stream_name) if needs_norm else None) or f"{GO2RTC_RTSP}/{urllib.parse.quote(stream_name)}?video=h264"
    try:
        proxy = open_mp4_proxy(binary, source, needs_norm)
    except OSError as exc:
        raise HTTPException(status_code=502, detail="Nie udało się odebrać obrazu z przekaźnika.") from exc
    return StreamingResponse(proxy.chunks(), media_type="video/mp4",
                             background=BackgroundTask(proxy.close))


@app.get("/api/cameras/{camera_id}/stream.mp4")
def proxy_camera_mp4_stream(camera_id: int, stream: int = 2):
    stream_name = ensure_camera_stream(camera_id, stream)
    binary = os.environ.get("FFMPEG_BIN") or shutil.which("ffmpeg")
    if not binary:
        raise HTTPException(status_code=503, detail="Brak FFmpeg do podglądu obrazu.")
    needs_norm = stream_needs_color_normalization(stream_name)
    source = (get_rtsp_url_for_stream(stream_name) if needs_norm else None) or f"{GO2RTC_RTSP}/{urllib.parse.quote(stream_name)}?video=h264"
    try:
        proxy = open_mp4_proxy(binary, source, needs_norm)
    except OSError as exc:
        raise HTTPException(status_code=502, detail="Nie udało się odebrać obrazu z przekaźnika.") from exc
    return StreamingResponse(proxy.chunks(), media_type="video/mp4", background=BackgroundTask(proxy.close))


def get_recording_dvr(dvr_id: int) -> tuple[str, str, int, str, str]:
    """Zwraca dane połączenia do NVR, nie wystawiając hasła poza proces."""
    conn = sqlite3.connect("data/dvrs.db")
    try:
        row = conn.execute(
            "SELECT name, ip, port, user, password FROM dvrs WHERE id = ?", (dvr_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora w bazie.")
    return row


def validate_recording_request(date: str, filename: str | None, start_time: str | None, end_time: str | None) -> tuple[str, str]:
    try:
        datetime.strptime(date, "%Y-%m-%d")
        start = datetime.strptime(start_time or "00:00:00", "%H:%M:%S")
        end = datetime.strptime(end_time or "23:59:59", "%H:%M:%S")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Nieprawidłowy format daty lub godziny nagrania.") from exc
    if filename and not filename.startswith("hikvision:"):
        try:
            Recording.parse(filename)
        except ArchiveError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif end <= start:
        raise HTTPException(status_code=422, detail="Koniec nagrania musi być późniejszy niż początek.")
    return start.strftime("%H:%M:%S"), end.strftime("%H:%M:%S")


@app.get("/api/recordings/days")
def get_recording_days(dvr_id: int, channel: int, year: int, month: int):
    """Zwraca listę dni w podanym miesiącu i roku, dla których na danym kanale istnieją nagrania."""
    conn = sqlite3.connect("data/dvrs.db")
    c = conn.cursor()
    c.execute("SELECT ip, user, password, vendor FROM dvrs WHERE id = ?", (dvr_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora w bazie.")

    ip, user, password = row[:3]
    vendor = row[3] if len(row) > 3 else None
    if vendor == "Hikvision" or is_hikvision_nvr(ip, user, password):
        month_start = datetime(year, month, 1)
        month_end = datetime(year + (month == 12), 1 if month == 12 else month + 1, 1)
        segments = hikvision_search_all_recordings(ip, user, password, channel, month_start, month_end)
        days = set()
        for segment in segments:
            day = max(segment["start"], month_start).date()
            last_day = min(segment["end"] - timedelta(microseconds=1), month_end - timedelta(microseconds=1)).date()
            while day <= last_day:
                if day.year == year and day.month == month:
                    days.add(day.day)
                day += timedelta(days=1)
        return {
            "dvr_id": dvr_id, "channel": channel, "year": year, "month": month,
            "days": sorted(days),
        }
    # Despite its name, this CGI field takes a channel number, not a bit mask.
    channel_mask = channel
    content = (
        f"<record>"
        f"<channelmask>{channel_mask}</channelmask>"
        f"<stream>all</stream>"
        f"<year>{year}</year>"
        f"<month>{month}</month>"
        f"</record>"
    )
    root = tdk_send_command(ip, user, password, "get.record.search", content, timeout=12.0)
    if root is None:
        raise HTTPException(status_code=502, detail="Brak odpowiedzi od rejestratora.")

    daymask_text = root.findtext(".//daymask") or ""
    days = []
    if daymask_text.strip():
        for d in daymask_text.split(","):
            d = d.strip()
            if d.isdigit():
                days.append(int(d))

    return {
        "dvr_id": dvr_id,
        "channel": channel,
        "year": year,
        "month": month,
        "days": sorted(set(days)),
    }


@app.get("/api/recordings/files")
def get_recording_files(dvr_id: int, channel: int, date: str):
    """Pobiera listę plików nagrań dla wybranego kontrolera, kanału i daty (YYYY-MM-DD)."""
    conn = sqlite3.connect("data/dvrs.db")
    c = conn.cursor()
    c.execute("SELECT ip, user, password, vendor FROM dvrs WHERE id = ?", (dvr_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora w bazie.")

    ip, user, password = row[:3]
    vendor = row[3] if len(row) > 3 else None
    if vendor == "Hikvision" or is_hikvision_nvr(ip, user, password):
        return {"files": hikvision_recording_files(ip, user, password, channel, date),
                "date": date, "channel": channel, "dvr_id": dvr_id}
    cnt_session = (
        f"<record>"
        f"<filetype>video</filetype>"
        f"<occurtype>all</occurtype>"
        f"<stream>all</stream>"
        f"<channel>{channel}</channel>"
        f"<starttime>{date}t00:00:00z</starttime>"
        f"<endtime>{date}t23:59:59z</endtime>"
        f"</record>"
    )
    sess_root = tdk_send_command(ip, user, password, "g.rec.session", cnt_session, timeout=15.0)
    if sess_root is None:
        raise HTTPException(status_code=502, detail="Brak odpowiedzi od rejestratora podczas tworzenia sesji.")

    sid = sess_root.findtext(".//id")
    if not sid:
        return {"files": [], "date": date, "channel": channel, "dvr_id": dvr_id}

    cnt_msg = f"<record><id>{sid}</id></record>"
    msg_root = tdk_send_command(ip, user, password, "g.rec.msg", cnt_msg, timeout=15.0)
    if msg_root is None:
        return {"files": [], "date": date, "channel": channel, "dvr_id": dvr_id}

    files = []
    for f_el in msg_root.findall(".//filename"):
        raw_name = (f_el.text or "").strip()
        if not raw_name:
            continue
        parts = raw_name.split("_")
        if len(parts) < 3:
            continue
        try:
            start_str = parts[1]  # YYYY-MM-DD-HH-MM-SS
            dur_sec = int(parts[2])
            start_dt = datetime.strptime(start_str, "%Y-%m-%d-%H-%M-%S")
            end_dt = start_dt + timedelta(seconds=dur_sec)

            size_kb = int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0
            size_mb = round(size_kb / 1024.0, 1)

            dur_hours = dur_sec // 3600
            dur_mins = (dur_sec % 3600) // 60
            dur_secs = dur_sec % 60
            dur_formatted = f"{dur_hours:02d}:{dur_mins:02d}:{dur_secs:02d}"

            files.append({
                "filename": raw_name,
                "start_time": start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": end_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "time_only_start": start_dt.strftime("%H:%M:%S"),
                "time_only_end": end_dt.strftime("%H:%M:%S"),
                "duration_seconds": dur_sec,
                "duration_formatted": dur_formatted,
                "size_kb": size_kb,
                "size_mb": size_mb,
            })
        except Exception:
            continue

    files.sort(key=lambda x: x["start_time"])
    for i, item in enumerate(files):
        item["index"] = i + 1

    return {"files": files, "date": date, "channel": channel, "dvr_id": dvr_id}


try:
    ARCHIVE_JOB_LIMIT = max(1, int(os.environ.get("ARCHIVE_MAX_CONCURRENT_JOBS", "2")))
except ValueError:
    ARCHIVE_JOB_LIMIT = 2
ARCHIVE_JOBS = BoundedSemaphore(ARCHIVE_JOB_LIMIT)


def download_owner(request: Request) -> str:
    """Stable per-user key; anonymous browsers supply their own random id."""
    user = request.session.get("user") or {}
    provider, subject = user.get("provider"), user.get("subject")
    if provider and subject:
        return f"user:{provider}:{subject}"
    browser_id = request.headers.get("X-Download-Client", "")
    if not re.fullmatch(r"[a-f0-9-]{16,64}", browser_id):
        raise HTTPException(status_code=400, detail="Brak identyfikatora przeglądarki pobrań.")
    return f"browser:{browser_id}"


class DownloadJobRequest(BaseModel):
    dvr_id: int
    channel: int
    date: str
    filename: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    format: Literal["avi", "mp4"] = "avi"
    quality: Literal["original", "1080p", "720p", "480p"] = "original"
    fps: Literal["original", "15", "10"] = "original"
    anonymize: bool = False


def update_download_job(job_id: str, **values):
    if not values:
        return
    assignments = ", ".join(f"{column} = ?" for column in values)
    with sqlite3.connect("data/dvrs.db") as conn:
        conn.execute(f"UPDATE download_jobs SET {assignments} WHERE id = ?", (*values.values(), job_id))


def job_row(row, now=None):
    now = time_module.time() if now is None else now
    data = dict(zip(("id", "created_at", "started_at", "finished_at", "dvr_id", "dvr_name", "channel",
                     "camera_name", "recording_date", "start_time", "end_time", "filename", "output_format",
                     "quality", "fps", "anonymized", "status", "stage", "progress", "result_name", "error",
                     "duration_seconds"), row))
    data["anonymized"] = bool(data["anonymized"])
    data["progress"] = round(float(data["progress"]), 1)
    data["elapsed_seconds"] = round(max(0, (data["finished_at"] or now) - (data["started_at"] or data["created_at"])))
    return data


class DownloadJobs:
    def __init__(self, workers: int):
        self.workers = workers
        self.queue = Queue()
        self.stop_event = Event()
        self.threads = []
        self.dvr_locks = {}
        self.dvr_locks_guard = Lock()
        self.active_cancels: dict[str, Event] = {}
        self.active_cancels_guard = Lock()

    def start(self):
        if self.threads:
            return
        with sqlite3.connect("data/dvrs.db") as conn:
            conn.execute("UPDATE download_jobs SET status = 'queued', started_at = NULL, stage = 'Oczekuje po restarcie' WHERE status = 'processing'")
            pending = conn.execute("SELECT id FROM download_jobs WHERE status = 'queued' ORDER BY created_at").fetchall()
        for (job_id,) in pending:
            self.queue.put(job_id)
        self.threads = [Thread(target=self._worker, daemon=True, name=f"download-worker-{number}")
                        for number in range(self.workers)]
        for thread in self.threads:
            thread.start()

    def stop(self):
        self.stop_event.set()
        for _ in self.threads:
            self.queue.put(None)
        for thread in self.threads:
            thread.join(timeout=2)
        self.threads = []

    def enqueue(self, job_id: str):
        self.queue.put(job_id)

    def cancel(self, job_id: str) -> bool:
        with self.active_cancels_guard:
            event = self.active_cancels.get(job_id)
            if event is not None:
                event.set()
                return True
        with sqlite3.connect("data/dvrs.db") as conn:
            row = conn.execute("SELECT status FROM download_jobs WHERE id = ?", (job_id,)).fetchone()
            if row and row[0] == "queued":
                conn.execute("UPDATE download_jobs SET status = 'cancelled', stage = 'Anulowane przez użytkownika', finished_at = ? WHERE id = ?",
                             (time_module.time(), job_id))
                conn.commit()
                return True
        return False

    def _dvr_lock(self, dvr_id: int):
        with self.dvr_locks_guard:
            return self.dvr_locks.setdefault(dvr_id, Lock())

    def _worker(self):
        while not self.stop_event.is_set():
            try:
                job_id = self.queue.get(timeout=0.5)
            except Empty:
                continue
            if job_id is None:
                return
            try:
                self._run(job_id)
            except Exception:
                logging.getLogger(__name__).exception("Nieobsłużony błąd zadania pobrania %s", job_id)
            finally:
                self.queue.task_done()

    def _run(self, job_id: str):
        with sqlite3.connect("data/dvrs.db") as conn:
            row = conn.execute("SELECT id, dvr_id, channel, recording_date, filename, start_time, end_time, output_format, quality, fps, anonymized FROM download_jobs WHERE id = ? AND status = 'queued'", (job_id,)).fetchone()
        if not row:
            return
        _, dvr_id, channel, date, filename, start_time, end_time, output_format, quality, fps_choice, anonymized = row
        recorder_lock = self._dvr_lock(dvr_id)
        if not recorder_lock.acquire(blocking=False):
            # A number of NVRs allow only one archive session at a time.
            # Keep the global worker available for a different recorder.
            update_download_job(job_id, stage="Oczekuje na eksport z tego rejestratora", progress=0)
            self.queue.put(job_id)
            time_module.sleep(0.2)
            return

        cancel_event = Event()
        with self.active_cancels_guard:
            self.active_cancels[job_id] = cancel_event

        started = time_module.time()
        update_download_job(job_id, status="processing", stage="Pobieranie materiału z rejestratora", progress=1,
                            started_at=started, error=None)

        def report(stage, progress):
            update_download_job(job_id, stage=stage, progress=max(1, min(99, progress)))

        folder = None
        acquired = False
        try:
            if cancel_event.is_set():
                update_download_job(job_id, status="cancelled", stage="Anulowane przez użytkownika", progress=0,
                                    finished_at=time_module.time(), duration_seconds=time_module.time() - started)
                return
            # The legacy direct endpoint shares this same limiter, so every
            # user together can never make more than two recorder transfers.
            ARCHIVE_JOBS.acquire()
            acquired = True
            folder, result, result_name = build_queued_recording(
                dvr_id, channel, date, filename, start_time, end_time, output_format, quality,
                fps_choice, bool(anonymized), report, is_cancelled=cancel_event.is_set,
            )
            update_download_job(job_id, status="ready", stage="Gotowe do pobrania", progress=100,
                                finished_at=time_module.time(), duration_seconds=time_module.time() - started,
                                result_path=str(result), result_name=result_name)
        except ArchiveCancelled:
            if folder:
                shutil.rmtree(folder, ignore_errors=True)
            update_download_job(job_id, status="cancelled", stage="Anulowane przez użytkownika", progress=0,
                                finished_at=time_module.time(), duration_seconds=time_module.time() - started)
        except (ArchiveError, HTTPException, OSError, ValueError) as exc:
            if folder:
                shutil.rmtree(folder, ignore_errors=True)
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
            update_download_job(job_id, status="failed", stage="Nie udało się przygotować nagrania", progress=0,
                                finished_at=time_module.time(), duration_seconds=time_module.time() - started,
                                error=detail)
        finally:
            with self.active_cancels_guard:
                self.active_cancels.pop(job_id, None)
            if acquired:
                ARCHIVE_JOBS.release()
            recorder_lock.release()


download_jobs = DownloadJobs(ARCHIVE_JOB_LIMIT)


def prepare_recording(dvr_id, channel, date, filename, start_time, end_time, preview,
                      output_format="avi", quality="original", fps_choice="original", anonymize=False):
    if output_format not in ("avi", "mp4") or quality not in ("original", "1080p", "720p", "480p"):
        raise HTTPException(status_code=422, detail="Nieprawidłowy format lub jakość nagrania.")
    if channel < 1:
        raise HTTPException(status_code=422, detail="Numer kanału musi być dodatni.")
    _, ip, port, user, password = get_recording_dvr(dvr_id)
    start_time, end_time = validate_recording_request(date, filename, start_time, end_time)
    if not ARCHIVE_JOBS.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Trwa przygotowywanie innych nagrań. Spróbuj ponownie za chwilę.")
    folder = None
    try:
        # Only device-returned filenames may identify a recording. In particular,
        # never substitute an invented RTSP URL or silently choose another file.
        available = get_recording_files(dvr_id, channel, date)["files"]
        if filename:
            matches = [item for item in available if item["filename"] == filename]
            if not matches:
                raise HTTPException(status_code=404, detail="Wybrany plik nie jest już dostępny w archiwum.")
            recording = Recording.parse(filename)
            if recording.channel != channel:
                raise HTTPException(status_code=422, detail="Plik nie należy do wybranej kamery.")
            selections = [(recording, recording.start, recording.end)]
        else:
            begin = datetime.fromisoformat(f"{date}T{start_time}")
            finish = datetime.fromisoformat(f"{date}T{end_time}")
            selections = []
            for item in available:
                recording = Recording.parse(item["filename"])
                if recording.channel != channel:
                    continue
                left, right = max(begin, recording.start), min(finish, recording.end)
                if left < right:
                    selections.append((recording, left, right))
            selections.sort(key=lambda selection: selection[1])
            # Search can return more than one stream for the same period. Pick
            # the first available stream and never duplicate an overlap.
            unique = []
            covered_until = begin
            for recording, left, right in selections:
                left = max(left, covered_until)
                if left < right:
                    unique.append((recording, left, right))
                    covered_until = right
            selections = unique
        if not selections:
            raise HTTPException(status_code=404, detail="Brak nagrań w wybranym zakresie.")
        if preview:
            limit = max(1, min(300, int(os.environ.get("ARCHIVE_PREVIEW_SECONDS", "60"))))
            recording, left, right = selections[0]
            selections = [(recording, left, min(right, left + timedelta(seconds=limit)))]
        scratch = Path("data/archive-tmp")
        scratch.mkdir(parents=True, exist_ok=True)
        folder = Path(tempfile.mkdtemp(prefix="recording-", dir=scratch))
        source = folder / "source.video"
        codec, fps, count = save_video(ip, port, user, password, selections, source)
        target_fps = float(fps_choice) if fps_choice in ("15", "10") else None
        eff_fps = target_fps if (target_fps and target_fps < fps) else fps
        suffix = "mp4" if preview else output_format
        result = folder / f"recording.{suffix}"
        if anonymize:
            # Never downscale before detecting faces. The full recorder
            # archive is wrapped first, then masked, and only then converted
            # to the quality requested for download.
            detector_input = folder / "detector-input.mp4"
            convert_video(source, detector_input, codec, fps, quality="original",
                          target_fps=target_fps if (target_fps and target_fps < fps) else None)
            masked = folder / "masked.mp4"
            anonymize_faces(detector_input, masked)
            convert_video(masked, result, "h264", eff_fps, preview=preview, quality=quality, source_is_container=True)
        else:
            convert_video(source, result, codec, fps, preview=preview, quality=quality,
                          target_fps=target_fps if (target_fps and target_fps < fps) else None)
        headers = {"Cache-Control": "no-store", "X-Archive-Audio": "none"}
        if preview:
            headers["X-Preview-Seconds"] = str(round(count / fps, 2))
        return FileResponse(
            result, media_type="video/mp4" if suffix == "mp4" else "video/x-msvideo",
            filename=(f"nvr-{dvr_id}-ch-{channel}-"
                      f"{selections[0][1]:%Y-%m-%d_%H-%M-%S}_{selections[-1][2]:%H-%M-%S}.{suffix}"),
            content_disposition_type="inline" if preview else "attachment",
            headers=headers,
            background=BackgroundTask(shutil.rmtree, folder, ignore_errors=True),
        )
    except HTTPException:
        if folder:
            shutil.rmtree(folder, ignore_errors=True)
        raise
    except (ArchiveError, OSError, ValueError) as exc:
        if folder:
            shutil.rmtree(folder, ignore_errors=True)
        if isinstance(exc, ArchiveError):
            detail = str(exc)
        elif isinstance(exc, TimeoutError):
            detail = "Przekroczono czas oczekiwania na rejestrator. Spróbuj ponownie."
        else:
            detail = "Błąd połączenia lub przetwarzania archiwum."
        logging.getLogger(__name__).warning("Archive operation failed: %s (errno=%s)",
                                           type(exc).__name__, getattr(exc, "errno", None),
                                           exc_info=not isinstance(exc, ArchiveError))
        raise HTTPException(status_code=502, detail=detail) from exc
    finally:
        ARCHIVE_JOBS.release()


def build_queued_recording(dvr_id, channel, date, filename, start_time, end_time,
                           output_format, quality, fps_choice, anonymize, report, is_cancelled=None):
    """Prepare one persisted queue item; the worker owns the temporary folder."""
    if output_format not in ("avi", "mp4") or quality not in ("original", "1080p", "720p", "480p"):
        raise HTTPException(status_code=422, detail="Nieprawidłowy format lub jakość nagrania.")
    _, ip, port, user, password = get_recording_dvr(dvr_id)
    start_time, end_time = validate_recording_request(date, filename, start_time, end_time)
    hikvision = is_hikvision_nvr(ip, user, password)
    if hikvision:
        hikvision_selections = select_hikvision_recordings(ip, user, password, channel, date,
                                                            filename, start_time, end_time)
        selections = []
    else:
        hikvision_selections = []
        available = get_recording_files(dvr_id, channel, date)["files"]
        if filename:
            matches = [item for item in available if item["filename"] == filename]
            if not matches:
                raise HTTPException(status_code=404, detail="Wybrany plik nie jest już dostępny w archiwum.")
            recording = Recording.parse(filename)
            if recording.channel != channel:
                raise HTTPException(status_code=422, detail="Plik nie należy do wybranej kamery.")
            selections = [(recording, recording.start, recording.end)]
        else:
            begin = datetime.fromisoformat(f"{date}T{start_time}")
            finish = datetime.fromisoformat(f"{date}T{end_time}")
            selections = []
            for item in available:
                recording = Recording.parse(item["filename"])
                if recording.channel != channel:
                    continue
                left, right = max(begin, recording.start), min(finish, recording.end)
                if left < right:
                    selections.append((recording, left, right))
            selections.sort(key=lambda selection: selection[1])
            unique, covered_until = [], begin
            for recording, left, right in selections:
                left = max(left, covered_until)
                if left < right:
                    unique.append((recording, left, right))
                    covered_until = right
            selections = unique
        if not selections:
            raise HTTPException(status_code=404, detail="Brak nagrań w wybranym zakresie.")

    scratch = Path("data/archive-jobs")
    scratch.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="download-", dir=scratch))
    try:
        source = folder / ("source.mp4" if hikvision else "source.video")
        report("Pobieranie materiału z rejestratora", 5)
        if hikvision:
            selection = hikvision_selections[0]
            codec, fps, _ = hikvision_download_video(ip, user, password, selection["playback_uri"],
                                                      source, is_cancelled=is_cancelled)
            selection_start, selection_end = selection["start"], selection["end"]
        else:
            codec, fps, _ = save_video(ip, port, user, password, selections, source, is_cancelled=is_cancelled)
            selection_start, selection_end = selections[0][1], selections[-1][2]
        if is_cancelled and is_cancelled():
            raise ArchiveCancelled("Pobieranie materiału zostało anulowane przez użytkownika.")
        target_fps = float(fps_choice) if fps_choice in ("15", "10") else None
        eff_fps = target_fps if (target_fps and target_fps < fps) else fps
        detector_input = folder / "detector-input.mp4"
        if anonymize:
            report("Przygotowanie materiału HQ do anonimizacji", 35)
            convert_video(source, detector_input, codec, fps, quality="original",
                          source_is_container=hikvision,
                          target_fps=target_fps if (target_fps and target_fps < fps) else None)
            if is_cancelled and is_cancelled():
                raise ArchiveCancelled("Pobieranie materiału zostało anulowane przez użytkownika.")
            masked = folder / "masked.mp4"
            report("Wykrywanie i zasłanianie głów", 40)
            anonymize_faces(detector_input, masked,
                            lambda fraction: report("Wykrywanie i zasłanianie głów", 40 + (fraction or 0) * 45),
                            is_cancelled=is_cancelled)
            if is_cancelled and is_cancelled():
                raise ArchiveCancelled("Pobieranie materiału zostało anulowane przez użytkownika.")
            report("Kodowanie pliku wynikowego", 86)
            input_file, input_codec = masked, "h264"
        else:
            input_file, input_codec = source, codec
            report("Kodowanie pliku wynikowego", 65)
        result = folder / f"recording.{output_format}"
        convert_video(input_file, result, input_codec, eff_fps, quality=quality,
                      source_is_container=anonymize or hikvision,
                      target_fps=target_fps if (not anonymize and target_fps and target_fps < fps) else None)
        result_name = (f"nvr-{dvr_id}-kamera-{channel}-{selection_start:%Y-%m-%d_%H-%M-%S}_"
                       f"{selection_end:%H-%M-%S}.{output_format}")
        return folder, result, result_name
    except Exception:
        shutil.rmtree(folder, ignore_errors=True)
        raise


@app.get("/api/recordings/download")
def download_recording(
    dvr_id: int, channel: int, date: str, filename: str | None = None,
    start_time: str | None = None, end_time: str | None = None,
    format: Literal["avi", "mp4"] = "avi",
    quality: Literal["original", "1080p", "720p", "480p"] = "original",
    fps: Literal["original", "15", "10"] = "original",
    anonymize: bool = False,
):
    return prepare_recording(dvr_id, channel, date, filename, start_time, end_time, False,
                             output_format=format, quality=quality, fps_choice=fps, anonymize=anonymize)


@app.post("/api/download-jobs")
def create_download_job(payload: DownloadJobRequest, request: Request):
    owner_id = download_owner(request)
    if payload.channel < 1:
        raise HTTPException(status_code=422, detail="Numer kanału musi być dodatni.")
    start_time, end_time = validate_recording_request(payload.date, payload.filename,
                                                       payload.start_time, payload.end_time)
    with sqlite3.connect("data/dvrs.db") as conn:
        dvr = conn.execute("SELECT name FROM dvrs WHERE id = ?", (payload.dvr_id,)).fetchone()
        if not dvr:
            raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora.")
        channel_row = conn.execute("SELECT name FROM channels WHERE dvr_id = ? AND channel_number = ?",
                                   (payload.dvr_id, payload.channel)).fetchone()
        camera_name = (channel_row[0] if channel_row and channel_row[0]
                       else f"Kamera {payload.channel}")
        job_id, created = uuid4().hex, time_module.time()
        conn.execute('''INSERT INTO download_jobs
                     (id, owner_id, created_at, dvr_id, dvr_name, channel, camera_name, recording_date,
                      start_time, end_time, filename, output_format, quality, fps, anonymized, status, stage, progress)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'Oczekuje w kolejce', 0)''',
                     (job_id, owner_id, created, payload.dvr_id, dvr[0], payload.channel, camera_name,
                      payload.date, start_time, end_time, payload.filename, payload.format, payload.quality,
                      payload.fps, int(payload.anonymize)))
    download_jobs.enqueue(job_id)
    return {"id": job_id, "status": "queued"}


def load_owned_job(job_id: str, owner_id: str):
    columns = ("id, created_at, started_at, finished_at, dvr_id, dvr_name, channel, camera_name, recording_date, "
               "start_time, end_time, filename, output_format, quality, fps, anonymized, status, stage, progress, "
               "result_name, error, duration_seconds")
    with sqlite3.connect("data/dvrs.db") as conn:
        row = conn.execute(f"SELECT {columns} FROM download_jobs WHERE id = ? AND owner_id = ?", (job_id, owner_id)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono zadania pobrania.")
    return row


@app.get("/api/download-jobs")
def list_download_jobs(request: Request):
    owner_id = download_owner(request)
    columns = ("id, created_at, started_at, finished_at, dvr_id, dvr_name, channel, camera_name, recording_date, "
               "start_time, end_time, filename, output_format, quality, fps, anonymized, status, stage, progress, "
               "result_name, error, duration_seconds")
    with sqlite3.connect("data/dvrs.db") as conn:
        rows = conn.execute(f"SELECT {columns} FROM download_jobs WHERE owner_id = ? ORDER BY created_at DESC LIMIT 100", (owner_id,)).fetchall()
        average_row = conn.execute("SELECT AVG(duration_seconds) FROM download_jobs WHERE status = 'ready' AND duration_seconds > 0").fetchone()
        active_count = conn.execute("SELECT COUNT(*) FROM download_jobs WHERE status = 'processing'").fetchone()[0]
    average = max(30, round(average_row[0] or 90))
    jobs = [job_row(row) for row in rows]
    for job in jobs:
        if job["status"] == "queued":
            with sqlite3.connect("data/dvrs.db") as conn:
                before = conn.execute("SELECT COUNT(*) FROM download_jobs WHERE status = 'queued' AND created_at < ?", (job["created_at"],)).fetchone()[0]
            job["queue_position"] = before + 1
            job["eta_seconds"] = max(0, (before + max(0, active_count - ARCHIVE_JOB_LIMIT + 1)) * average)
        elif job["status"] == "processing":
            job["eta_seconds"] = max(0, average - job["elapsed_seconds"])
    return {"jobs": jobs, "concurrency": ARCHIVE_JOB_LIMIT}


@app.get("/api/download-jobs/{job_id}/file")
def download_job_file(job_id: str, request: Request):
    owner_id = download_owner(request)
    with sqlite3.connect("data/dvrs.db") as conn:
        row = conn.execute("SELECT status, result_path, result_name FROM download_jobs WHERE id = ? AND owner_id = ?",
                           (job_id, owner_id)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono zadania pobrania.")
    status, result_path, result_name = row
    if status != "ready" or not result_path or not Path(result_path).is_file():
        raise HTTPException(status_code=409, detail="Plik nie jest jeszcze gotowy.")
    return FileResponse(result_path, filename=result_name, media_type="application/octet-stream",
                        headers={"Cache-Control": "no-store"})


@app.post("/api/download-jobs/{job_id}/cancel")
def cancel_download_job(job_id: str, request: Request):
    owner_id = download_owner(request)
    with sqlite3.connect("data/dvrs.db") as conn:
        row = conn.execute("SELECT owner_id, status FROM download_jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono zadania pobrania.")
    if row[0] != owner_id and not is_admin(request):
        raise HTTPException(status_code=403, detail="Brak uprawnień do anulowania tego zadania.")
    if row[1] in ("ready", "failed", "cancelled"):
        return {"status": row[1], "message": "Zadanie już zakończone."}
    download_jobs.cancel(job_id)
    return {"status": "cancelling", "id": job_id}


@app.get("/api/recordings/preview")
def preview_recording(
    dvr_id: int, channel: int, date: str, filename: str | None = None,
    start_time: str | None = None, end_time: str | None = None,
):
    return prepare_recording(dvr_id, channel, date, filename, start_time, end_time, True)
