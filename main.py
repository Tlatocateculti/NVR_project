from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse, RedirectResponse
from starlette.background import BackgroundTask
from starlette.middleware.sessions import SessionMiddleware
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Literal
from threading import BoundedSemaphore, Lock
import shutil
import tempfile
import logging
import mimetypes
from quii_archive import ArchiveError, Recording, save_video, convert_video
from local_runtime import LocalRelay
from live_proxy import open_mp4_proxy
from auth import callback_url, oauth, settings as auth_settings
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dvrip import DVRIPCam
from datetime import datetime, timedelta
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

@asynccontextmanager
async def app_lifespan(app):
    local_relay.start()
    try:
        yield
    finally:
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
STREAM_COLOR_NORMALIZATION: dict[str, bool] = {}

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


class WebRTCOffer(BaseModel):
    dvr_id: int
    channel: int
    sdp: str
    stream: int = 2  # 2 = Substream (zapasowy), 1 = Mainstream (HQ)


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
                 (id INTEGER PRIMARY KEY, name TEXT, ip TEXT, port INTEGER, user TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS channels
                 (id INTEGER PRIMARY KEY,
                  dvr_id INTEGER,
                  channel_number INTEGER,
                  name TEXT,
                  FOREIGN KEY(dvr_id) REFERENCES dvrs(id) ON DELETE CASCADE)''')
    # Connection state is transient and must never be persisted as part of a
    # channel name. Remove labels written by older versions of the application.
    c.execute("UPDATE channels SET name = REPLACE(name, ' [offline]', '') WHERE name LIKE '% [offline]'")
    conn.commit()
    conn.close()


init_db()


def fetch_nvr_channels(nvr: NVR) -> list[dict]:
    """Pobiera listę kanałów i ich nazwy (obsługuje NVR Qualvision/TDK oraz Xiongmai NETIP)."""
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
    u_enc = urllib.parse.quote(user, safe="")
    p_enc = urllib.parse.quote(password, safe="")

    stream_id = stream if stream in (1, 2) else 2
    rtsp_qv = f"rtsp://{u_enc}:{p_enc}@{ip}:554/mode=real&idc={channel}&ids={stream_id}#media=video"

    stream_name = f"nvr_{dvr_id}_ch_{channel}_s_{stream_id}"
    params = [("name", stream_name), ("src", rtsp_qv)]
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


def stream_needs_color_normalization(stream_name: str) -> bool:
    """Detect broken H.264 VUI colour metadata once per active stream."""
    cached = STREAM_COLOR_NORMALIZATION.get(stream_name)
    if cached is not None:
        return cached

    ffprobe = os.environ.get("FFPROBE_BIN") or shutil.which("ffprobe")
    if not ffprobe:
        STREAM_COLOR_NORMALIZATION[stream_name] = False
        return False

    source = f"{GO2RTC_RTSP}/{urllib.parse.quote(stream_name)}?video=h264"
    try:
        probe = subprocess.run(
            [
                ffprobe, "-v", "error", "-rtsp_transport", "tcp", "-timeout", "8000000",
                "-show_entries", "stream=color_space,color_transfer,color_primaries",
                "-of", "default=noprint_wrappers=1", source,
            ],
            capture_output=True, text=True, timeout=12, check=False,
        )
        details = dict(
            line.split("=", 1) for line in probe.stdout.splitlines() if "=" in line
        )
        normalize = (
            details.get("color_space") == "gbr"
            or details.get("color_transfer") == "reserved"
            or details.get("color_primaries") == "reserved"
        )
    except (OSError, subprocess.TimeoutExpired):
        normalize = False
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
async def get_dvrs():
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
async def get_dvr_channels(dvr_id: int):
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
async def get_dvr_channel_status():
    """Return the current NVR-reported state; it is never persisted."""
    conn = sqlite3.connect("data/dvrs.db")
    try:
        rows = conn.execute("SELECT id, ip, port, user, password FROM dvrs").fetchall()
    finally:
        conn.close()

    result: dict[str, dict[str, bool]] = {}
    for dvr_id, ip, port, user, password in rows:
        statuses = fetch_tdkcgi_channel_status(
            NVR(name="", ip=ip, port=port, user=user, password=password)
        )
        if statuses is not None:
            result[str(dvr_id)] = {str(channel): online for channel, online in statuses.items()}
    return {"channels": result}


@app.post("/api/dvrs/test")
async def test_dvr_connection(nvr: NVR):
    channels = fetch_nvr_channels(nvr)
    return {"status": "ok", "channels_count": len(channels), "channels": channels}


@app.post("/api/dvrs")
async def add_dvr(nvr: NVR):
    channels = fetch_nvr_channels(nvr)

    conn = sqlite3.connect('data/dvrs.db')
    c = conn.cursor()
    c.execute(
        "INSERT INTO dvrs (name, ip, port, user, password) VALUES (?, ?, ?, ?, ?)",
        (nvr.name, nvr.ip, nvr.port, nvr.user, nvr.password)
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


@app.get("/api/stream.mp4")
def proxy_mp4_stream(dvr_id: int, channel: int, stream: int = 2):
    """Copy H.264 from the relay into fMP4 without its HTTP MP4 consumer."""
    stream_name = ensure_go2rtc_stream(dvr_id, channel, stream)
    binary = os.environ.get("FFMPEG_BIN") or shutil.which("ffmpeg")
    if not binary:
        raise HTTPException(status_code=503, detail="Brak FFmpeg do podglądu obrazu.")
    source = f"{GO2RTC_RTSP}/{urllib.parse.quote(stream_name)}?video=h264"
    try:
        proxy = open_mp4_proxy(binary, source, stream_needs_color_normalization(stream_name))
    except OSError as exc:
        raise HTTPException(status_code=502, detail="Nie udało się odebrać obrazu z przekaźnika.") from exc
    return StreamingResponse(proxy.chunks(), media_type="video/mp4",
                             background=BackgroundTask(proxy.close))


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
    if filename:
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
    c.execute("SELECT ip, user, password FROM dvrs WHERE id = ?", (dvr_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora w bazie.")

    ip, user, password = row
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
    c.execute("SELECT ip, user, password FROM dvrs WHERE id = ?", (dvr_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora w bazie.")

    ip, user, password = row
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


ARCHIVE_JOBS = BoundedSemaphore(2)


def prepare_recording(dvr_id, channel, date, filename, start_time, end_time, preview,
                      output_format="avi", quality="original"):
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
        suffix = "mp4" if preview else output_format
        result = folder / f"recording.{suffix}"
        convert_video(source, result, codec, fps, preview=preview, quality=quality)
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


@app.get("/api/recordings/download")
def download_recording(
    dvr_id: int, channel: int, date: str, filename: str | None = None,
    start_time: str | None = None, end_time: str | None = None,
    format: Literal["avi", "mp4"] = "avi",
    quality: Literal["original", "1080p", "720p", "480p"] = "original",
):
    return prepare_recording(dvr_id, channel, date, filename, start_time, end_time, False,
                             output_format=format, quality=quality)


@app.get("/api/recordings/preview")
def preview_recording(
    dvr_id: int, channel: int, date: str, filename: str | None = None,
    start_time: str | None = None, end_time: str | None = None,
):
    return prepare_recording(dvr_id, channel, date, filename, start_time, end_time, True)
