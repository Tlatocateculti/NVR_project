from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
from starlette.background import BackgroundTask
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from dvrip import DVRIPCam
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
import urllib.request
import urllib.parse
import urllib.error
import subprocess
import tempfile
import hashlib
import sqlite3
import secrets
import base64
import struct
import json
import re
import os

app = FastAPI()
templates = Jinja2Templates(directory="templates")

GO2RTC_API = "http://go2rtc:1984"

os.makedirs("data", exist_ok=True)


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

    online_map: dict[int, bool] = {}
    status_root = tdk_send_command(nvr.ip, nvr.user, nvr.password, "get.channelmanagement.status")
    if status_root is not None:
        for ch_st in status_root.findall(".//channel"):
            cid = ch_st.findtext("id")
            conn_state = (ch_st.findtext(".//connection") or "").strip().lower()
            if cid and cid.isdigit():
                online_map[int(cid)] = (conn_state == "connected")

    channels = []
    for idx, ch_el in enumerate(root.findall(".//ch")):
        id_text = ch_el.findtext("id")
        name_text = ch_el.findtext("name")
        ch_num = int(id_text) if id_text and id_text.isdigit() else (idx + 1)
        ch_name = (name_text or "").strip() or f"Kanał {ch_num}"
        if ch_num in online_map and not online_map[ch_num]:
            ch_name = f"{ch_name} [offline]"
        channels.append({"channel_number": ch_num, "name": ch_name})

    return channels


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
        rtsp_raw = f"rtsp://{u_enc}:{p_enc}@{ip}:554/mode=real&idc={channel}&ids=1"
        params.append(("src", f"ffmpeg:{rtsp_raw}#video=h264"))

    query = urllib.parse.urlencode(params)
    put_req = urllib.request.Request(f"{GO2RTC_API}/api/streams?{query}", method="PUT")
    urllib.request.urlopen(put_req, timeout=5.0).read()
    return stream_name


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/dvrs")
async def get_dvrs():
    conn = sqlite3.connect('data/dvrs.db')
    c = conn.cursor()
    c.execute("SELECT id, name, ip, port, user, password FROM dvrs")
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
            "user": r[4],
            "password": r[5],
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
async def start_webrtc_session(offer: WebRTCOffer, request: Request):
    """Rejestruje strumień RTSP (#media=video) w go2rtc i zwraca SDP Answer z lokalnym kandydatem ICE."""
    try:
        stream_name = ensure_go2rtc_stream(offer.dvr_id, offer.channel, offer.stream)

        w_req = urllib.request.Request(
            f"{GO2RTC_API}/api/webrtc?src={urllib.parse.quote(stream_name)}",
            data=offer.sdp.encode("utf-8"),
            headers={"Content-Type": "application/sdp"},
            method="POST",
        )
        with urllib.request.urlopen(w_req, timeout=15.0) as w_resp:
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
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=502, detail=f"Błąd go2rtc ({e.code}): {err_body}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Błąd połączenia z go2rtc: {str(e)}")


@app.get("/api/stream.mp4")
def proxy_mp4_stream(dvr_id: int, channel: int, stream: int = 2):
    """Strumień fMP4 (MSE/HTTP) z go2rtc jako niezawodny fallback."""
    stream_name = ensure_go2rtc_stream(dvr_id, channel, stream)
    url = f"{GO2RTC_API}/api/stream.mp4?src={urllib.parse.quote(stream_name)}"

    def iter_chunks():
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15.0) as resp:
            while True:
                chunk = resp.read(16384)
                if not chunk:
                    break
                yield chunk

    return StreamingResponse(iter_chunks(), media_type="video/mp4")


def cleanup_temp_file(path: str):
    """Usuwa plik tymczasowy po wysłaniu do klienta."""
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def get_recording_dvr(dvr_id: int) -> tuple[str, str, str, str]:
    """Zwraca dane połączenia do NVR, nie wystawiając hasła poza proces."""
    conn = sqlite3.connect("data/dvrs.db")
    try:
        row = conn.execute(
            "SELECT name, ip, user, password FROM dvrs WHERE id = ?", (dvr_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora w bazie.")
    return row


def validate_recording_request(date: str, filename: str | None, start_time: str | None, end_time: str | None) -> tuple[str, str]:
    """Waliduje zakres, zanim zostanie przekazany do serwera RTSP NVR."""
    try:
        datetime.strptime(date, "%Y-%m-%d")
        start = datetime.strptime(start_time or "00:00:00", "%H:%M:%S")
        end = datetime.strptime(end_time or "23:59:59", "%H:%M:%S")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Nieprawidłowy format daty lub godziny nagrania.") from exc
    if end <= start:
        raise HTTPException(status_code=422, detail="Koniec nagrania musi być późniejszy niż początek.")
    if filename and ("/" in filename or "\\" in filename or ".." in filename):
        raise HTTPException(status_code=422, detail="Nieprawidłowa nazwa pliku nagrania.")
    return start.strftime("%H:%M:%S"), end.strftime("%H:%M:%S")


def recording_rtsp_url(ip: str, user: str, password: str, channel: int, date: str, start_time: str, end_time: str) -> str:
    """Adres archiwum RTSP Qualvision/TDK.

    Ten model NVR używa tej samej ścieżki RTSP co podgląd na żywo, z trybem
    ``playback`` i granicami czasu.  Dane logowania są kodowane, więc znaki
    takie jak ``@`` albo ``#`` w haśle nie zmieniają składni URL-a.
    """
    q_user = urllib.parse.quote(user, safe="")
    q_password = urllib.parse.quote(password, safe="")
    start = f"{date}T{start_time}Z"
    end = f"{date}T{end_time}Z"
    params = urllib.parse.urlencode({
        "idc": channel,
        "ids": 1,
        "starttime": start,
        "endtime": end,
    })
    return f"rtsp://{q_user}:{q_password}@{ip}:554/mode=playback&{params}"


def redact_url(text: str) -> str:
    """Nie umieszczaj poświadczeń NVR w odpowiedzi błędu lub logu API."""
    return re.sub(r"(rtsp://[^:/@]+:)[^@]+@", r"\1***@", text)


def materialize_recording(
    source_url: str,
    output_path: str,
    output_format: str,
    max_seconds: int,
) -> None:
    """Pobiera materiał z archiwum NVR przez ffmpeg; nigdy nie tworzy atrapy."""
    common = [
        "ffmpeg", "-y", "-nostdin", "-rtsp_transport", "tcp",
        "-i", source_url, "-map", "0:v:0?", "-map", "0:a?", "-t", str(max_seconds),
    ]
    if output_format == "avi":
        cmd = common + ["-c", "copy", "-f", "avi", output_path]
    else:
        # NVR zwraca HEVC na części kanałów; H.264 + yuv420p działa w HTML5
        # także w przeglądarkach bez sprzętowego dekodera HEVC.
        cmd = common + [
            "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-movflags", "+faststart", "-f", "mp4", output_path,
        ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_seconds + 90)
    except subprocess.TimeoutExpired as exc:
        cleanup_temp_file(output_path)
        raise HTTPException(status_code=504, detail="Przekroczono czas pobierania nagrania z rejestratora.") from exc
    if proc.returncode != 0 or not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        cleanup_temp_file(output_path)
        diagnostic = redact_url((proc.stderr or "").strip().splitlines()[-1] if proc.stderr else "brak danych")
        raise HTTPException(status_code=502, detail=f"NVR nie udostępnił wskazanego nagrania ({diagnostic}).")


@app.get("/api/recordings/days")
async def get_recording_days(dvr_id: int, channel: int, year: int, month: int):
    """Zwraca listę dni w podanym miesiącu i roku, dla których na danym kanale istnieją nagrania."""
    conn = sqlite3.connect("data/dvrs.db")
    c = conn.cursor()
    c.execute("SELECT ip, user, password FROM dvrs WHERE id = ?", (dvr_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rejestratora w bazie.")

    ip, user, password = row
    channel_mask = 1 << (channel - 1)
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
async def get_recording_files(dvr_id: int, channel: int, date: str):
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


@app.get("/api/recordings/download")
async def download_recording(
    dvr_id: int,
    channel: int,
    date: str,
    filename: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
):
    """Pobiera rzeczywiste nagranie NVR jako AVI dla pliku lub przedziału czasu."""
    if channel < 1:
        raise HTTPException(status_code=422, detail="Numer kanału musi być dodatni.")
    dvr_name, ip, user, password = get_recording_dvr(dvr_id)
    start, end = validate_recording_request(date, filename, start_time, end_time)
    s_clean = start.replace(":", "-")
    e_clean = end.replace(":", "-")
    safe_dvr = re.sub(r"[^\w\-]", "_", dvr_name)
    download_filename = f"nagranie_{safe_dvr}_kan{channel}_{date}_{s_clean}-{e_clean}.avi"

    tf = tempfile.NamedTemporaryFile(suffix=".avi", delete=False)
    out_path = tf.name
    tf.close()
    max_seconds = int((datetime.strptime(end, "%H:%M:%S") - datetime.strptime(start, "%H:%M:%S")).total_seconds())
    materialize_recording(recording_rtsp_url(ip, user, password, channel, date, start, end), out_path, "avi", max_seconds)

    return FileResponse(
        out_path,
        media_type="video/x-msvideo",
        filename=download_filename,
        background=BackgroundTask(cleanup_temp_file, out_path),
    )


@app.get("/api/recordings/preview")
async def preview_recording(
    dvr_id: int,
    channel: int,
    date: str,
    filename: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
):
    """Zwraca rzeczywisty materiał archiwalny jako zgodny z HTML5 plik MP4."""
    if channel < 1:
        raise HTTPException(status_code=422, detail="Numer kanału musi być dodatni.")
    _, ip, user, password = get_recording_dvr(dvr_id)
    start, end = validate_recording_request(date, filename, start_time, end_time)

    tf = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
    out_path = tf.name
    tf.close()

    max_seconds = int((datetime.strptime(end, "%H:%M:%S") - datetime.strptime(start, "%H:%M:%S")).total_seconds())
    materialize_recording(recording_rtsp_url(ip, user, password, channel, date, start, end), out_path, "mp4", max_seconds)

    return FileResponse(
        out_path,
        media_type="video/mp4",
        background=BackgroundTask(cleanup_temp_file, out_path),
    )
