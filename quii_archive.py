"""Qualvision archive transport verified against a real uCMS download.

The HTTP search filename is kept intact. Its fields identify the recording in
the binary file request; credentials and packet payloads must never be logged.
"""
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque
from statistics import median
import os
import select
import shutil
import socket
import struct
import subprocess
import time


class ArchiveError(Exception):
    pass


@dataclass(frozen=True)
class Recording:
    raw_filename: str
    channel: int
    start: datetime
    end: datetime
    stream: int
    file_id: int
    flags: int

    @classmethod
    def parse(cls, raw_filename: str):
        parts = raw_filename.split("_")
        try:
            if len(parts) != 11 or len(raw_filename) > 512:
                raise ValueError
            numeric = [int(parts[i]) for i in (0, 2, 3, 4, 5, 6, 7, 8, 9, 10)]
            channel, duration, stream, _, file_id, _, flags, _, _, _ = numeric
            start = datetime.strptime(parts[1], "%Y-%m-%d-%H-%M-%S")
            if not (0 <= channel < 255 and 0 < duration <= 172800
                    and 0 <= stream <= 255 and 0 <= file_id <= 0xffffffff
                    and 0 <= flags <= 255):
                raise ValueError
            return cls(raw_filename, channel + 1, start,
                       start + timedelta(seconds=duration), stream, file_id, flags)
        except (ValueError, OverflowError) as exc:
            raise ArchiveError("Nieobsługiwane metadane pliku archiwalnego.") from exc


def packed_time(value: datetime) -> int:
    if not 2000 <= value.year <= 2063:
        raise ArchiveError("Data poza zakresem protokołu archiwum.")
    return ((value.year - 2000) << 26 | value.month << 22 | value.day << 17
            | value.hour << 12 | value.minute << 6 | value.second)


def frame_time(payload):
    value = struct.unpack_from("<I", payload, 8)[0]
    milliseconds = struct.unpack_from("<H", payload, 12)[0]
    try:
        if milliseconds > 999:
            raise ValueError
        return datetime(2000 + (value >> 26), (value >> 22) & 15,
                        (value >> 17) & 31, (value >> 12) & 31,
                        (value >> 6) & 63, value & 63, milliseconds * 1000)
    except ValueError as exc:
        raise ArchiveError("Nieprawidłowy znacznik czasu ramki archiwum.") from exc


def read_exact(connection, count):
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ArchiveError("Rejestrator przerwał transfer przed jego zakończeniem.")
        result.extend(chunk)
    return bytes(result)


def control_packet(command, channel=0):
    result = bytearray(32)
    result[0] = command
    struct.pack_into("<I", result, 8, channel)
    return result


def read_reply(connection):
    header = read_exact(connection, 32)
    length = struct.unpack_from("<I", header, 4)[0]
    if length > 2 * 1024 * 1024:
        raise ArchiveError("Nieprawidłowa długość odpowiedzi rejestratora.")
    return header, read_exact(connection, length)


def archive_frames(ip, port, user, password, recording, start, end):
    """Yield verified media records. An explicit terminal record marks success."""
    if end <= start or start < recording.start or end > recording.end:
        raise ArchiveError("Zakres wykracza poza wybrany plik archiwalny.")
    auth_body = (user + "&&" + password).encode("utf-8") + b"\0"
    auth_body += b"\0" * ((-len(auth_body)) % 16)
    if len(auth_body) > 1024:
        raise ArchiveError("Dane logowania przekraczają limit protokołu.")
    auth = bytearray.fromhex(
        "0a01015000000000ff433030323300000000000000000000040100000000a1aa"
    )
    struct.pack_into("<I", auth, 4, len(auth_body))
    with ExitStack() as stack:
        control = stack.enter_context(socket.create_connection((ip, port), timeout=15))
        control.sendall(auth + auth_body)
        reply, _ = read_reply(control)
        session = struct.unpack_from("<I", reply, 16)[0]
        if reply[0] != 0xb0 or reply[8] != 0 or session == 0:
            raise ArchiveError("Rejestrator odrzucił logowanie do archiwum.")
        auth[0] = 0xa0
        control.sendall(auth + auth_body)
        config = control_packet(0xa4, 26)
        config[2] = 1
        control.sendall(config)
        for _ in range(128):
            reply, _ = read_reply(control)
            if reply[0] == 0xb4:
                break
            if reply[0] != 0x73:  # asynchronous channel-status notifications
                raise ArchiveError("Rejestrator nie potwierdził sesji archiwum.")
        else:
            raise ArchiveError("Brak potwierdzenia sesji archiwum.")
        data = stack.enter_context(socket.create_connection((ip, port), timeout=20))
        attach = control_packet(0xf1, session)
        attach[12:14] = b"\x02\x11"
        data.sendall(attach)
        mode = control_packet(0xc9, recording.channel)
        mode[22:24] = b"\x05\x01"
        control.sendall(mode)
        # The data connection is attached asynchronously. Starting C2 before
        # F3 can race the attach on older recorders, producing an idle or
        # misaligned data stream. Wait for the device's explicit confirmation.
        for _ in range(128):
            reply, _ = read_reply(control)
            if reply[0] == 0xf3:
                break
            if reply[0] != 0x73:
                raise ArchiveError("Rejestrator nie potwierdził połączenia danych archiwum.")
        else:
            raise ArchiveError("Brak potwierdzenia połączenia danych archiwum.")
        request = control_packet(0xc2)
        request[8] = recording.channel
        struct.pack_into("<H", request, 9, start.year)
        request[11:16] = bytes((start.month, start.day, start.hour, start.minute, start.second))
        request[16] = recording.stream
        struct.pack_into("<I", request, 17, recording.file_id)
        request[21] = recording.flags
        request[22:24] = b"\x05\x01"
        request[27] = 1
        struct.pack_into("<I", request, 28, packed_time(end))
        control.sendall(request)
        deadline = time.monotonic() + int(os.environ.get("ARCHIVE_TRANSFER_TIMEOUT", "900"))
        while True:
            if time.monotonic() > deadline:
                raise ArchiveError("Przekroczono limit czasu pobierania archiwum.")
            header = read_exact(data, 32)
            if header[:4] != b"\xbb\x11\xee\0":
                raise ArchiveError("Nieprawidłowy nagłówek danych archiwum.")
            if header[8] != recording.channel:
                raise ArchiveError("Rejestrator zwrócił dane innej kamery.")
            length = struct.unpack_from("<I", header, 4)[0]
            if length == 0 and header[15] == 0x12:
                return
            if not 0 < length <= 16 * 1024 * 1024:
                raise ArchiveError("Nieprawidłowa długość ramki archiwum.")
            payload = read_exact(data, length)
            ack = control_packet(0x68, recording.channel)
            sequence = struct.unpack_from("<I", header, 8)[0] >> 8
            struct.pack_into("<I", ack, 12, sequence + 1)
            control.sendall(ack)
            while select.select([control], [], [], 0)[0]:
                if not control.recv(65536):
                    raise ArchiveError("Zamknięto sesję sterującą archiwum.")
            yield payload


def save_video(ip, port, user, password, selections, target: Path):
    """Remove the vendor envelope, preserving real H.264/HEVC video bytes."""
    codec = nominal_fps = None
    count = total = 0
    duration = 0.0
    limit = int(os.environ.get("ARCHIVE_MAX_BYTES", str(4 * 1024**3)))
    with target.open("wb") as output:
        for recording, start, end in selections:
            have_keyframe = False
            first_timestamp = last_timestamp = None
            intervals = deque(maxlen=256)
            segment_count = 0
            for payload in archive_frames(ip, port, user, password, recording, start, end):
                # E0/E1 are the inter/key video frames observed in uCMS.
                # Other media types (including audio) are not repackaged yet.
                if len(payload) < 24 or payload[:3] != b"\0\0\x01" or payload[3] not in (0xe0, 0xe1):
                    continue
                size = struct.unpack_from("<I", payload, 4)[0]
                if size != len(payload) - 20:
                    raise ArchiveError("Niekompletna ramka obrazu w archiwum.")
                timestamp = frame_time(payload)
                if timestamp < start or timestamp >= end:
                    continue
                if payload[3] == 0xe1:
                    have_keyframe = True
                if not have_keyframe:
                    continue
                frame_codec = {1: "h264", 2: "hevc"}.get(payload[14])
                if frame_codec is None:
                    raise ArchiveError("Nieobsługiwany kodek archiwum.")
                if codec is not None and codec != frame_codec:
                    raise ArchiveError("W nagraniu zmienił się kodek obrazu. Wybierz krótszy zakres.")
                codec = frame_codec
                # This byte is a varying rate estimate on some NVRs (e.g.
                # 67/68 on recorder 103), not a fixed format identifier.
                # Derive the AVI/MP4 average frame rate from source timestamps.
                if 1 <= payload[15] / 4 <= 120:
                    nominal_fps = payload[15] / 4
                if first_timestamp is None:
                    first_timestamp = timestamp
                if last_timestamp is not None:
                    delta = (timestamp - last_timestamp).total_seconds()
                    if delta > 0:
                        intervals.append(delta)
                last_timestamp = timestamp
                segment_count += 1
                total += size
                if total > limit:
                    raise ArchiveError("Nagranie przekracza limit rozmiaru. Wybierz krótszy zakres.")
                output.write(payload[20:])
                count += 1
            if segment_count:
                frame_duration = median(intervals) if intervals else (
                    1 / nominal_fps if nominal_fps else None)
                if frame_duration is None:
                    raise ArchiveError("Brak znaczników tempa obrazu w archiwum.")
                duration += (last_timestamp - first_timestamp).total_seconds() + frame_duration
    if count == 0:
        raise ArchiveError("Brak obrazu w wybranym zakresie archiwum.")
    if duration <= 0:
        raise ArchiveError("Nieprawidłowy czas trwania obrazu w archiwum.")
    return codec, count / duration, count


def convert_video(source: Path, target: Path, codec, fps, preview=False, quality="original"):
    if quality not in ("original", "1080p", "720p", "480p"):
        raise ArchiveError("Nieprawidłowy profil jakości nagrania.")
    binary = os.environ.get("FFMPEG_BIN") or shutil.which("ffmpeg")
    if not binary:
        raise ArchiveError("Brak FFmpeg na serwerze. Zainstaluj FFmpeg lub ustaw FFMPEG_BIN.")
    arguments = [binary, "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
                 "-r", str(fps), "-f", codec, "-i", str(source), "-an"]
    if preview or quality != "original":
        height = 720 if preview else {"1080p": 1080, "720p": 720, "480p": 480}[quality]
        arguments += ["-vf", f"scale=w=-2:h='min({height},ih)'", "-c:v", "libx264",
                      "-preset", "veryfast", "-crf", "24" if preview else "20",
                      "-pix_fmt", "yuv420p"]
    else:
        arguments += ["-c:v", "copy"]
        if codec == "hevc" and target.suffix.lower() == ".avi":
            arguments += ["-tag:v", "HEVC"]
        elif codec == "hevc" and target.suffix.lower() == ".mp4":
            arguments += ["-tag:v", "hvc1"]
    if target.suffix.lower() == ".mp4":
        arguments += ["-movflags", "+faststart"]
    arguments += [str(target)]
    try:
        result = subprocess.run(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                timeout=600 if preview or quality == "original" else
                                int(os.environ.get("ARCHIVE_CONVERT_TIMEOUT", "3600")), check=False)
    except subprocess.TimeoutExpired as exc:
        raise ArchiveError("Przekroczono czas konwersji nagrania.") from exc
    if result.returncode or not target.exists() or target.stat().st_size == 0:
        raise ArchiveError("FFmpeg nie zdołał przetworzyć rzeczywistego nagrania.")
