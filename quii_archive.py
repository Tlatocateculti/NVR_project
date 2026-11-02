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


def anonymize_worker_count() -> int:
    """Choose a safe OpenCV worker count for this host/container.

    Archive preparation permits two simultaneous jobs, so each job gets half
    of the CPUs assigned to this process. Eight workers is the useful ceiling
    for the small YuNet inference batches; more threads add scheduling cost.
    A numeric ARCHIVE_ANONYMIZE_THREADS explicitly overrides auto-selection.
    """
    configured = os.environ.get("ARCHIVE_ANONYMIZE_THREADS", "auto").strip().lower()
    if configured != "auto":
        try:
            return max(1, min(int(configured), os.cpu_count() or 1))
        except ValueError:
            pass
    try:
        available = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        available = os.cpu_count() or 1
    concurrent_jobs = max(1, int(os.environ.get("ARCHIVE_MAX_CONCURRENT_JOBS", "2")))
    return max(1, min(8, (available + concurrent_jobs - 1) // concurrent_jobs))


def openvino_yolo_head_detector(model: Path, cv2, np):
    """Return a YOLOv8 head detector using OpenVINO CPU inference, or None."""
    if not model.exists():
        return None
    try:
        from openvino import Core
        compiled = Core().compile_model(str(model), "CPU")
        input_layer, output_layer = compiled.input(0), compiled.output(0)
    except Exception:
        return None

    def detect(frame, conf_threshold=0.20):
        height, width = frame.shape[:2]
        tile_size, tile_step = 640, 512
        x_starts = list(range(0, max(1, width - tile_size + 1), tile_step))
        y_starts = list(range(0, max(1, height - tile_size + 1), tile_step))
        if x_starts[-1] != max(0, width - tile_size):
            x_starts.append(max(0, width - tile_size))
        if y_starts[-1] != max(0, height - tile_size):
            y_starts.append(max(0, height - tile_size))

        boxes, scores = [], []
        for top in y_starts:
            for left in x_starts:
                tile = frame[top:min(height, top + tile_size), left:min(width, left + tile_size)]
                tile_height, tile_width = tile.shape[:2]
                if tile_height != 640 or tile_width != 640:
                    padded = np.zeros((640, 640, 3), dtype=tile.dtype)
                    padded[:tile_height, :tile_width] = tile
                    tile = padded
                blob = np.ascontiguousarray((tile.astype(np.float32) / 255.0).transpose(2, 0, 1)[None])
                preds = compiled({input_layer: blob})[output_layer][0].T
                for cx, cy, bw, bh, conf in preds:
                    if conf >= conf_threshold and 0 <= cx < tile_width and 0 <= cy < tile_height:
                        bx = max(0, int(left + cx - bw / 2))
                        by = max(0, int(top + cy - bh / 2))
                        bw_i = min(width - bx, int(bw))
                        bh_i = min(height - by, int(bh))
                        if bw_i >= 10 and bh_i >= 10:
                            boxes.append([bx, by, bw_i, bh_i])
                            scores.append(float(conf))
        kept = cv2.dnn.NMSBoxes(boxes, scores, conf_threshold, 0.40) if boxes else []
        return [(boxes[int(i)], scores[int(i)]) for i in (kept.flatten() if len(kept) > 0 else [])]

    return detect


def openvino_face_detector(model: Path, cv2, np):
    """Return Intel Open Model Zoo face detection, or ``None`` if unavailable."""
    if not model.exists() or not model.with_suffix(".bin").exists():
        return None
    try:
        from openvino import Core
        compiled = Core().compile_model(str(model), "CPU")
        input_layer, output_layer = compiled.input(0), compiled.output(0)
        _, _, input_height, input_width = (int(value) for value in input_layer.shape)
    except Exception:
        return None

    def detect(frame, conf_threshold=0.30):
        height, width = frame.shape[:2]
        tile_size, tile_step = 640, 512
        x_starts = list(range(0, max(1, width - tile_size + 1), tile_step))
        y_starts = list(range(0, max(1, height - tile_size + 1), tile_step))
        if x_starts[-1] != max(0, width - tile_size):
            x_starts.append(max(0, width - tile_size))
        if y_starts[-1] != max(0, height - tile_size):
            y_starts.append(max(0, height - tile_size))
        boxes, scores = [], []
        for top in y_starts:
            for left in x_starts:
                tile = frame[top:min(height, top + tile_size), left:min(width, left + tile_size)]
                tile_height, tile_width = tile.shape[:2]
                resized = cv2.resize(tile, (input_width, input_height))
                blob = np.ascontiguousarray(resized.transpose(2, 0, 1)[None])
                result = compiled({input_layer: blob})[output_layer].reshape(-1, 7)
                for _, _, confidence, x1, y1, x2, y2 in result:
                    if confidence < conf_threshold:
                        continue
                    x1, y1 = left + max(0, x1 * tile_width), top + max(0, y1 * tile_height)
                    x2, y2 = left + min(tile_width, x2 * tile_width), top + min(tile_height, y2 * tile_height)
                    if x2 - x1 >= 10 and y2 - y1 >= 10:
                        boxes.append([int(x1), int(y1), int(x2 - x1), int(y2 - y1)])
                        scores.append(float(confidence))
        kept = cv2.dnn.NMSBoxes(boxes, scores, conf_threshold, 0.35) if boxes else []
        return [(boxes[int(i)], scores[int(i)]) for i in (kept.flatten() if len(kept) > 0 else [])]

    return detect


def openvino_person_detector(model: Path, cv2, np):
    """Return a CPU person detector using tiling and full-frame analysis."""
    if not model.exists() or not model.with_suffix(".bin").exists():
        return None
    try:
        from openvino import Core
        compiled = Core().compile_model(str(model), "CPU")
        input_layer, output_layer = compiled.input(0), compiled.output(0)
        _, _, input_height, input_width = (int(value) for value in input_layer.shape)
    except Exception:
        return None

    def detect(frame, conf_threshold=0.35):
        height, width = frame.shape[:2]
        tile_size, tile_step = 640, 512
        x_starts = list(range(0, max(1, width - tile_size + 1), tile_step))
        y_starts = list(range(0, max(1, height - tile_size + 1), tile_step))
        if x_starts[-1] != max(0, width - tile_size):
            x_starts.append(max(0, width - tile_size))
        if y_starts[-1] != max(0, height - tile_size):
            y_starts.append(max(0, height - tile_size))

        boxes, scores = [], []
        # Native resolution tiles for small / seated people
        for top in y_starts:
            for left in x_starts:
                tile = frame[top:min(height, top + tile_size), left:min(width, left + tile_size)]
                tile_height, tile_width = tile.shape[:2]
                resized = cv2.resize(tile, (input_width, input_height))
                blob = np.ascontiguousarray(resized.transpose(2, 0, 1)[None])
                result = compiled({input_layer: blob})[output_layer].reshape(-1, 7)
                for _, label, confidence, x1, y1, x2, y2 in result:
                    if int(label) == 0 and confidence >= conf_threshold:
                        bx = left + max(0, int(x1 * tile_width))
                        by = top + max(0, int(y1 * tile_height))
                        bw = int((x2 - x1) * tile_width)
                        bh = int((y2 - y1) * tile_height)
                        if bw >= 20 and bh >= 30:
                            boxes.append([bx, by, bw, bh])
                            scores.append(float(confidence))

        # Full-frame pass for large / nearby people
        resized_full = cv2.resize(frame, (input_width, input_height))
        blob_full = np.ascontiguousarray(resized_full.transpose(2, 0, 1)[None])
        res_full = compiled({input_layer: blob_full})[output_layer].reshape(-1, 7)
        for _, label, confidence, x1, y1, x2, y2 in res_full:
            if int(label) == 0 and confidence >= conf_threshold:
                bx = max(0, int(x1 * width))
                by = max(0, int(y1 * height))
                bw = int((x2 - x1) * width)
                bh = int((y2 - y1) * height)
                if bw >= 20 and bh >= 30:
                    boxes.append([bx, by, bw, bh])
                    scores.append(float(confidence))

        kept = cv2.dnn.NMSBoxes(boxes, scores, conf_threshold, 0.40) if boxes else []
        return [(boxes[int(i)], scores[int(i)]) for i in (kept.flatten() if len(kept) > 0 else [])]

    return detect


def extract_torso_appearance(frame, head_box, cv2, np):
    """Compute an HSV color histogram of the torso/clothing area directly below the head."""
    height, width = frame.shape[:2]
    hx, hy, hw, hh = head_box
    tx = max(0, int(hx - 0.25 * hw))
    ty = min(height - 1, int(hy + hh * 0.75))
    tw = min(width - tx, int(hw * 1.5))
    th = min(height - ty, int(hh * 1.6))
    if tw < 8 or th < 8:
        return None
    torso_crop = frame[ty:ty + th, tx:tx + tw]
    hsv = cv2.cvtColor(torso_crop, cv2.COLOR_BGR2HSV)
    hist = cv2.calcHist([hsv], [0, 1], None, [16, 8], [0, 180, 0, 256])
    cv2.normalize(hist, hist, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    return hist


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
    try:
        idle_timeout = max(30, int(os.environ.get("ARCHIVE_SOCKET_IDLE_TIMEOUT", "180")))
    except ValueError:
        idle_timeout = 180
    with ExitStack() as stack:
        control = stack.enter_context(socket.create_connection((ip, port), timeout=15))
        if hasattr(control, "settimeout"):
            control.settimeout(idle_timeout)
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
        # Long recordings can pause between GOPs.  The connect timeout is not
        # a safe read timeout and caused false failures after 20 seconds.
        if hasattr(data, "settimeout"):
            data.settimeout(idle_timeout)
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
        deadline = time.monotonic() + int(os.environ.get("ARCHIVE_TRANSFER_TIMEOUT", "7200"))
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


def convert_video(source: Path, target: Path, codec, fps, preview=False, quality="original", source_is_container=False):
    if quality not in ("original", "1080p", "720p", "480p"):
        raise ArchiveError("Nieprawidłowy profil jakości nagrania.")
    binary = os.environ.get("FFMPEG_BIN") or shutil.which("ffmpeg")
    if not binary:
        raise ArchiveError("Brak FFmpeg na serwerze. Zainstaluj FFmpeg lub ustaw FFMPEG_BIN.")
    arguments = [binary, "-hide_banner", "-loglevel", "error", "-nostdin", "-y"]
    if source_is_container:
        arguments += ["-i", str(source)]
    else:
        arguments += ["-r", str(fps), "-f", codec, "-i", str(source)]
    arguments += ["-an"]
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


def anonymize_faces(source: Path, target: Path, progress_callback=None):
    """Write a H.264 copy with detected faces covered by black masks."""
    try:
        import cv2
        import numpy as np
    except ImportError as exc:
        raise ArchiveError("Anonimizacja twarzy nie jest dostępna: brakuje modułu OpenCV.") from exc
    cv2.setNumThreads(anonymize_worker_count())

    capture = cv2.VideoCapture(str(source))
    if not capture.isOpened():
        raise ArchiveError("Nie można odczytać nagrania do anonimizacji.")
    width, height = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH)), int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = capture.get(cv2.CAP_PROP_FPS) or 25.0
    if width < 1 or height < 1:
        capture.release()
        raise ArchiveError("Nagranie nie zawiera prawidłowego obrazu do anonimizacji.")

    models_dir = Path(__file__).resolve().parent / "models"
    yolo_detector = openvino_yolo_head_detector(models_dir / "yolov8n-head.onnx", cv2, np)
    person_detector = openvino_person_detector(models_dir / "person-detection-0202.xml", cv2, np)
    intel_detector = openvino_face_detector(models_dir / "face-detection-retail-0004.xml", cv2, np)
    adas_detector = openvino_face_detector(models_dir / "face-detection-adas-0001.xml", cv2, np)

    yunet = None
    yunet_model = models_dir / "face_detection_yunet_2023mar.onnx"
    if yunet_model.exists() and hasattr(cv2, "FaceDetectorYN"):
        yunet = cv2.FaceDetectorYN.create(str(yunet_model), "", (width, height), 0.30, 0.20, 5000)

    if not yolo_detector and not person_detector and not intel_detector and not adas_detector and yunet is None:
        capture.release()
        raise ArchiveError("Nie można uruchomić modeli detekcji dla anonimizacji.")

    binary = os.environ.get("FFMPEG_BIN") or shutil.which("ffmpeg")
    if not binary:
        capture.release()
        raise ArchiveError("Brak FFmpeg na serwerze. Zainstaluj FFmpeg lub ustaw FFMPEG_BIN.")
    arguments = [binary, "-hide_banner", "-loglevel", "error", "-nostdin", "-y"]
    arguments += ["-f", "rawvideo", "-pixel_format", "bgr24", "-video_size", f"{width}x{height}",
                  "-framerate", str(fps), "-i", "pipe:0", "-an"]
    arguments += ["-c:v", "libx264", "-preset", "superfast", "-crf", "20", "-pix_fmt", "yuv420p"]
    if target.suffix.lower() == ".mp4":
        arguments += ["-movflags", "+faststart"]
    arguments.append(str(target))
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE)

    try:
        detection_interval = max(1, min(30, int(os.environ.get("ARCHIVE_ANONYMIZE_INTERVAL", "2"))))
    except ValueError:
        detection_interval = 2

    max_hold_frames = max(10, min(150, int(fps * 2.0)))
    frame_number = 0
    tracks = []
    def detect_frame_candidates(frame):
        # 1. Direct head detections
        direct_heads = list(yolo_detector(frame)) if yolo_detector else []

        # 2. Supplementary face detections
        face_boxes = []
        if intel_detector:
            face_boxes.extend(intel_detector(frame))
        if adas_detector:
            face_boxes.extend(adas_detector(frame))
        if yunet:
            yn_out = yunet.detect(frame)[1]
            if yn_out is not None:
                for face in yn_out:
                    face_boxes.append(([int(face[0]), int(face[1]), int(face[2]), int(face[3])], float(face[-1])))

        # 3. Person silhouette detections
        people = list(person_detector(frame)) if person_detector else []

        candidates = []
        claimed_heads = set()

        # For every detected person, align to a head or estimate head position from posture
        for (px, py, pw, ph), p_conf in people:
            matched_head, matched_idx = None, None
            for idx, ((hx, hy, hw, hh), h_conf) in enumerate(direct_heads):
                if idx in claimed_heads:
                    continue
                hcx, hcy = hx + hw / 2, hy + hh / 2
                if px - pw * 0.15 <= hcx <= px + pw * 1.15 and py - ph * 0.20 <= hcy <= py + ph * 0.65:
                    matched_head = [hx, hy, hw, hh]
                    matched_idx = idx
                    break

            if matched_head is None:
                # Check face detections
                for (fx, fy, fw, fh), f_conf in face_boxes:
                    fcx, fcy = fx + fw / 2, fy + fh / 2
                    if px - pw * 0.15 <= fcx <= px + pw * 1.15 and py - ph * 0.20 <= fcy <= py + ph * 0.65:
                        matched_head = [fx, fy, fw, fh]
                        break

            if matched_head is not None:
                if matched_idx is not None:
                    claimed_heads.add(matched_idx)
                candidates.append((matched_head, 0.85))
            else:
                # Conservative head derived from upper body posture
                hw = max(16, int(pw * 0.48))
                hh = max(18, int(ph * 0.35))
                hx = int(px + (pw - hw) / 2)
                hy = max(0, int(py - hh * 0.05))
                candidates.append(([hx, hy, hw, hh], float(p_conf)))

        # Also keep any unattached direct heads or faces with strong confidence
        for idx, ((hx, hy, hw, hh), h_conf) in enumerate(direct_heads):
            if idx not in claimed_heads and h_conf >= 0.30:
                candidates.append(([hx, hy, hw, hh], float(h_conf)))

        for (fx, fy, fw, fh), f_conf in face_boxes:
            if f_conf >= 0.45:
                candidates.append(([fx, fy, fw, fh], float(f_conf)))

        if not candidates:
            return []

        c_boxes = [c[0] for c in candidates]
        c_scores = [c[1] for c in candidates]
        kept = cv2.dnn.NMSBoxes(c_boxes, c_scores, 0.20, 0.40)
        return [c_boxes[int(i)] for i in (kept.flatten() if len(kept) > 0 else [])]

    try:
        while True:
            ok, frame = capture.read()
            if not ok:
                break

            is_detection_frame = (frame_number % detection_interval == 0)
            detections = detect_frame_candidates(frame) if is_detection_frame else []

            matched_tracks = set()
            matched_dets = set()

            # Associate detections to existing tracks
            for d_idx, d_box in enumerate(detections):
                dx, dy, dw, dh = d_box
                dcx, dcy = dx + dw / 2, dy + dh / 2
                best_t, best_dist = None, float("inf")
                for t_idx, track in enumerate(tracks):
                    if t_idx in matched_tracks:
                        continue
                    tx, ty, tw, th = track["box"]
                    tcx, tcy = tx + tw / 2, ty + th / 2
                    dist = ((dcx - tcx) ** 2 + (dcy - tcy) ** 2) ** 0.5
                    max_allowed = max(dw, dh, tw, th) * 1.3
                    if dist < best_dist and dist <= max_allowed:
                        best_t, best_dist = t_idx, dist
                if best_t is not None:
                    matched_tracks.add(best_t)
                    matched_dets.add(d_idx)
                    track = tracks[best_t]
                    track["box"] = d_box
                    track["missed"] = 0
                    new_hist = extract_torso_appearance(frame, d_box, cv2, np)
                    if new_hist is not None:
                        if track.get("torso_hist") is None:
                            track["torso_hist"] = new_hist
                        else:
                            track["torso_hist"] = 0.80 * track["torso_hist"] + 0.20 * new_hist

            # Initialize new tracks for unmatched detections
            for d_idx, d_box in enumerate(detections):
                if d_idx not in matched_dets:
                    hist = extract_torso_appearance(frame, d_box, cv2, np)
                    tracks.append({"box": d_box, "torso_hist": hist, "missed": 0})

            # Check tracks not updated by detection
            surviving = []
            for t_idx, track in enumerate(tracks):
                if is_detection_frame and t_idx in matched_tracks:
                    surviving.append(track)
                    continue

                track["missed"] += 1
                if track["missed"] > max_hold_frames:
                    continue

                # Verify that the torso/clothing is still present under the head
                cur_hist = extract_torso_appearance(frame, track["box"], cv2, np)
                if cur_hist is not None and track.get("torso_hist") is not None:
                    corr = cv2.compareHist(cur_hist, track["torso_hist"], cv2.HISTCMP_CORREL)
                    if corr < 0.45:
                        # Person moved or left; do not keep ghost mask on empty chair/background
                        continue

                surviving.append(track)

            tracks = surviving

            # Render solid black masks covering heads and immediate contours
            for track in tracks:
                bx, by, bw, bh = track["box"]
                pad_x = max(6, int(bw * 0.16))
                pad_y = max(6, int(bh * 0.18))
                left = max(0, bx - pad_x)
                top = max(0, by - pad_y)
                right = min(width, bx + bw + pad_x)
                bottom = min(height, by + bh + pad_y)
                frame[top:bottom, left:right] = 0
            process.stdin.write(frame.tobytes())
            frame_number += 1
            if progress_callback and frame_number % 20 == 0:
                total_frames = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
                progress_callback(frame_number / total_frames if total_frames > 0 else None)
        process.stdin.close()
        process.wait(timeout=int(os.environ.get("ARCHIVE_ANONYMIZE_TIMEOUT", "7200")))
    except (BrokenPipeError, subprocess.TimeoutExpired, OSError) as exc:
        process.kill()
        process.wait()
        raise ArchiveError("Nie udało się zanonimizować twarzy w nagraniu.") from exc
    finally:
        capture.release()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
    if process.returncode or not target.exists() or target.stat().st_size == 0:
        raise ArchiveError("Nie udało się zanonimizować twarzy w nagraniu.")
