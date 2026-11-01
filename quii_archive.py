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

    def detect(frame):
        height, width = frame.shape[:2]
        # The detector accepts 300×300 input.  Feeding a whole CCTV frame
        # makes distant faces just a few pixels wide, so infer overlapping
        # native-resolution tiles and run NMS once across all detections.
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
                    if confidence < 0.35:
                        continue
                    x1, y1 = left + max(0, x1 * tile_width), top + max(0, y1 * tile_height)
                    x2, y2 = left + min(tile_width, x2 * tile_width), top + min(tile_height, y2 * tile_height)
                    if x2 - x1 >= 10 and y2 - y1 >= 10:
                        boxes.append([x1, y1, x2 - x1, y2 - y1])
                        scores.append(float(confidence))
        kept = cv2.dnn.NMSBoxes(boxes, scores, 0.35, 0.35) if boxes else []
        faces = []
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        for index in kept:
            x1, y1, box_width, box_height = boxes[int(index)]
            x2, y2 = x1 + box_width, y1 + box_height
            region = gray[int(y1):int(y2), int(x1):int(x2)]
            points = cv2.goodFeaturesToTrack(region, maxCorners=8, qualityLevel=0.01,
                                              minDistance=4, blockSize=5)
            if points is None:
                points = np.array([[x1 + box_width / 2, y1 + box_height / 2]], dtype="float32")
            else:
                points = points.reshape(-1, 2) + np.array([x1, y1], dtype="float32")
            faces.append(([x1, y1, box_width, box_height], points.astype("float32")))
        return faces

    return detect


def openvino_person_detector(model: Path, cv2, np):
    """Return a CPU person detector used to make head masking persistent.

    Face detection says *where the head is*; it is intentionally not trusted
    as the identity of a person from one frame to the next.  This detector
    supplies that stable, full-body anchor.  It is run only on keyframes.
    """
    if not model.exists() or not model.with_suffix(".bin").exists():
        return None
    try:
        from openvino import Core
        compiled = Core().compile_model(str(model), "CPU")
        input_layer, output_layer = compiled.input(0), compiled.output(0)
        _, _, input_height, input_width = (int(value) for value in input_layer.shape)
    except Exception:
        return None

    def detect(frame):
        height, width = frame.shape[:2]
        resized = cv2.resize(frame, (input_width, input_height))
        blob = np.ascontiguousarray(resized.transpose(2, 0, 1)[None])
        result = compiled({input_layer: blob})[output_layer].reshape(-1, 7)
        boxes, scores = [], []
        for _, label, confidence, x1, y1, x2, y2 in result:
            # This Open Model Zoo model is single-class: person is label 0.
            if int(label) != 0 or confidence < 0.55:
                continue
            left, top = max(0, x1 * width), max(0, y1 * height)
            right, bottom = min(width, x2 * width), min(height, y2 * height)
            if right - left >= 24 and bottom - top >= 36:
                boxes.append([left, top, right - left, bottom - top])
                scores.append(float(confidence))
        kept = cv2.dnn.NMSBoxes(boxes, scores, 0.55, 0.40) if boxes else []
        people = []
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        for index in kept:
            x, y, box_width, box_height = boxes[int(index)]
            region = gray[int(y):int(y + box_height), int(x):int(x + box_width)]
            points = cv2.goodFeaturesToTrack(region, maxCorners=32, qualityLevel=0.008,
                                              minDistance=7, blockSize=7)
            if points is None:
                points = np.array([[x + box_width / 2, y + box_height / 2]], dtype="float32")
            else:
                points = points.reshape(-1, 2) + np.array([x, y], dtype="float32")
            people.append(([x, y, box_width, box_height], points.astype("float32")))
        return people

    return detect


def openvino_head_pose_estimator(model: Path, cv2, np):
    """Estimate a head from facial keypoints inside one detected person."""
    if not model.exists() or not model.with_suffix(".bin").exists():
        return None
    try:
        from openvino import Core
        compiled = Core().compile_model(str(model), "CPU")
        input_layer = compiled.input(0)
        _, _, input_height, input_width = (int(value) for value in input_layer.shape)
        heatmap_output = next(output for output in compiled.outputs if int(output.shape[1]) == 19)
    except Exception:
        return None

    def estimate(frame, person_box):
        frame_height, frame_width = frame.shape[:2]
        x, y, box_width, box_height = person_box
        left = max(0, int(x - box_width * 0.18))
        top = max(0, int(y - box_height * 0.18))
        right = min(frame_width, int(x + box_width * 1.18))
        bottom = min(frame_height, int(y + box_height * 1.05))
        if right - left < 16 or bottom - top < 16:
            return None
        crop = frame[top:bottom, left:right]
        resized = cv2.resize(crop, (input_width, input_height))
        blob = np.ascontiguousarray(resized.transpose(2, 0, 1)[None])
        heatmaps = compiled({input_layer: blob})[heatmap_output][0]
        map_height, map_width = heatmaps.shape[1:]
        points = []
        # COCO/OpenPose: nose, right/left eye, right/left ear.
        for joint in (0, 14, 15, 16, 17):
            heatmap = heatmaps[joint]
            row, column = np.unravel_index(np.argmax(heatmap), heatmap.shape)
            score = float(heatmap[row, column])
            if score >= 0.12:
                points.append((left + (column + 0.5) * (right - left) / map_width,
                               top + (row + 0.5) * (bottom - top) / map_height))
        if not points:
            return None
        xs, ys = zip(*points)
        center_x, center_y = sum(xs) / len(xs), sum(ys) / len(ys)
        spread = max(xs) - min(xs) if len(xs) > 1 else 0
        head_width = max(28, min(box_width * 0.62, max(spread * 2.4, box_width * 0.30)))
        head_height = max(32, min(box_height * 0.34, head_width * 1.15))
        return [center_x - head_width / 2, center_y - head_height * 0.48,
                head_width, head_height]

    return estimate


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

    def estimated_head(person_box):
        """Conservative head silhouette derived from a detected person box.

        This is used only when the person model positively sees a person but
        their face is turned away, covered, or too small for the face model.
        It intentionally covers hair and ears as well as the face.
        """
        x, y, person_width, person_height = person_box
        head_width = max(28, min(person_width * 0.70, 220))
        head_height = max(32, min(person_height * 0.30, head_width * 1.15, 250))
        return [x + (person_width - head_width) / 2, y - head_height * 0.06,
                head_width, head_height]

    def head_from_relative(person_box, relative):
        x, y, person_width, person_height = person_box
        rel_x, rel_y, rel_width, rel_height = relative
        return [x + rel_x * person_width, y + rel_y * person_height,
                max(10, rel_width * person_width), max(10, rel_height * person_height)]
    # The source archive is passed to this detector at its native resolution.
    # Lower-quality previews are never used as anonymization input.
    intel_detector = openvino_face_detector(
        Path(__file__).resolve().parent / "models" / "face-detection-retail-0004.xml", cv2, np)
    adas_detector = openvino_face_detector(
        Path(__file__).resolve().parent / "models" / "face-detection-adas-0001.xml", cv2, np)
    detector = None
    model = Path(__file__).resolve().parent / "models" / "face_detection_yunet_2023mar.onnx"
    if model.exists() and hasattr(cv2, "FaceDetectorYN"):
        detector = cv2.FaceDetectorYN.create(str(model), "", (width, height), 0.30, 0.20, 5000)
    if not intel_detector and detector is None:
        if not model.exists() or not hasattr(cv2, "FaceDetectorYN"):
            capture.release()
            raise ArchiveError("Nie można uruchomić modelu wykrywania twarzy dla anonimizacji.")
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
        keyframe_interval = max(4, min(120, int(os.environ.get("ARCHIVE_ANONYMIZE_KEYFRAME_INTERVAL", "12"))))
    except ValueError:
        keyframe_interval = 12
    frame_number = 0
    # A track belongs to a person, not to a transient face detection.  Its
    # ``head_box`` is populated only by a real face detector and remains set
    # while the person remains in the frame.  This is the important privacy
    # rule: a missed face in one keyframe must never reveal a known head.
    tracks = []
    try:
        while True:
            ok, frame = capture.read()
            if not ok:
                break
            # The person model is deliberately evaluated for every frame.
            # OpenCV optical flow was attracted to chairs and desk edges, so
            # it could leave a black box behind after a person walked away.
            # A positive silhouette is now required for every rendered mask.
            face_candidates = []
            if True:
                detected = detector.detect(frame)[1] if detector else None
                faces = list(intel_detector(frame)) if intel_detector else []
                if adas_detector:
                    faces.extend(adas_detector(frame))
                if detected is not None:
                    faces.extend((face[:4], face[4:14].reshape(5, 2).astype("float32")) for face in detected)
                for box, landmarks in faces:
                    x, y, face_width, face_height = box
                    ratio = face_width / max(face_height, 1)
                    if 10 <= face_width <= 360 and 10 <= face_height <= 360 and 0.40 <= ratio <= 2.2:
                        face_candidates.append(([x, y, face_width, face_height], landmarks))
            # A mask is based exclusively on a face/head detected in this
            # exact frame.  Inferring it from a whole person box produced
            # persistent masks on chairs and in empty areas.
            people = [(box, points) for box, points in face_candidates]

            # Associate detections to people already in the scene.  A person
            # is never retained without a current silhouette detection.
            matched, refreshed = set(), []
            for box, points in people:
                x, y, person_width, person_height = box
                center_x, center_y = x + person_width / 2, y + person_height / 2
                best_index, best_distance = None, float("inf")
                for index, old_track in enumerate(tracks):
                    if index in matched:
                        continue
                    ox, oy, ow, oh = old_track["box"]
                    distance = ((center_x - (ox + ow / 2)) ** 2 + (center_y - (oy + oh / 2)) ** 2) ** 0.5
                    if distance < best_distance and distance <= max(person_width, person_height, ow, oh) * 0.75:
                        best_index, best_distance = index, distance
                if best_index is None:
                    refreshed.append({"box": box, "points": points,
                                      "head_box": estimated_head(box), "head_is_measured": False})
                else:
                    track = tracks[best_index]
                    track.update(box=box, points=points)
                    if track.get("head_is_measured", False) and track.get("head_relative") is not None:
                        track["head_box"] = head_from_relative(box, track["head_relative"])
                    else:
                        track["head_box"] = estimated_head(box)
                    refreshed.append(track)
                    matched.add(best_index)
            # Attach a measured head to the corresponding current silhouette.
            # A measurement is stored in silhouette-relative coordinates, so
            # every next frame moves the head with the newly detected person.
            for face_box, _ in face_candidates:
                fx, fy, fw, fh = face_box
                face_center_x, face_center_y = fx + fw / 2, fy + fh / 2
                owner, owner_distance = None, float("inf")
                for track in refreshed:
                    px, py, pw, ph = track["box"]
                    if not (px - pw * 0.15 <= face_center_x <= px + pw * 1.15
                            and py - ph * 0.30 <= face_center_y <= py + ph * 0.70):
                        continue
                    distance = abs(face_center_x - (px + pw / 2)) + abs(face_center_y - py)
                    if distance < owner_distance:
                        owner, owner_distance = track, distance
                if owner is not None:
                    px, py, pw, ph = owner["box"]
                    owner["head_box"] = face_box
                    owner["head_relative"] = [(face_box[0] - px) / max(pw, 1),
                                              (face_box[1] - py) / max(ph, 1),
                                              face_box[2] / max(pw, 1), face_box[3] / max(ph, 1)]
                    owner["head_is_measured"] = True
            tracks = refreshed
            for track in tracks:
                if track["head_box"] is None:
                    continue
                x, y, face_width, face_height = track["head_box"]
                if track.get("head_is_measured", False):
                    # Cover the whole head (hair, ears, jaw), not merely the
                    # face rectangle supplied by the detector.
                    pad_x = max(10, int(face_width * 0.8))
                    pad_top, pad_bottom = max(10, int(face_height)), max(10, int(face_height * 0.6))
                    mask_width = min(220, int(face_width + 2 * pad_x))
                    mask_height = min(250, int(face_height + pad_top + pad_bottom))
                    center_x = x + face_width / 2
                    center_y = y + face_height / 2 - face_height * 0.12
                else:
                    # ``head_box`` is already a deliberately enlarged head
                    # silhouette estimated from the person box.  Padding it a
                    # second time was the cause of person-sized black blocks.
                    mask_width = min(220, int(face_width * 1.10))
                    mask_height = min(250, int(face_height * 1.10))
                    center_x, center_y = x + face_width / 2, y + face_height / 2
                left = max(0, round(center_x - mask_width / 2))
                top = max(0, round(center_y - mask_height / 2))
                right = min(width, left + mask_width)
                bottom = min(height, top + mask_height)
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
