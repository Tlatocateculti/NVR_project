import struct
import unittest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch

from quii_archive import ArchiveError, Recording, archive_frames, frame_time, packed_time, read_exact, save_video


FILENAME = "01_2026-10-28-05-43-06_4350_01_01_235208705_3589_00_00_1039869_37"


class Connection:
    def __init__(self, content):
        self.content = bytearray(content)
        self.sent = []

    def recv(self, length):
        length = min(length, 7)  # force headers/bodies across TCP reads
        result = bytes(self.content[:length])
        del self.content[:length]
        return result

    def sendall(self, content):
        self.sent.append(bytes(content))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def header(command, length=0):
    result = bytearray(32)
    result[0] = command
    struct.pack_into("<I", result, 4, length)
    return result


class ArchiveTests(unittest.TestCase):
    def test_filename_preserves_identity_and_converts_channel_once(self):
        recording = Recording.parse(FILENAME)
        self.assertEqual(recording.raw_filename, FILENAME)
        self.assertEqual(recording.channel, 2)
        self.assertEqual(recording.file_id, 235208705)
        self.assertEqual(recording.end, datetime(2026, 10, 28, 6, 55, 36))

    def test_bad_metadata_rejected(self):
        for value in ("../file", FILENAME.replace("4350", "-1"),
                      FILENAME.replace("235208705", "4294967296")):
            with self.subTest(value=value), self.assertRaises(ArchiveError):
                Recording.parse(value)

    def test_packed_timestamp_matches_captured_request(self):
        self.assertEqual(packed_time(datetime(2026, 10, 28, 6, 55, 36)), 0x6ab86de4)

    def test_media_timestamp_matches_captured_frame(self):
        payload = bytes.fromhex("000001e118ae0000c65ab86af802026480073804")
        self.assertEqual(frame_time(payload), datetime(2026, 10, 28, 5, 43, 6, 760000))

    def test_tcp_segmentation(self):
        self.assertEqual(read_exact(Connection(b"0123456789"), 10), b"0123456789")

    def test_truncated_tcp_record_is_not_success(self):
        with self.assertRaises(ArchiveError):
            read_exact(Connection(b"short"), 32)

    def run_transfer(self, data_bytes, confirmed=True):
        auth = header(0xb0)
        struct.pack_into("<I", auth, 16, 42)
        # Notifications are allowed before the solicited configuration reply.
        control = Connection(auth + header(0x73, 2) + b"ok" + header(0xb4)
                             + header(0x73) + (header(0xf3) if confirmed else b""))
        data = Connection(data_bytes)
        recording = Recording.parse(FILENAME)
        with patch("quii_archive.socket.create_connection", side_effect=[control, data]), \
                patch("quii_archive.select.select", return_value=([], [], [])):
            result = list(archive_frames("device", 34567, "user", "secret", recording,
                                         recording.start, recording.start + timedelta(seconds=10)))
        return result, control, data

    def test_request_and_terminal_record(self):
        terminal = bytearray(32)
        terminal[:4] = b"\xbb\x11\xee\0"
        terminal[8] = 2
        terminal[15] = 0x12
        result, control, data = self.run_transfer(terminal)
        self.assertEqual(result, [])
        self.assertEqual(len(control.sent[0]), 48)  # 32-byte header + padded auth
        request = control.sent[-1]
        self.assertEqual(len(request), 32)
        self.assertEqual(request[8], 2)
        self.assertEqual(struct.unpack_from("<I", request, 17)[0], 235208705)
        self.assertEqual(struct.unpack_from("<I", data.sent[0], 8)[0], 42)

    def test_disconnect_without_terminal_record_fails(self):
        with self.assertRaises(ArchiveError):
            self.run_transfer(b"")

    def test_missing_data_attach_confirmation_fails(self):
        with self.assertRaises(ArchiveError):
            self.run_transfer(b"", confirmed=False)

    def test_unknown_data_header_fails(self):
        with self.assertRaises(ArchiveError):
            self.run_transfer(bytes(32))

    def test_varying_rate_estimate_uses_source_timestamps(self):
        recording = Recording.parse(FILENAME)
        records = []
        for index, rate in enumerate((68, 67, 68)):
            frame = bytearray(24)
            frame[:4] = b"\0\0\x01" + bytes((0xe1 if index == 0 else 0xe0,))
            struct.pack_into("<I", frame, 4, 4)
            struct.pack_into("<I", frame, 8, packed_time(recording.start))
            struct.pack_into("<H", frame, 12, index * 58)
            frame[14:16] = bytes((2, rate))
            frame[20:] = b"data"
            records.append(bytes(frame))
        with tempfile.TemporaryDirectory() as folder, \
                patch("quii_archive.archive_frames", return_value=iter(records)):
            codec, fps, count = save_video("device", 34567, "user", "secret",
                [(recording, recording.start, recording.start + timedelta(seconds=1))],
                Path(folder) / "payload.bin")
        self.assertEqual((codec, count), ("hevc", 3))
        self.assertAlmostEqual(fps, 1 / 0.058)


if __name__ == "__main__":
    unittest.main()
