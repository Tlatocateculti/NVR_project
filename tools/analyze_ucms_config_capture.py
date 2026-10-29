"""Summarize uCMS binary configuration traffic without exposing payloads or credentials.
Requires tshark. Input captures are private and may contain plaintext login data.
"""
import argparse
import collections
import json
from pathlib import Path
import shutil
import struct
import subprocess


def summarize(capture, tshark):
    proc = subprocess.run([tshark, '-r', str(capture), '-Y', 'tcp.len > 0',
        '-T', 'fields', '-e', 'tcp.stream', '-e', 'ip.src', '-e', 'tcp.srcport',
        '-e', 'tcp.seq', '-e', 'tcp.payload'], check=True, capture_output=True, text=True)
    streams = collections.defaultdict(dict)
    for line in proc.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) != 5:
            continue
        stream, ip, port, seq, payload = fields
        try:
            streams[(stream, ip, port)][int(seq)] = bytes.fromhex(payload.replace(':', ''))
        except ValueError:
            continue
    output = []
    for (stream, ip, port), segments in sorted(streams.items()):
        data = bytearray()
        end = min(segments)
        gaps = 0
        for pos, payload in sorted(segments.items()):
            if pos > end:
                gaps += 1
                break  # Never parse across missing bytes.
            if pos + len(payload) > end:
                data.extend(payload[max(0, end-pos):])
                end = pos + len(payload)
        entry = {'stream': stream, 'source': ip, 'source_port': int(port),
                 'captured_bytes': len(data), 'gaps': gaps}
        if data.startswith((b'POST ', b'HTTP/')):
            import re
            entry['transport'] = 'HTTP'
            entry['commands'] = sorted(set(x.decode('ascii', errors='replace')
                for x in re.findall(rb'<command>([a-zA-Z0-9_.]+)</command>', data)))
            entry['response_tags'] = dict(collections.Counter(x.decode('ascii')
                for x in re.findall(rb'<([a-zA-Z][a-zA-Z0-9_]*)[ >]', data)))
        else:
            entry['transport'] = 'quii-candidate'
            offset = 0
            frames = collections.Counter()
            blocks = collections.Counter()
            while offset + 32 <= len(data):
                header = data[offset:offset+32]
                length = struct.unpack_from('<I', header, 4)[0]
                if length > 2*1024*1024 or offset+32+length > len(data):
                    break
                frames[(f'0x{header[0]:02x}', length)] += 1
                body = data[offset+32:offset+32+length]
                if header[0] == 0:
                    cursor = 0
                    while cursor+8 <= len(body):
                        block_id, size = struct.unpack_from('<II', body, cursor)
                        if cursor+8+size > len(body):
                            break
                        blocks[(f'0x{block_id:08x}', size)] += 1
                        cursor += 8+size
                offset += 32+length
            entry['parsed_bytes'] = offset
            entry['frames'] = [{'command': c, 'body_bytes': n, 'count': count}
                               for (c,n),count in sorted(frames.items())]
            entry['blocks'] = [{'id': c, 'data_bytes': n, 'count': count}
                               for (c,n),count in sorted(blocks.items())]
        output.append(entry)
    return {'capture': capture.name, 'note': 'Metadata only; no configuration values or authentication payloads.',
            'streams': output}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--tshark', default=shutil.which('tshark'))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not args.tshark:
        parser.error('Install tshark or provide --tshark PATH')
    result = summarize(args.capture, args.tshark)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f'Sanitized metadata: {len(result["streams"])} stream directions saved.')
