"""Read-only recorder camera configuration probe; works with the project's Linux setup.
Never prints or saves camera usernames/passwords. Does not send write commands.
"""
import argparse
import collections
import json
from pathlib import Path
import sqlite3
import sys
import socket
import struct
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# main currently resolves static assets relative to the process directory.
import os
_previous_directory = Path.cwd()
try:
    os.chdir(ROOT)
    import main
finally:
    os.chdir(_previous_directory)


def read_native_blocks(ip, port, user, password, block_ids):
    """Only captured read operations are allowed; no configuration setters."""
    from quii_archive import read_reply
    if not block_ids or not set(block_ids) <= {0x31, 0xd5, 0xd6, 0x105, 0x106}:
        raise ValueError('Unsupported read block')
    credentials = (user + '&&' + password).encode('utf-8') + b'\0'
    credentials += b'\0' * ((-len(credentials)) % 16)
    if len(credentials) > 1024:
        raise ValueError('Authentication payload too large')
    auth = bytearray.fromhex('0a01015000000000ff433030323300000000000000000000040100000000a1aa')
    struct.pack_into('<I', auth, 4, len(credentials))
    found = {}
    with socket.create_connection((ip, port), timeout=12) as conn:
        conn.sendall(auth + credentials)
        reply, _ = read_reply(conn)
        if reply[0] != 0xb0 or reply[8] != 0:
            raise RuntimeError('Authentication rejected')
        auth[0] = 0xa0
        conn.sendall(auth + credentials)
        request = bytearray(32)
        body = b''.join(struct.pack('<II', block, 0) for block in block_ids)
        struct.pack_into('<I', request, 4, len(body))
        conn.sendall(request + body)
        for _ in range(128):
            header, body = read_reply(conn)
            if header[0] != 0:
                continue
            offset = 0
            while offset+8 <= len(body):
                block_id, size = struct.unpack_from('<II', body, offset)
                if offset+8+size > len(body):
                    raise RuntimeError('Incomplete configuration block')
                if block_id in block_ids:
                    found[block_id] = body[offset+8:offset+8+size]
                offset += 8+size
            if all(block in found for block in block_ids):
                return found
        raise RuntimeError('No recognized configuration response')


def read_time(ip, port, user, password):
    data = read_native_blocks(ip, port, user, password, [0x31])[0x31]
    if len(data) != 32:
        raise RuntimeError('Unknown clock schema')
    year, month, day, weekday, hour, minute, second, reserved = struct.unpack('<8I', data)
    value = datetime(year, month, day, hour, minute, second)
    return {'recorder_local_time': value.isoformat(), 'weekday_raw': weekday,
            'timezone': 'not decoded; do not treat as UTC', 'read_block': '0x31'}


def read_network(ip, port, user, password):
    import ipaddress
    blocks = read_native_blocks(ip, port, user, password, [0xd5, 0xd6, 0x105, 0x106])
    adapter, dns, ntp_options, ntp_list = (blocks[k] for k in [0xd5, 0xd6, 0x105, 0x106])
    if len(adapter) != 80 or len(dns) != 32 or len(ntp_options) != 24 or len(ntp_list) % 84:
        raise RuntimeError('Unknown network schema')
    servers = []
    for offset in range(0, len(ntp_list), 84):
        record = ntp_list[offset:offset+84]
        servers.append({'id': int.from_bytes(record[:4], 'little'),
                        'hostname': record[4:84].split(b'\0')[0].decode('utf-8', errors='replace')})
    return {'ipv4': str(ipaddress.IPv4Address(adapter[48:52])),
            'netmask': str(ipaddress.IPv4Address(adapter[52:56])),
            'gateway': str(ipaddress.IPv4Address(adapter[56:60])),
            'dns': [part.split(b'\0')[0].decode('ascii', errors='replace') for part in [dns[:16], dns[16:]]],
            'ntp': {'port': int.from_bytes(ntp_options[2:4], 'little'),
                    'interval_minutes': int.from_bytes(ntp_options[4:8], 'little'),
                    'flags_raw': ntp_options[:2].hex(), 'flags_note': 'enable and selection flags not fully decoded',
                    'servers': servers},
            'read_blocks': ['0xd5', '0xd6', '0x105', '0x106'],
            'note': 'Partial schema; DHCP, IPv6, ports and flags still require decoding'}


def inspect(dvr_id, include_time=False, include_network=False):
    with sqlite3.connect(ROOT / 'data/dvrs.db') as db:
        row = db.execute('SELECT ip, user, password FROM dvrs WHERE id = ?', (dvr_id,)).fetchone()
    if row is None:
        raise ValueError('Unknown recorder ID')
    root = main.tdk_send_command(*row, 'get.channelmanagement.config', timeout=12)
    if root is None or root.findtext('.//error') != '0':
        raise RuntimeError('Recorder did not confirm a successful configuration read')
    # Explicit allowlist: credentials and stream URLs are never included.
    allowed = {'enabled', 'type', 'ipaddress', 'port', 'protocol', 'protocoltype',
               'timesync', 'remoteid', 'connection', 'resomode'}
    channels = []
    for channel in root.findall('.//channel'):
        values = {'id': channel.findtext('id')}
        for el in channel.iter():
            if el.tag in allowed and el.text is not None:
                values[el.tag] = el.text
        channels.append(values)
    result = {'dvr_id': dvr_id, 'command': 'get.channelmanagement.config',
            'error': 0, 'schema': dict(collections.Counter(e.tag for e in root.iter())),
            'channels': channels}
    if include_time or include_network:
        with sqlite3.connect(ROOT / 'data/dvrs.db') as db:
            port = db.execute('SELECT port FROM dvrs WHERE id = ?', (dvr_id,)).fetchone()[0]
        if include_time:
            result['time'] = read_time(row[0], port, row[1], row[2])
        if include_network:
            result['network'] = read_network(row[0], port, row[1], row[2])
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dvr-id', required=True, type=int)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--include-time', action='store_true', help='Also read the native recorder clock (no synchronization)')
    parser.add_argument('--include-network', action='store_true', help='Read IPv4/DNS/NTP; no configuration changes')
    args = parser.parse_args()
    try:
        result = inspect(args.dvr_id, args.include_time, args.include_network)
    except Exception:
        # Avoid exception bodies that could include an authenticated request.
        print('Configuration read failed; check connectivity, recorder ID and OpenSSL.', file=sys.stderr)
        raise SystemExit(1)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + '\n', encoding='utf-8')
        print(f'Read {len(result["channels"])} channels; saved sanitized configuration to {args.output}')
    else:
        print(text)
