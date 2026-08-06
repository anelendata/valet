"""Small WebSocket helpers for Valet's JSON RPC transport."""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT = 0x1
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


class WebSocketError(ConnectionError):
    pass


def accept_key(client_key: str) -> str:
    digest = hashlib.sha1((client_key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def client_key() -> str:
    return base64.b64encode(os.urandom(16)).decode("ascii")


def read_http_headers(sock: socket.socket) -> tuple[str, dict[str, str]]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            raise WebSocketError("connection closed during handshake")
        data += chunk
        if len(data) > 65536:
            raise WebSocketError("handshake headers too large")
    head, _, _rest = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    start = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return start, headers


def read_text(sock: socket.socket, *, expect_masked: bool) -> str:
    while True:
        opcode, payload = read_frame(sock, expect_masked=expect_masked)
        if opcode == OP_TEXT:
            return payload.decode("utf-8")
        if opcode == OP_PING:
            write_frame(sock, OP_PONG, payload, mask=False)
            continue
        if opcode == OP_PONG:
            continue
        if opcode == OP_CLOSE:
            raise WebSocketError("websocket closed")
        raise WebSocketError(f"unsupported websocket opcode: {opcode}")


def write_text(sock: socket.socket, text: str, *, mask: bool) -> None:
    write_frame(sock, OP_TEXT, text.encode("utf-8"), mask=mask)


def write_close(sock: socket.socket, *, mask: bool) -> None:
    try:
        write_frame(sock, OP_CLOSE, b"", mask=mask)
    except OSError:
        pass


def read_frame(sock: socket.socket, *, expect_masked: bool) -> tuple[int, bytes]:
    head = _read_exact(sock, 2)
    first, second = head[0], head[1]
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if not fin:
        raise WebSocketError("fragmented frames are not supported")
    if masked != expect_masked:
        raise WebSocketError("invalid websocket mask bit")
    if length == 126:
        length = struct.unpack("!H", _read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _read_exact(sock, 8))[0]
    if length > 16 * 1024 * 1024:
        raise WebSocketError("websocket frame too large")
    mask_key = _read_exact(sock, 4) if masked else b""
    payload = _read_exact(sock, length)
    if masked:
        payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def write_frame(sock: socket.socket, opcode: int, payload: bytes, *, mask: bool) -> None:
    first = 0x80 | opcode
    length = len(payload)
    if length < 126:
        head = bytes([first, (0x80 if mask else 0) | length])
    elif length < (1 << 16):
        head = bytes([first, (0x80 if mask else 0) | 126]) + struct.pack("!H", length)
    else:
        head = bytes([first, (0x80 if mask else 0) | 127]) + struct.pack("!Q", length)
    if mask:
        mask_key = os.urandom(4)
        payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
        sock.sendall(head + mask_key + payload)
    else:
        sock.sendall(head + payload)


def _read_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise WebSocketError("websocket closed")
        data += chunk
    return data
