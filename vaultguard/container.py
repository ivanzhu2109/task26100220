""".vault 容器格式：认证头 + 逐块 AES-GCM 密文。

头部布局（全部大端）：
    MAGIC(8) | u32 upload_id 长度 | upload_id
    u64 明文总长度 | u32 分块数 | 64 字节 SHA-256(十六进制 ASCII)
    u32 元数据密文长度 | 元数据密文(含 GCM tag)
    32 字节头 HMAC（覆盖以上全部字段）
之后依次存放各分块密文：分块 i 长度 = 明文长度 + 16(GCM tag)。
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from .crypto import CHUNK_SIZE
from .errors import IntegrityError

MAGIC = b"VAULT001"
TAG_LEN = 16
HEADER_MAC_LEN = 32
_SHA256_HEX_LEN = 64


def build_header(
    upload_id: str,
    total_length: int,
    sha256_hex: str,
    chunk_count: int,
    enc_meta: bytes,
    header_mac: bytes,
) -> bytes:
    """序列化容器头（含元数据密文与头 HMAC）。"""
    uid = upload_id.encode("utf-8")
    if len(sha256_hex) != _SHA256_HEX_LEN:
        raise ValueError("sha256_hex 必须为 64 个十六进制字符")
    if len(header_mac) != HEADER_MAC_LEN:
        raise ValueError("header_mac 长度错误")
    fields = (
        MAGIC
        + struct.pack(">I", len(uid))
        + uid
        + struct.pack(">Q", total_length)
        + struct.pack(">I", chunk_count)
        + sha256_hex.encode("ascii")
        + struct.pack(">I", len(enc_meta))
        + enc_meta
    )
    return fields + header_mac


def _fields_end(data: bytes) -> int:
    """返回头 HMAC 之前的字段区结束偏移，格式错误抛 IntegrityError。"""
    try:
        if data[: len(MAGIC)] != MAGIC:
            raise IntegrityError("容器魔数不匹配")
        pos = len(MAGIC)
        (uid_len,) = struct.unpack_from(">I", data, pos)
        pos += 4 + uid_len
        pos += 8  # total_length
        pos += 4  # chunk_count
        pos += _SHA256_HEX_LEN
        (meta_len,) = struct.unpack_from(">I", data, pos)
        pos += 4 + meta_len
        return pos
    except (struct.error, IndexError) as exc:
        raise IntegrityError("容器头损坏或截断") from exc


def parse_header(data: bytes) -> dict:
    """解析容器头，返回字段字典；格式错误抛 IntegrityError。"""
    end = _fields_end(data)
    if len(data) < end + HEADER_MAC_LEN:
        raise IntegrityError("容器头损坏或截断")
    pos = len(MAGIC)
    (uid_len,) = struct.unpack_from(">I", data, pos)
    pos += 4
    uid = data[pos : pos + uid_len].decode("utf-8")
    pos += uid_len
    (total_length,) = struct.unpack_from(">Q", data, pos)
    pos += 8
    (chunk_count,) = struct.unpack_from(">I", data, pos)
    pos += 4
    sha256_hex = data[pos : pos + _SHA256_HEX_LEN].decode("ascii")
    pos += _SHA256_HEX_LEN
    (meta_len,) = struct.unpack_from(">I", data, pos)
    pos += 4
    enc_meta = data[pos : pos + meta_len]
    pos += meta_len
    mac = data[pos : pos + HEADER_MAC_LEN]
    return {
        "upload_id": uid,
        "total_length": total_length,
        "chunk_count": chunk_count,
        "sha256_hex": sha256_hex,
        "enc_meta": enc_meta,
        "header_mac": mac,
        "mac_coverage": data[:end],  # 头 HMAC 覆盖的字节
        "header_len": end + HEADER_MAC_LEN,
    }


def chunk_plain_lengths(total_length: int, chunk_count: int) -> list[int]:
    """按声明总长度计算每个分块的明文长度。"""
    if chunk_count < 1:
        raise IntegrityError("分块数必须为正")
    lengths = []
    remaining = total_length
    for i in range(chunk_count):
        n = min(CHUNK_SIZE, remaining)
        if n <= 0:
            raise IntegrityError("分块数与总长度不一致")
        lengths.append(n)
        remaining -= n
    if remaining != 0:
        raise IntegrityError("分块数与总长度不一致")
    return lengths


def chunk_offsets(header: dict, hdr_len: int) -> list[tuple[int, int]]:
    """按声明长度计算每个分块密文在容器内的 (偏移, 长度)。"""
    offsets = []
    pos = hdr_len
    for n in chunk_plain_lengths(header["total_length"], header["chunk_count"]):
        offsets.append((pos, n + TAG_LEN))
        pos += n + TAG_LEN
    return offsets


def write_container(path: Path, header: bytes, enc_chunks: list[bytes]) -> None:
    """原子地写出完整容器文件。"""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(header)
        for blob in enc_chunks:
            f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
