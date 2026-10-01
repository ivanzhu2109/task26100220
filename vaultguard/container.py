""".vault 容器格式：加密头部 + 逐块 AEAD 密文，保护身份/策略/顺序/总长。

布局：
    MAGIC(4) | header_len(4, BE) | header_json | header_mac(32) | 密文区
header_json 为规范化 JSON（键排序），含上传标识、总长度、明文 SHA-256、
分块大小、分块数、策略元数据密文与每块随机 nonce；header_mac 为对
MAGIC|header_len|header_json 的 HMAC，密钥由文件密钥派生，不落盘。
密文区为各分块 密文||GCM标签 按序拼接，长度可由头部字段推导，
任何截断/调块/篡改都会在结构解析或 AEAD 校验时失败。
"""

from __future__ import annotations

import base64
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path

from .crypto import TAG_LEN
from .errors import IntegrityError

MAGIC: bytes = b"VLT1"
_MAC_LEN: int = 32
_MAX_HEADER_LEN: int = 16 * 1024 * 1024


@dataclass(frozen=True)
class ContainerHeader:
    upload_id: str
    total_length: int
    sha256_hex: str
    chunk_size: int
    chunk_count: int
    policy_ct: bytes          # 策略元数据密文（nonce||ct||tag）
    chunk_nonces: tuple[bytes, ...]
    header_mac: bytes         # 对头部规范化字节的 HMAC


def chunk_plain_size(header: ContainerHeader, seq: int) -> int:
    """第 seq 块的明文长度。"""
    if not 0 <= seq < header.chunk_count:
        raise IntegrityError(f"分块序号越界: {seq}")
    if seq < header.chunk_count - 1:
        return header.chunk_size
    return header.total_length - header.chunk_size * (header.chunk_count - 1)


def chunk_cipher_size(header: ContainerHeader, seq: int) -> int:
    """第 seq 块的密文长度（含 GCM 标签）。"""
    return chunk_plain_size(header, seq) + TAG_LEN


def _header_signed_bytes(header_json: bytes) -> bytes:
    return MAGIC + struct.pack(">I", len(header_json)) + header_json


def header_signing_payload(header: ContainerHeader) -> bytes:
    """待 HMAC 的规范化头部字节（供 core 计算 header_mac）。"""
    return _header_signed_bytes(_encode_header(header))


def _encode_header(header: ContainerHeader) -> bytes:
    obj = {
        "upload_id": header.upload_id,
        "total_length": header.total_length,
        "sha256": header.sha256_hex,
        "chunk_size": header.chunk_size,
        "chunk_count": header.chunk_count,
        "policy_ct": base64.b64encode(header.policy_ct).decode("ascii"),
        "chunk_nonces": [
            base64.b64encode(n).decode("ascii") for n in header.chunk_nonces
        ],
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_header(raw: bytes, header_mac: bytes) -> ContainerHeader:
    try:
        obj = json.loads(raw.decode("utf-8"))
        return ContainerHeader(
            upload_id=str(obj["upload_id"]),
            total_length=int(obj["total_length"]),
            sha256_hex=str(obj["sha256"]),
            chunk_size=int(obj["chunk_size"]),
            chunk_count=int(obj["chunk_count"]),
            policy_ct=base64.b64decode(obj["policy_ct"], validate=True),
            chunk_nonces=tuple(
                base64.b64decode(n, validate=True) for n in obj["chunk_nonces"]
            ),
            header_mac=header_mac,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise IntegrityError("容器头部损坏或格式非法") from exc


def write_container(
    path: Path,
    header: ContainerHeader,
    chunk_ciphertexts: list[bytes],
) -> None:
    """原子写入容器文件（临时文件 + fsync + os.replace）。"""
    if len(chunk_ciphertexts) != header.chunk_count:
        raise ValueError("密文块数与头部声明不符")
    header_json = _encode_header(header)
    body = _header_signed_bytes(header_json) + header.header_mac + b"".join(
        chunk_ciphertexts
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp." + os.urandom(6).hex())
    try:
        with open(tmp, "wb") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_container(path: Path) -> tuple[ContainerHeader, bytes]:
    """读取容器，返回 (头部, 密文区)。仅做结构解析，不做密钥校验。"""
    try:
        blob = Path(path).read_bytes()
    except OSError as exc:
        raise IntegrityError(f"容器不可读: {exc}") from exc
    if len(blob) < 4 + 4 + _MAC_LEN or blob[:4] != MAGIC:
        raise IntegrityError("容器魔数缺失或文件被截断")
    (header_len,) = struct.unpack(">I", blob[4:8])
    if header_len <= 0 or header_len > _MAX_HEADER_LEN:
        raise IntegrityError("容器头部长度非法")
    mac_start = 8 + header_len
    mac_end = mac_start + _MAC_LEN
    if len(blob) < mac_end:
        raise IntegrityError("容器头部被截断")
    header = _decode_header(blob[8:mac_start], blob[mac_start:mac_end])
    if len(header.chunk_nonces) != header.chunk_count:
        raise IntegrityError("容器 nonce 数与分块数不符")
    ciphertext = blob[mac_end:]
    expected = sum(chunk_cipher_size(header, s) for s in range(header.chunk_count))
    if len(ciphertext) != expected:
        raise IntegrityError(
            f"容器密文区长度不符：期望 {expected}，实际 {len(ciphertext)}"
        )
    return header, ciphertext
