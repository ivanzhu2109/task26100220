"""密钥派生、AEAD 与 HMAC 辅助函数。密钥仅存在于内存，绝不落盘。"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import IntegrityError

CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB
KEY_LEN = 32  # 文件密钥长度（字节）
NONCE_LEN = 12  # AES-GCM 标准 nonce 长度


def validate_key(key: bytes) -> bytes:
    """校验并返回文件密钥，不合法时抛出 ValueError。"""
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
        raise ValueError(f"文件密钥必须为 {KEY_LEN} 字节")
    return bytes(key)


def _domain_nonce(domain: bytes, upload_id: str, seq: int | None) -> bytes:
    """从 (域, 上传标识, 序号) 确定性派生 12 字节 nonce。"""
    uid = upload_id.encode("utf-8")
    h = hashlib.sha256()
    h.update(b"VG-NONCE")
    h.update(domain)
    h.update(len(uid).to_bytes(4, "big"))
    h.update(uid)
    h.update((-1 if seq is None else seq).to_bytes(8, "big", signed=True))
    return h.digest()[:NONCE_LEN]


def chunk_nonce(upload_id: str, seq: int) -> bytes:
    """为某个分块派生唯一 nonce。"""
    return _domain_nonce(b"chunk", upload_id, seq)


def meta_nonce(upload_id: str) -> bytes:
    """为策略元数据派生唯一 nonce。"""
    return _domain_nonce(b"meta", upload_id, None)


def _aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def _aead_decrypt(key: bytes, nonce: bytes, aad: bytes, blob: bytes, what: str) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, blob, aad)
    except InvalidTag as exc:
        raise IntegrityError(f"{what} 认证失败") from exc


def encrypt_chunk(key: bytes, upload_id: str, seq: int, aad: bytes, plaintext: bytes) -> bytes:
    """AES-GCM 加密一个分块，返回 密文||tag。"""
    return _aead_encrypt(key, chunk_nonce(upload_id, seq), aad, plaintext)


def decrypt_chunk(key: bytes, upload_id: str, seq: int, aad: bytes, blob: bytes) -> bytes:
    """AES-GCM 解密并认证一个分块，失败抛 IntegrityError。"""
    return _aead_decrypt(key, chunk_nonce(upload_id, seq), aad, blob, f"分块 {seq}")


def encrypt_meta(key: bytes, upload_id: str, aad: bytes, plaintext: bytes) -> bytes:
    """加密策略元数据。"""
    return _aead_encrypt(key, meta_nonce(upload_id), aad, plaintext)


def decrypt_meta(key: bytes, upload_id: str, aad: bytes, blob: bytes) -> bytes:
    """解密并认证策略元数据。"""
    return _aead_decrypt(key, meta_nonce(upload_id), aad, blob, "策略元数据")


def chunk_mac(key: bytes, upload_id: str, seq: int, plaintext: bytes) -> bytes:
    """对明文分块计算带密钥的 HMAC，用于重复/冲突检测（密钥不落盘）。"""
    uid = upload_id.encode("utf-8")
    h = hmac.new(key, digestmod=hashlib.sha256)
    h.update(b"VG-CHUNK-MAC")
    h.update(len(uid).to_bytes(4, "big"))
    h.update(uid)
    h.update(seq.to_bytes(8, "big"))
    h.update(plaintext)
    return h.digest()


def header_mac(key: bytes, header_fields: bytes) -> bytes:
    """对容器头关键字段计算 HMAC，保护身份/长度/哈希声明。"""
    return hmac.new(key, b"VG-HEADER" + header_fields, hashlib.sha256).digest()


def meta_mac(key: bytes, upload_id: str, metadata: bytes) -> bytes:
    """对策略元数据计算带密钥的 HMAC，用于声明一致性校验。"""
    uid = upload_id.encode("utf-8")
    h = hmac.new(key, digestmod=hashlib.sha256)
    h.update(b"VG-META-MAC")
    h.update(len(uid).to_bytes(4, "big"))
    h.update(uid)
    h.update(metadata)
    return h.digest()
