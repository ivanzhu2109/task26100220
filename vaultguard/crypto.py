"""密钥派生与 AEAD 加解密辅助。文件密钥仅由调用方传入，绝不落盘。"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import IntegrityError

CHUNK_SIZE: int = 4 * 1024 * 1024  # 4 MiB
KEY_LEN: int = 32
NONCE_LEN: int = 12
TAG_LEN: int = 16

_INFO_CHUNK: bytes = b"vaultguard/chunk/v1"
_INFO_POLICY: bytes = b"vaultguard/policy/v1"
_INFO_HEADER: bytes = b"vaultguard/header/v1"
_INFO_FINGERPRINT: bytes = b"vaultguard/fingerprint/v1"


def validate_key(key: bytes) -> bytes:
    """校验文件密钥为 32 字节，返回原密钥。"""
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
        raise ValueError("file_key 必须为 32 字节的 bytes")
    return bytes(key)


def _hkdf_expand(prk: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_key(file_key: bytes, purpose: bytes) -> bytes:
    """用 HKDF-SHA256 从文件密钥派生指定用途的子密钥。"""
    prk = hmac.new(b"vaultguard-hkdf-salt-v1", file_key, hashlib.sha256).digest()
    return _hkdf_expand(prk, purpose)


def chunk_key(file_key: bytes) -> bytes:
    return derive_key(file_key, _INFO_CHUNK)


def policy_key(file_key: bytes) -> bytes:
    return derive_key(file_key, _INFO_POLICY)


def header_key(file_key: bytes) -> bytes:
    return derive_key(file_key, _INFO_HEADER)


def fingerprint_key(file_key: bytes) -> bytes:
    return derive_key(file_key, _INFO_FINGERPRINT)


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM 加密，返回 密文||标签。"""
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM 解密并校验；失败抛 IntegrityError，绝不返回未认证数据。"""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise IntegrityError("AEAD 校验失败：数据被篡改或不完整") from exc


def hmac_digest(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256，用于分块内容指纹与头部完整性。"""
    return hmac.new(key, data, hashlib.sha256).digest()
