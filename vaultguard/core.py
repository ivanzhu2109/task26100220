"""VaultGuard 主入口：提交分块、封存文件、逐段读回。

安全要点：
- 文件密钥 file_key 由调用方每次调用时传入，绝不写入磁盘或数据库。
- 明文（文件内容、策略元数据）只存在于内存；落盘的只有 AEAD 密文、
  HMAC 指纹与哈希。
- 每个分块以 AES-256-GCM 加密，AAD 绑定上传标识、序号、总长度、
  明文 SHA-256 与策略密文哈希，调块/篡改/截断均无法通过校验。
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from . import crypto
from .container import (
    ContainerHeader,
    chunk_cipher_size,
    chunk_plain_size,
    header_signing_payload,
    read_container,
    write_container,
)
from .errors import (
    ChunkConflictError,
    DeclarationConflictError,
    IntegrityError,
    InvalidChunkError,
    NotSealReadyError,
    UploadNotFoundError,
)
from .store import ChunkRecord, Store, UploadRecord

_UPLOAD_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


@dataclass(frozen=True)
class UploadDecl:
    """调用方对一次上传的声明；同一上传标识下不可改变。"""

    total_length: int        # 非空文件总长度（>0）
    sha256_hex: str          # 完整明文的 SHA-256（十六进制）
    policy: bytes            # 策略元数据（将被加密保护）


def _chunk_count(total_length: int) -> int:
    return (total_length + crypto.CHUNK_SIZE - 1) // crypto.CHUNK_SIZE


def _expected_chunk_size(total_length: int, seq: int) -> int:
    count = _chunk_count(total_length)
    if seq < count - 1:
        return crypto.CHUNK_SIZE
    return total_length - crypto.CHUNK_SIZE * (count - 1)


def _aad_prefix(tag: bytes, upload_id: str, total_length: int, sha256_hex: str) -> bytes:
    uid = upload_id.encode("utf-8")
    return (
        tag
        + struct.pack(">H", len(uid))
        + uid
        + struct.pack(">Q", total_length)
        + bytes.fromhex(sha256_hex)
    )


def _policy_aad(upload_id: str, total_length: int, sha256_hex: str) -> bytes:
    return _aad_prefix(b"VG1P", upload_id, total_length, sha256_hex)


def _chunk_aad(
    upload_id: str,
    seq: int,
    total_length: int,
    sha256_hex: str,
    policy_ct: bytes,
) -> bytes:
    return (
        _aad_prefix(b"VG1C", upload_id, total_length, sha256_hex)
        + struct.pack(">I", seq)
        + hashlib.sha256(policy_ct).digest()
    )


class VaultGuard:
    """加密续传库。file_key 由调用方每次调用时提供，绝不落盘。"""

    def __init__(self, data_dir: str | Path) -> None:
        self._dir = Path(data_dir)
        self._staging = self._dir / "staging"
        self._vaults = self._dir / "vaults"
        self._staging.mkdir(parents=True, exist_ok=True)
        self._vaults.mkdir(parents=True, exist_ok=True)
        self._store = Store(self._dir / "progress.db")

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "VaultGuard":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ 提交

    def submit_chunk(
        self,
        upload_id: str,
        file_key: bytes,
        decl: UploadDecl,
        seq: int,
        data: bytes,
    ) -> None:
        """提交一个分块（可乱序、可重试）。相同内容重试幂等；不同内容拒绝。"""
        key = crypto.validate_key(file_key)
        self._validate_upload_id(upload_id)
        self._validate_decl(decl)
        rec = self._register(upload_id, key, decl)
        count = rec.chunk_count
        if not 0 <= seq < count:
            raise InvalidChunkError(f"分块序号越界: seq={seq}, 共 {count} 块")
        expected = _expected_chunk_size(rec.total_length, seq)
        if len(data) != expected:
            raise InvalidChunkError(
                f"分块 {seq} 长度应为 {expected} 字节，实际 {len(data)}"
            )

        fingerprint = crypto.hmac_digest(
            crypto.fingerprint_key(key), struct.pack(">I", seq) + data
        )
        existing = self._store.get_chunk(upload_id, seq)
        if existing is not None:
            if existing.size == len(data) and existing.plain_hmac == fingerprint:
                return  # 相同内容的重试：幂等成功（含封存后的迟到重试）
            raise ChunkConflictError(
                f"上传 {upload_id!r} 分块 {seq} 已存在不同内容，拒绝覆盖"
            )

        nonce = os.urandom(crypto.NONCE_LEN)
        ct = crypto.aead_encrypt(
            crypto.chunk_key(key),
            nonce,
            data,
            _chunk_aad(upload_id, seq, rec.total_length, rec.sha256_hex, rec.policy_ct),
        )
        blob = nonce + ct
        part = self._staging / upload_id / f"{seq:08d}.part"
        self._write_atomic(part, blob)
        self._store.put_chunk(
            ChunkRecord(
                upload_id=upload_id,
                seq=seq,
                size=len(data),
                plain_hmac=fingerprint,
                ct_sha256=hashlib.sha256(blob).digest(),
            )
        )

    # ------------------------------------------------------------------ 封存

    def seal(self, upload_id: str, file_key: bytes) -> Path:
        """分块齐全且明文长度/SHA-256 符合声明后封存为 .vault；重复封存返回同一路径。"""
        key = crypto.validate_key(file_key)
        self._validate_upload_id(upload_id)
        rec = self._require_upload(upload_id)
        vault = self._vaults / f"{upload_id}.vault"
        if rec.status == "sealed":
            if rec.vault_path and Path(rec.vault_path).is_file():
                return Path(rec.vault_path)  # 幂等：同一个不可变成品
            raise IntegrityError(f"上传 {upload_id!r} 已封存但容器文件缺失")

        chunks = self._store.chunk_map(upload_id)
        if len(chunks) != rec.chunk_count:
            raise NotSealReadyError(
                f"分块未齐全: {len(chunks)}/{rec.chunk_count}"
            )

        hasher = hashlib.sha256()
        nonces: list[bytes] = []
        cts: list[bytes] = []
        total = 0
        for seq in range(rec.chunk_count):
            crec = chunks[seq]
            blob = (self._staging / upload_id / f"{seq:08d}.part").read_bytes()
            if hashlib.sha256(blob).digest() != crec.ct_sha256:
                raise IntegrityError(f"暂存分块 {seq} 密文与登记不符")
            nonce, ct = blob[: crypto.NONCE_LEN], blob[crypto.NONCE_LEN :]
            plain = crypto.aead_decrypt(
                crypto.chunk_key(key),
                nonce,
                ct,
                _chunk_aad(
                    upload_id, seq, rec.total_length, rec.sha256_hex, rec.policy_ct
                ),
            )
            if len(plain) != crec.size:
                raise IntegrityError(f"暂存分块 {seq} 长度与登记不符")
            hasher.update(plain)
            total += len(plain)
            nonces.append(nonce)
            cts.append(ct)

        if total != rec.total_length or hasher.hexdigest() != rec.sha256_hex:
            raise NotSealReadyError("拼接后的明文长度或 SHA-256 与声明不符，拒绝封存")

        header = ContainerHeader(
            upload_id=upload_id,
            total_length=rec.total_length,
            sha256_hex=rec.sha256_hex,
            chunk_size=crypto.CHUNK_SIZE,
            chunk_count=rec.chunk_count,
            policy_ct=rec.policy_ct,
            chunk_nonces=tuple(nonces),
            header_mac=b"",
        )
        mac = crypto.hmac_digest(
            crypto.header_key(key), header_signing_payload(header)
        )
        header = ContainerHeader(**{**header.__dict__, "header_mac": mac})
        write_container(vault, header, cts)
        self._store.mark_sealed(upload_id, str(vault))
        for seq in range(rec.chunk_count):
            try:
                os.unlink(self._staging / upload_id / f"{seq:08d}.part")
            except OSError:
                pass
        try:
            (self._staging / upload_id).rmdir()
        except OSError:
            pass
        return vault

    # ------------------------------------------------------------------ 读回

    def vault_path(self, upload_id: str) -> Path | None:
        """已封存则返回 .vault 路径，否则 None。"""
        rec = self._store.get_upload(upload_id)
        if rec and rec.status == "sealed" and rec.vault_path:
            return Path(rec.vault_path)
        return None

    def read_chunk(self, upload_id: str, file_key: bytes, seq: int) -> bytes:
        """逐段读回：完整性校验通过才返回明文，否则抛 IntegrityError。"""
        key = crypto.validate_key(file_key)
        rec = self._require_upload(upload_id)
        if rec.status != "sealed" or not rec.vault_path:
            raise UploadNotFoundError(f"上传 {upload_id!r} 尚未封存")
        header, ciphertext = read_container(Path(rec.vault_path))
        if header.upload_id != upload_id:
            raise IntegrityError("容器身份与请求的上传标识不符")
        if (
            header.total_length != rec.total_length
            or header.sha256_hex != rec.sha256_hex
        ):
            raise IntegrityError("容器声明与登记信息不符")
        expect_mac = crypto.hmac_digest(
            crypto.header_key(key), header_signing_payload(header)
        )
        if expect_mac != header.header_mac:
            raise IntegrityError("容器头部完整性校验失败")
        if not 0 <= seq < header.chunk_count:
            raise InvalidChunkError(f"分块序号越界: seq={seq}")
        offset = sum(chunk_cipher_size(header, s) for s in range(seq))
        size = chunk_cipher_size(header, seq)
        ct = ciphertext[offset : offset + size]
        return crypto.aead_decrypt(
            crypto.chunk_key(key),
            header.chunk_nonces[seq],
            ct,
            _chunk_aad(
                upload_id, seq, header.total_length, header.sha256_hex, header.policy_ct
            ),
        )

    def read_all(self, upload_id: str, file_key: bytes) -> bytes:
        """便捷方法：按序读回全部明文，并整体复核 SHA-256。"""
        rec = self._require_upload(upload_id)
        parts = [self.read_chunk(upload_id, file_key, s) for s in range(rec.chunk_count)]
        blob = b"".join(parts)
        if len(blob) != rec.total_length or hashlib.sha256(blob).hexdigest() != rec.sha256_hex:
            raise IntegrityError("整体明文与声明不符")
        return blob

    # ------------------------------------------------------------------ 内部

    def _register(self, upload_id: str, key: bytes, decl: UploadDecl) -> UploadRecord:
        count = _chunk_count(decl.total_length)
        rec = self._store.get_upload(upload_id)
        if rec is None:
            nonce = os.urandom(crypto.NONCE_LEN)
            policy_ct = nonce + crypto.aead_encrypt(
                crypto.policy_key(key),
                nonce,
                decl.policy,
                _policy_aad(upload_id, decl.total_length, decl.sha256_hex),
            )
            return self._store.register_upload(
                upload_id, decl.total_length, decl.sha256_hex.lower(), count, policy_ct
            )
        if (
            rec.total_length != decl.total_length
            or rec.sha256_hex != decl.sha256_hex.lower()
        ):
            raise DeclarationConflictError(
                f"上传 {upload_id!r} 的总长度或 SHA-256 与已登记声明不一致"
            )
        plain_policy = crypto.aead_decrypt(
            crypto.policy_key(key),
            rec.policy_ct[: crypto.NONCE_LEN],
            rec.policy_ct[crypto.NONCE_LEN :],
            _policy_aad(upload_id, rec.total_length, rec.sha256_hex),
        )
        if plain_policy != decl.policy:
            raise DeclarationConflictError(
                f"上传 {upload_id!r} 的策略元数据与已登记声明不一致"
            )
        return rec

    def _require_upload(self, upload_id: str) -> UploadRecord:
        rec = self._store.get_upload(upload_id)
        if rec is None:
            raise UploadNotFoundError(f"上传 {upload_id!r} 不存在")
        return rec

    @staticmethod
    def _validate_upload_id(upload_id: str) -> None:
        if not _UPLOAD_ID_RE.match(upload_id):
            raise ValueError("upload_id 仅允许字母数字及 . _ -，长度 1-128")

    @staticmethod
    def _validate_decl(decl: UploadDecl) -> None:
        if decl.total_length <= 0:
            raise ValueError("total_length 必须为正（不接受空文件）")
        try:
            raw = bytes.fromhex(decl.sha256_hex)
        except ValueError:
            raise ValueError("sha256_hex 必须是十六进制字符串") from None
        if len(raw) != 32:
            raise ValueError("sha256_hex 必须是 64 个十六进制字符")
        if not isinstance(decl.policy, (bytes, bytearray)):
            raise ValueError("policy 必须为 bytes")

    @staticmethod
    def _write_atomic(path: Path, blob: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp." + os.urandom(6).hex())
        try:
            with open(tmp, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
