"""VaultGuard 主接口：提交分块、封存文件、逐段读回。"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from pathlib import Path

from . import container, crypto
from .errors import (
    IntegrityError,
    InvalidChunkError,
    UnknownUploadError,
    UploadIncompleteError,
)
from .store import UploadStore

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _chunk_count(total_length: int) -> int:
    return (total_length + crypto.CHUNK_SIZE - 1) // crypto.CHUNK_SIZE


def _chunk_aad(total_length: int, chunk_count: int, seq: int) -> bytes:
    """分块 AAD：绑定总长度、分块数与序号，防止跨声明移植与调序。"""
    return b"VG-CHUNK" + struct.pack(">QII", total_length, chunk_count, seq)


class VaultGuard:
    """加密续传库入口。调用方负责鉴权并为每次调用提供文件密钥。"""

    def __init__(self, work_dir: Path | str) -> None:
        """work_dir 下创建 state.sqlite、staging/ 与 vaults/。"""
        self._dir = Path(work_dir)
        self._staging = self._dir / "staging"
        self._vaults = self._dir / "vaults"
        self._staging.mkdir(parents=True, exist_ok=True)
        self._vaults.mkdir(parents=True, exist_ok=True)
        self._store = UploadStore(self._dir / "state.sqlite")

    # ---- 内部辅助 ----

    def _safe_name(self, upload_id: str) -> str:
        """把上传标识映射为安全的文件名，避免路径穿越。"""
        return hashlib.sha256(upload_id.encode("utf-8")).hexdigest()

    def _staging_dir(self, upload_id: str) -> Path:
        return self._staging / self._safe_name(upload_id)

    def _vault_path(self, upload_id: str) -> Path:
        return self._vaults / (self._safe_name(upload_id) + ".vault")

    @staticmethod
    def _validate_declaration(total_length: int, sha256_hex: str) -> None:
        if not isinstance(total_length, int) or total_length <= 0:
            raise InvalidChunkError("总长度必须为正整数（文件非空）")
        if not _SHA256_RE.match(sha256_hex):
            raise InvalidChunkError("sha256_hex 必须为 64 个小写十六进制字符")

    def _register(
        self,
        key: bytes,
        upload_id: str,
        total_length: int,
        sha256_hex: str,
        metadata: bytes,
    ) -> None:
        """登记/校验上传声明，声明不可变。"""
        self._validate_declaration(total_length, sha256_hex)
        enc_meta = crypto.encrypt_meta(key, upload_id, sha256_hex.encode("ascii"), metadata)
        self._store.begin_upload(
            upload_id,
            total_length,
            sha256_hex,
            enc_meta,
            crypto.meta_mac(key, upload_id, metadata),
        )

    # ---- 提交分块 ----

    def submit_chunk(
        self,
        key: bytes,
        upload_id: str,
        total_length: int,
        sha256_hex: str,
        metadata: bytes,
        seq: int,
        data: bytes,
    ) -> bool:
        """提交一个分块。重复提交相同内容返回 False（幂等），新写入返回 True。"""
        key = crypto.validate_key(key)
        self._register(key, upload_id, total_length, sha256_hex, metadata)

        count = _chunk_count(total_length)
        if not isinstance(seq, int) or not 0 <= seq < count:
            raise InvalidChunkError(f"分块序号 {seq!r} 超出范围 [0, {count})")
        expected = min(crypto.CHUNK_SIZE, total_length - seq * crypto.CHUNK_SIZE)
        if len(data) != expected or len(data) == 0:
            raise InvalidChunkError(
                f"分块 {seq} 长度应为 {expected} 字节，实际 {len(data)} 字节"
            )

        mac = crypto.chunk_mac(key, upload_id, seq, data)
        if self._store.get_chunk_mac(upload_id, seq) is not None:
            # 已确认过的分块：相同则幂等成功，不同则拒绝且不触碰原数据。
            self._store.record_chunk(upload_id, seq, mac)
            return False
        self._store.record_chunk(upload_id, seq, mac)

        aad = _chunk_aad(total_length, count, seq)
        blob = crypto.encrypt_chunk(key, upload_id, seq, aad, data)
        sdir = self._staging_dir(upload_id)
        sdir.mkdir(parents=True, exist_ok=True)
        tmp = sdir / f"{seq}.tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, sdir / f"{seq}.bin")
        return True

    # ---- 封存 ----

    def seal(
        self,
        key: bytes,
        upload_id: str,
        total_length: int,
        sha256_hex: str,
        metadata: bytes,
    ) -> Path:
        """全部齐且校验通过则封存，返回 .vault 路径；重复封存返回同一路径。"""
        key = crypto.validate_key(key)
        self._register(key, upload_id, total_length, sha256_hex, metadata)

        existing = self._store.get_sealed(upload_id)
        if existing is not None:
            path = self._vaults / existing
            if not path.exists():
                raise IntegrityError(f"上传 {upload_id!r} 已封存但容器文件缺失")
            return path

        decl = self._store.get_declaration(upload_id)
        if decl is None:
            raise UnknownUploadError(f"上传 {upload_id!r} 不存在")
        _, _, enc_meta, _ = decl

        count = _chunk_count(total_length)
        received = self._store.received_seqs(upload_id)
        missing = [i for i in range(count) if i not in received]
        if missing:
            raise UploadIncompleteError(f"上传 {upload_id!r} 缺少分块: {missing}")

        sdir = self._staging_dir(upload_id)
        enc_chunks: list[bytes] = []
        hasher = hashlib.sha256()
        written = 0
        for seq in range(count):
            blob_path = sdir / f"{seq}.bin"
            if not blob_path.exists():
                raise IntegrityError(f"分块 {seq} 的暂存数据缺失")
            blob = blob_path.read_bytes()
            plain = crypto.decrypt_chunk(
                key, upload_id, seq, _chunk_aad(total_length, count, seq), blob
            )
            mac = crypto.chunk_mac(key, upload_id, seq, plain)
            if mac != self._store.get_chunk_mac(upload_id, seq):
                raise IntegrityError(f"分块 {seq} 与已确认内容不符")
            hasher.update(plain)
            written += len(plain)
            enc_chunks.append(blob)

        if written != total_length:
            raise IntegrityError(f"拼接长度 {written} 与声明 {total_length} 不符")
        if hasher.hexdigest() != sha256_hex:
            raise IntegrityError("拼接明文的 SHA-256 与声明不符")

        fields = container.build_header(
            upload_id, total_length, sha256_hex, count, enc_meta, b"\x00" * 32
        )[:-32]
        header = container.build_header(
            upload_id,
            total_length,
            sha256_hex,
            count,
            enc_meta,
            crypto.header_mac(key, fields),
        )
        vault_name = self._vault_path(upload_id).name
        container.write_container(self._vaults / vault_name, header, enc_chunks)
        self._store.mark_sealed(upload_id, vault_name)

        for seq in range(count):
            (sdir / f"{seq}.bin").unlink(missing_ok=True)
        try:
            sdir.rmdir()
        except OSError:
            pass
        return self._vaults / vault_name

    # ---- 读回 ----

    def _load_container(self, key: bytes, vault_path: Path | str) -> tuple[dict, bytes]:
        data = Path(vault_path).read_bytes()
        header = container.parse_header(data)
        if crypto.header_mac(key, header["mac_coverage"]) != header["header_mac"]:
            raise IntegrityError("容器头认证失败（身份/长度/元数据声明被篡改）")
        return header, data

    def read_chunk(self, key: bytes, vault_path: Path | str, seq: int) -> bytes:
        """认证并读回第 seq 段明文；任何篡改都会抛 IntegrityError。"""
        key = crypto.validate_key(key)
        header, data = self._load_container(key, vault_path)
        count = header["chunk_count"]
        if not isinstance(seq, int) or not 0 <= seq < count:
            raise InvalidChunkError(f"分块序号 {seq!r} 超出范围 [0, {count})")
        offsets = container.chunk_offsets(header, header["header_len"])
        expected_total = offsets[-1][0] + offsets[-1][1]
        if len(data) != expected_total:
            raise IntegrityError("容器长度与声明不符（被截断或追加）")
        off, length = offsets[seq]
        blob = data[off : off + length]
        return crypto.decrypt_chunk(
            key,
            header["upload_id"],
            seq,
            _chunk_aad(header["total_length"], count, seq),
            blob,
        )

    def read_all(self, key: bytes, vault_path: Path | str) -> bytes:
        """读回完整明文并校验整体 SHA-256。"""
        key = crypto.validate_key(key)
        header, _ = self._load_container(key, vault_path)
        parts = [
            self.read_chunk(key, vault_path, seq)
            for seq in range(header["chunk_count"])
        ]
        plain = b"".join(parts)
        if len(plain) != header["total_length"]:
            raise IntegrityError("明文总长度与声明不符")
        if hashlib.sha256(plain).hexdigest() != header["sha256_hex"]:
            raise IntegrityError("明文 SHA-256 与声明不符")
        return plain

    def read_metadata(self, key: bytes, vault_path: Path | str) -> bytes:
        """认证并读回策略元数据。"""
        key = crypto.validate_key(key)
        header, _ = self._load_container(key, vault_path)
        return crypto.decrypt_meta(
            key,
            header["upload_id"],
            header["sha256_hex"].encode("ascii"),
            header["enc_meta"],
        )

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "VaultGuard":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
