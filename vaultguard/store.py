"""SQLite 持久化：上传声明、分块接收进度、封存状态。不保存任何明文。"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


_SCHEMA = """
CREATE TABLE IF NOT EXISTS uploads (
    upload_id    TEXT PRIMARY KEY,
    total_length INTEGER NOT NULL,
    sha256_hex   TEXT NOT NULL,
    chunk_count  INTEGER NOT NULL,
    policy_ct    BLOB NOT NULL,
    status       TEXT NOT NULL DEFAULT 'receiving',
    vault_path   TEXT
);
CREATE TABLE IF NOT EXISTS chunks (
    upload_id  TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    size       INTEGER NOT NULL,
    plain_hmac BLOB NOT NULL,
    ct_sha256  BLOB NOT NULL,
    PRIMARY KEY (upload_id, seq)
);
"""


@dataclass(frozen=True)
class UploadRecord:
    upload_id: str
    total_length: int
    sha256_hex: str
    chunk_count: int
    policy_ct: bytes
    status: str  # "receiving" | "sealed"
    vault_path: str | None


@dataclass(frozen=True)
class ChunkRecord:
    upload_id: str
    seq: int
    size: int
    plain_hmac: bytes
    ct_sha256: bytes


def _row_to_upload(row: sqlite3.Row) -> UploadRecord:
    return UploadRecord(
        upload_id=row["upload_id"],
        total_length=row["total_length"],
        sha256_hex=row["sha256_hex"],
        chunk_count=row["chunk_count"],
        policy_ct=bytes(row["policy_ct"]),
        status=row["status"],
        vault_path=row["vault_path"],
    )


def _row_to_chunk(row: sqlite3.Row) -> ChunkRecord:
    return ChunkRecord(
        upload_id=row["upload_id"],
        seq=row["seq"],
        size=row["size"],
        plain_hmac=bytes(row["plain_hmac"]),
        ct_sha256=bytes(row["ct_sha256"]),
    )


class Store:
    """封装进度数据库的所有读写。"""

    def __init__(self, db_path: Path) -> None:
        self._conn = sqlite3.connect(str(db_path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def get_upload(self, upload_id: str) -> UploadRecord | None:
        row = self._conn.execute(
            "SELECT * FROM uploads WHERE upload_id = ?", (upload_id,)
        ).fetchone()
        return _row_to_upload(row) if row else None

    def register_upload(
        self,
        upload_id: str,
        total_length: int,
        sha256_hex: str,
        chunk_count: int,
        policy_ct: bytes,
    ) -> UploadRecord:
        """登记新上传；已存在则直接返回已登记记录（一致性由 core 校验）。"""
        existing = self.get_upload(upload_id)
        if existing is not None:
            return existing
        self._conn.execute(
            "INSERT INTO uploads (upload_id, total_length, sha256_hex, chunk_count,"
            " policy_ct, status) VALUES (?, ?, ?, ?, ?, 'receiving')",
            (upload_id, total_length, sha256_hex, chunk_count, policy_ct),
        )
        rec = self.get_upload(upload_id)
        assert rec is not None
        return rec

    def get_chunk(self, upload_id: str, seq: int) -> ChunkRecord | None:
        row = self._conn.execute(
            "SELECT * FROM chunks WHERE upload_id = ? AND seq = ?", (upload_id, seq)
        ).fetchone()
        return _row_to_chunk(row) if row else None

    def put_chunk(self, rec: ChunkRecord) -> None:
        self._conn.execute(
            "INSERT INTO chunks (upload_id, seq, size, plain_hmac, ct_sha256)"
            " VALUES (?, ?, ?, ?, ?)",
            (rec.upload_id, rec.seq, rec.size, rec.plain_hmac, rec.ct_sha256),
        )

    def chunk_map(self, upload_id: str) -> dict[int, ChunkRecord]:
        rows = self._conn.execute(
            "SELECT * FROM chunks WHERE upload_id = ? ORDER BY seq", (upload_id,)
        ).fetchall()
        return {row["seq"]: _row_to_chunk(row) for row in rows}

    def mark_sealed(self, upload_id: str, vault_path: str) -> None:
        self._conn.execute(
            "UPDATE uploads SET status = 'sealed', vault_path = ? WHERE upload_id = ?",
            (vault_path, upload_id),
        )

    def delete_chunks(self, upload_id: str, keep_fingerprints: bool = True) -> None:
        """封存后清理分块暂存信息；保留内容指纹用于迟到重试比对。"""
        if keep_fingerprints:
            # 指纹行仍保留在 chunks 表中，仅由调用方删除暂存文件。
            return
        self._conn.execute("DELETE FROM chunks WHERE upload_id = ?", (upload_id,))
