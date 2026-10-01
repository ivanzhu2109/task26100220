"""SQLite 上传进度存储。只保存密文、HMAC 与状态，绝不保存明文或密钥。"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .errors import ChunkConflictError, DeclarationConflictError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS uploads (
    upload_id    TEXT PRIMARY KEY,
    total_length INTEGER NOT NULL,
    sha256_hex   TEXT NOT NULL,
    enc_meta     BLOB NOT NULL,
    meta_mac     BLOB NOT NULL,
    vault_name   TEXT
);
CREATE TABLE IF NOT EXISTS chunks (
    upload_id TEXT NOT NULL,
    seq       INTEGER NOT NULL,
    mac       BLOB NOT NULL,
    PRIMARY KEY (upload_id, seq)
);
"""


class UploadStore:
    """管理上传进度数据库。"""

    def __init__(self, db_path: Path) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def begin_upload(
        self,
        upload_id: str,
        total_length: int,
        sha256_hex: str,
        enc_meta: bytes,
        meta_mac: bytes,
    ) -> None:
        """登记新上传；若已存在则校验声明一致，否则抛 DeclarationConflictError。"""
        row = self._conn.execute(
            "SELECT total_length, sha256_hex, enc_meta, meta_mac FROM uploads WHERE upload_id=?",
            (upload_id,),
        ).fetchone()
        if row is not None:
            if row[0] != total_length or row[1] != sha256_hex or bytes(row[3]) != meta_mac:
                raise DeclarationConflictError(
                    f"上传 {upload_id!r} 的长度/哈希/策略元数据声明与已登记的不一致"
                )
            return
        with self._conn:
            self._conn.execute(
                "INSERT INTO uploads (upload_id, total_length, sha256_hex, enc_meta, meta_mac)"
                " VALUES (?,?,?,?,?)",
                (upload_id, total_length, sha256_hex, enc_meta, meta_mac),
            )

    def record_chunk(self, upload_id: str, seq: int, mac: bytes) -> None:
        """登记分块 HMAC；同序号不同 mac 抛 ChunkConflictError。"""
        existing = self.get_chunk_mac(upload_id, seq)
        if existing is not None:
            if existing != mac:
                raise ChunkConflictError(
                    f"上传 {upload_id!r} 分块 {seq} 收到与已确认内容不同的数据"
                )
            return
        with self._conn:
            self._conn.execute(
                "INSERT INTO chunks (upload_id, seq, mac) VALUES (?,?,?)",
                (upload_id, seq, mac),
            )

    def get_chunk_mac(self, upload_id: str, seq: int) -> bytes | None:
        row = self._conn.execute(
            "SELECT mac FROM chunks WHERE upload_id=? AND seq=?", (upload_id, seq)
        ).fetchone()
        return bytes(row[0]) if row else None

    def received_seqs(self, upload_id: str) -> set[int]:
        rows = self._conn.execute(
            "SELECT seq FROM chunks WHERE upload_id=?", (upload_id,)
        ).fetchall()
        return {r[0] for r in rows}

    def get_declaration(self, upload_id: str) -> tuple[int, str, bytes, bytes] | None:
        """返回 (total_length, sha256_hex, enc_meta, meta_mac) 或 None。"""
        row = self._conn.execute(
            "SELECT total_length, sha256_hex, enc_meta, meta_mac FROM uploads WHERE upload_id=?",
            (upload_id,),
        ).fetchone()
        if row is None:
            return None
        return (row[0], row[1], bytes(row[2]), bytes(row[3]))

    def mark_sealed(self, upload_id: str, vault_name: str) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE uploads SET vault_name=? WHERE upload_id=?",
                (vault_name, upload_id),
            )

    def get_sealed(self, upload_id: str) -> str | None:
        """已封存则返回 vault 文件名，否则 None。"""
        row = self._conn.execute(
            "SELECT vault_name FROM uploads WHERE upload_id=?", (upload_id,)
        ).fetchone()
        return row[0] if row and row[0] else None

    def close(self) -> None:
        self._conn.close()
