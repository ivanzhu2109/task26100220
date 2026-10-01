"""VaultGuard 自动化测试。"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from vaultguard import (
    ChunkConflictError,
    DeclarationConflictError,
    IntegrityError,
    InvalidChunkError,
    UploadIncompleteError,
    VaultGuard,
)
from vaultguard.crypto import CHUNK_SIZE

KEY = bytes(range(32))
META = b'{"retention":"7y","level":"secret"}'


def make_file(nchunks: int, tail: int = 1000) -> bytes:
    """生成 nchunks 个整块加一段尾块的确定性数据。"""
    rng = 0
    out = bytearray()
    total = (nchunks - 1) * CHUNK_SIZE + tail
    while len(out) < total:
        out += hashlib.sha256(struct.pack(">Q", rng)).digest()
        rng += 1
    return bytes(out[:total])


def chunks_of(data: bytes) -> list[bytes]:
    return [data[i : i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]


class VaultGuardTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="vg-test-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.vg = VaultGuard(self.dir)
        self.addCleanup(self.vg.close)
        self.data = make_file(3)  # 2 整块 + 尾块
        self.sha = hashlib.sha256(self.data).hexdigest()
        self.parts = chunks_of(self.data)
        self.uid = "upload-001"

    def submit(self, seq: int, uid: str | None = None, **kw) -> bool:
        args = dict(
            key=KEY,
            upload_id=uid or self.uid,
            total_length=len(self.data),
            sha256_hex=self.sha,
            metadata=META,
            seq=seq,
            data=self.parts[seq] if seq < len(self.parts) else b"x",
        )
        args.update(kw)
        return self.vg.submit_chunk(**args)


class TestResumableUpload(VaultGuardTestBase):
    def test_out_of_order_and_duplicate_and_conflict(self) -> None:
        # 乱序到达
        self.assertTrue(self.submit(2))
        self.assertTrue(self.submit(0))
        # 缺块时不能封存
        with self.assertRaises(UploadIncompleteError):
            self.vg.seal(KEY, self.uid, len(self.data), self.sha, META)
        self.assertTrue(self.submit(1))

        # 相同内容重复提交：幂等，视为同一次写入
        self.assertFalse(self.submit(1))
        self.assertFalse(self.submit(0))

        # 冲突内容：拒绝，且原内容不被破坏
        bad = bytes(len(self.parts[1]))
        with self.assertRaises(ChunkConflictError):
            self.submit(1, data=bad)
        self.assertFalse(self.submit(1))  # 原内容仍在

        path1 = self.vg.seal(KEY, self.uid, len(self.data), self.sha, META)
        # 重复封存：同一路径、同一文件，不生成另一份
        path2 = self.vg.seal(KEY, self.uid, len(self.data), self.sha, META)
        self.assertEqual(path1, path2)
        vaults = list((self.dir / "vaults").glob("*.vault"))
        self.assertEqual(len(vaults), 1)

        # 封存后相同分块的迟到重试仍成功（幂等）
        self.assertFalse(self.submit(2))
        # 封存后冲突重试仍被拒绝
        with self.assertRaises(ChunkConflictError):
            self.submit(2, data=bytes(len(self.parts[2])))

        # 读回逐字节一致，SHA-256 与独立计算一致
        back = self.vg.read_all(KEY, path1)
        self.assertEqual(back, self.data)
        self.assertEqual(hashlib.sha256(back).hexdigest(), self.sha)
        for i, part in enumerate(self.parts):
            self.assertEqual(self.vg.read_chunk(KEY, path1, i), part)
        self.assertEqual(self.vg.read_metadata(KEY, path1), META)

    def test_declaration_immutable(self) -> None:
        self.submit(0)
        with self.assertRaises(DeclarationConflictError):
            self.submit(1, total_length=len(self.data) + 1)
        with self.assertRaises(DeclarationConflictError):
            self.submit(1, sha256_hex=hashlib.sha256(b"x").hexdigest())
        with self.assertRaises(DeclarationConflictError):
            self.submit(1, metadata=b'{"level":"public"}')
        # 正常提交不受影响
        self.assertTrue(self.submit(1))

    def test_invalid_chunks_rejected(self) -> None:
        with self.assertRaises(InvalidChunkError):
            self.submit(3)  # 序号越界
        with self.assertRaises(InvalidChunkError):
            self.submit(0, data=self.parts[0][:-1])  # 长度不符
        with self.assertRaises(InvalidChunkError):
            self.submit(0, total_length=0)  # 空文件不允许
        with self.assertRaises(ValueError):
            self.submit(0, key=b"short")

    def test_no_plaintext_on_disk(self) -> None:
        marker = b"TOP-SECRET-PAYLOAD-MARKER" * 100
        data = marker + os.urandom(CHUNK_SIZE) + marker
        sha = hashlib.sha256(data).hexdigest()
        meta = b"POLICY:ULTRA-CONFIDENTIAL-MARKER"
        parts = chunks_of(data)
        for i in (1, 0):
            self.vg.submit_chunk(KEY, "up-secret", len(data), sha, meta, i, parts[i])
        # 封存前：暂存与 SQLite 中不得出现明文
        self._assert_no_plaintext()
        path = self.vg.seal(KEY, "up-secret", len(data), sha, meta)
        # 封存后：容器与 SQLite 中同样不得出现明文
        self._assert_no_plaintext()
        self.assertEqual(self.vg.read_all(KEY, path), data)

    def _assert_no_plaintext(self) -> None:
        for p in self.dir.rglob("*"):
            if p.is_file():
                blob = p.read_bytes()
                self.assertNotIn(b"TOP-SECRET-PAYLOAD-MARKER", blob, p.name)
                self.assertNotIn(b"ULTRA-CONFIDENTIAL-MARKER", blob, p.name)
                self.assertNotIn(b"range(32)", blob)  # 密钥不得落盘
                self.assertNotIn(KEY, blob, p.name)


class TestTamperDetection(VaultGuardTestBase):
    def setUp(self) -> None:
        super().setUp()
        for i in (2, 0, 1):
            self.submit(i)
        self.path = self.vg.seal(KEY, self.uid, len(self.data), self.sha, META)
        self.blob = self.path.read_bytes()

    def _write_tampered(self, blob: bytes) -> Path:
        p = self.dir / "tampered.vault"
        p.write_bytes(blob)
        return p

    def test_flip_ciphertext_byte(self) -> None:
        b = bytearray(self.blob)
        b[-1] ^= 0x01  # 最后一块密文
        p = self._write_tampered(bytes(b))
        with self.assertRaises(IntegrityError):
            self.vg.read_all(KEY, p)
        with self.assertRaises(IntegrityError):
            self.vg.read_chunk(KEY, p, 2)
        # 未受影响的分块也不可从未通过整体校验的容器里被当作成功读取
        self.assertEqual(self.vg.read_chunk(KEY, p, 0), self.parts[0])

    def test_flip_header_byte(self) -> None:
        b = bytearray(self.blob)
        b[20] ^= 0x01  # 头内声明字段
        p = self._write_tampered(bytes(b))
        with self.assertRaises(IntegrityError):
            self.vg.read_all(KEY, p)
        with self.assertRaises(IntegrityError):
            self.vg.read_chunk(KEY, p, 0)
        with self.assertRaises(IntegrityError):
            self.vg.read_metadata(KEY, p)

    def test_flip_metadata_byte(self) -> None:
        # 定位元数据密文并翻转一字节
        pos = 8
        (uid_len,) = struct.unpack_from(">I", self.blob, pos)
        pos += 4 + uid_len + 8 + 4 + 64
        (meta_len,) = struct.unpack_from(">I", self.blob, pos)
        pos += 4
        b = bytearray(self.blob)
        b[pos] ^= 0x01
        p = self._write_tampered(bytes(b))
        with self.assertRaises(IntegrityError):
            self.vg.read_metadata(KEY, p)
        with self.assertRaises(IntegrityError):
            self.vg.read_all(KEY, p)
        _ = meta_len

    def test_truncate_container(self) -> None:
        p = self._write_tampered(self.blob[:-100])
        with self.assertRaises(IntegrityError):
            self.vg.read_all(KEY, p)
        with self.assertRaises(IntegrityError):
            self.vg.read_chunk(KEY, p, 2)

    def test_append_garbage(self) -> None:
        p = self._write_tampered(self.blob + b"extra")
        with self.assertRaises(IntegrityError):
            self.vg.read_all(KEY, p)

    def test_swap_chunks(self) -> None:
        # 调换分块 0 与分块 1 的密文（两者等长）
        from vaultguard import container as c

        header = c.parse_header(self.blob)
        offsets = c.chunk_offsets(header, header["header_len"])
        (o0, l0), (o1, l1) = offsets[0], offsets[1]
        self.assertEqual(l0, l1)
        b = bytearray(self.blob)
        b[o0 : o0 + l0], b[o1 : o1 + l1] = self.blob[o1 : o1 + l1], self.blob[o0 : o0 + l0]
        p = self._write_tampered(bytes(b))
        with self.assertRaises(IntegrityError):
            self.vg.read_all(KEY, p)
        with self.assertRaises(IntegrityError):
            self.vg.read_chunk(KEY, p, 0)

    def test_wrong_key_rejected(self) -> None:
        with self.assertRaises(IntegrityError):
            self.vg.read_all(os.urandom(32), self.path)

    def test_forged_chunk_rejected(self) -> None:
        # 用另一把钥匙伪造的分块不能通过认证
        from vaultguard import container as c
        from vaultguard.crypto import encrypt_chunk

        header = c.parse_header(self.blob)
        offsets = c.chunk_offsets(header, header["header_len"])
        o0, l0 = offsets[0]
        forged = encrypt_chunk(os.urandom(32), self.uid, 0, b"", os.urandom(l0 - 16))
        b = bytearray(self.blob)
        b[o0 : o0 + l0] = forged
        p = self._write_tampered(bytes(b))
        with self.assertRaises(IntegrityError):
            self.vg.read_chunk(KEY, p, 0)


class TestPersistence(unittest.TestCase):
    def test_restart_keeps_confirmed_chunks(self) -> None:
        d = Path(tempfile.mkdtemp(prefix="vg-test-"))
        self.addCleanup(shutil.rmtree, d, True)
        data = make_file(2)
        sha = hashlib.sha256(data).hexdigest()
        parts = chunks_of(data)

        vg = VaultGuard(d)
        vg.submit_chunk(KEY, "up-r", len(data), sha, META, 0, parts[0])
        vg.close()

        # 模拟客户端重启：新实例复用 SQLite，已确认分块不丢
        vg2 = VaultGuard(d)
        self.addCleanup(vg2.close)
        self.assertFalse(vg2.submit_chunk(KEY, "up-r", len(data), sha, META, 0, parts[0]))
        with self.assertRaises(ChunkConflictError):
            vg2.submit_chunk(KEY, "up-r", len(data), sha, META, 0, bytes(len(parts[0])))
        self.assertTrue(vg2.submit_chunk(KEY, "up-r", len(data), sha, META, 1, parts[1]))
        path = vg2.seal(KEY, "up-r", len(data), sha, META)
        self.assertEqual(vg2.read_all(KEY, path), data)


if __name__ == "__main__":
    unittest.main()
