"""VaultGuard 自动化测试。

通过 monkeypatch 把分块大小缩到 64 字节，以便快速构造多块文件；
核心逻辑（乱序、重试、封存、完整性）与 4MiB 场景完全一致。
"""

from __future__ import annotations

import hashlib
import os
import struct

import pytest

import vaultguard.crypto as crypto
from vaultguard import (
    ChunkConflictError,
    DeclarationConflictError,
    IntegrityError,
    InvalidChunkError,
    NotSealReadyError,
    UploadDecl,
    VaultGuard,
)
from vaultguard.container import MAGIC

CHUNK = 64  # 测试用分块大小


@pytest.fixture(autouse=True)
def small_chunks(monkeypatch):
    monkeypatch.setattr(crypto, "CHUNK_SIZE", CHUNK)


@pytest.fixture()
def key():
    return os.urandom(32)


def make_file(nchunks: int, tail: int = 17) -> tuple[bytes, list[bytes]]:
    plain = os.urandom((nchunks - 1) * CHUNK + tail)
    chunks = [plain[i : i + CHUNK] for i in range(0, len(plain), CHUNK)]
    return plain, chunks


def decl_of(plain: bytes, policy: bytes = b'{"level":"secret","dept":"fin"}') -> UploadDecl:
    return UploadDecl(len(plain), hashlib.sha256(plain).hexdigest(), policy)


def submit_all(vg: VaultGuard, uid: str, key: bytes, decl: UploadDecl, chunks, order=None):
    for seq in (order if order is not None else range(len(chunks))):
        vg.submit_chunk(uid, key, decl, seq, chunks[seq])


# ---------------------------------------------------------------- 基本流程

def test_out_of_order_upload_and_readback(tmp_path, key):
    plain, chunks = make_file(7)
    decl = decl_of(plain)
    with VaultGuard(tmp_path) as vg:
        submit_all(vg, "up", key, decl, chunks, order=[3, 0, 6, 1, 5, 2, 4])
        vault = vg.seal("up", key)
        assert vault.is_file()
        back = vg.read_all("up", key)
        assert back == plain
        # 与独立计算的 SHA-256 对照
        assert hashlib.sha256(back).hexdigest() == hashlib.sha256(plain).hexdigest()
        for i, c in enumerate(chunks):
            assert vg.read_chunk("up", key, i) == c


def test_single_chunk_file(tmp_path, key):
    plain, chunks = make_file(1, tail=10)
    decl = decl_of(plain)
    with VaultGuard(tmp_path) as vg:
        submit_all(vg, "one", key, decl, chunks)
        vg.seal("one", key)
        assert vg.read_all("one", key) == plain


# ---------------------------------------------------------------- 重试与冲突

def test_duplicate_same_chunk_is_idempotent(tmp_path, key):
    plain, chunks = make_file(3)
    decl = decl_of(plain)
    with VaultGuard(tmp_path) as vg:
        vg.submit_chunk("up", key, decl, 0, chunks[0])
        vg.submit_chunk("up", key, decl, 0, chunks[0])  # 相同内容重试
        vg.submit_chunk("up", key, decl, 1, chunks[1])
        vg.submit_chunk("up", key, decl, 2, chunks[2])
        vg.seal("up", key)
        assert vg.read_all("up", key) == plain


def test_conflicting_chunk_rejected_and_original_kept(tmp_path, key):
    plain, chunks = make_file(3)
    decl = decl_of(plain)
    with VaultGuard(tmp_path) as vg:
        vg.submit_chunk("up", key, decl, 1, chunks[1])
        with pytest.raises(ChunkConflictError):
            vg.submit_chunk("up", key, decl, 1, os.urandom(CHUNK))
        # 原内容未被破坏
        vg.submit_chunk("up", key, decl, 0, chunks[0])
        vg.submit_chunk("up", key, decl, 2, chunks[2])
        vg.seal("up", key)
        assert vg.read_all("up", key) == plain


def test_late_retry_after_seal(tmp_path, key):
    plain, chunks = make_file(3)
    decl = decl_of(plain)
    with VaultGuard(tmp_path) as vg:
        submit_all(vg, "up", key, decl, chunks)
        vg.seal("up", key)
        vg.submit_chunk("up", key, decl, 0, chunks[0])  # 相同分块迟到重试：成功
        with pytest.raises(ChunkConflictError):
            vg.submit_chunk("up", key, decl, 0, os.urandom(CHUNK))  # 不同内容：拒绝
        assert vg.read_all("up", key) == plain


def test_repeated_seal_returns_same_file(tmp_path, key):
    plain, chunks = make_file(4)
    decl = decl_of(plain)
    with VaultGuard(tmp_path) as vg:
        submit_all(vg, "up", key, decl, chunks)
        p1 = vg.seal("up", key)
        blob1 = p1.read_bytes()
        p2 = vg.seal("up", key)
        assert p1 == p2
        assert p1.read_bytes() == blob1  # 成品未被重写
        vaults = list((tmp_path / "vaults").glob("*.vault"))
        assert vaults == [p1]  # 只有一份逻辑成品


# ---------------------------------------------------------------- 声明不可变

def test_declaration_immutable(tmp_path, key):
    plain, chunks = make_file(2)
    decl = decl_of(plain)
    with VaultGuard(tmp_path) as vg:
        vg.submit_chunk("up", key, decl, 0, chunks[0])
        with pytest.raises(DeclarationConflictError):
            vg.submit_chunk("up", key, UploadDecl(len(plain) + 1, decl.sha256_hex, decl.policy), 1, chunks[1])
        with pytest.raises(DeclarationConflictError):
            vg.submit_chunk("up", key, UploadDecl(len(plain), "00" * 32, decl.policy), 1, chunks[1])
        with pytest.raises(DeclarationConflictError):
            vg.submit_chunk("up", key, UploadDecl(len(plain), decl.sha256_hex, b"other"), 1, chunks[1])
        # 相同声明可重复提交
        vg.submit_chunk("up", key, decl, 1, chunks[1])
        vg.seal("up", key)
        assert vg.read_all("up", key) == plain


def test_empty_file_rejected(tmp_path, key):
    with VaultGuard(tmp_path) as vg:
        with pytest.raises(ValueError):
            vg.submit_chunk("up", key, UploadDecl(0, "00" * 32, b"p"), 0, b"x")


# ---------------------------------------------------------------- 封存门槛

def test_seal_requires_all_chunks(tmp_path, key):
    plain, chunks = make_file(3)
    decl = decl_of(plain)
    with VaultGuard(tmp_path) as vg:
        vg.submit_chunk("up", key, decl, 0, chunks[0])
        vg.submit_chunk("up", key, decl, 2, chunks[2])
        with pytest.raises(NotSealReadyError):
            vg.seal("up", key)


def test_invalid_chunk_rejected(tmp_path, key):
    plain, chunks = make_file(2)
    decl = decl_of(plain)
    with VaultGuard(tmp_path) as vg:
        with pytest.raises(InvalidChunkError):
            vg.submit_chunk("up", key, decl, 2, chunks[0])  # 序号越界
        with pytest.raises(InvalidChunkError):
            vg.submit_chunk("up", key, decl, 0, b"short")  # 中间块不足 CHUNK
        with pytest.raises(InvalidChunkError):
            vg.submit_chunk("up", key, decl, 1, chunks[0])  # 末块长度不符


# ---------------------------------------------------------------- 容器篡改

def _sealed(tmp_path, key, nchunks=4):
    plain, chunks = make_file(nchunks)
    decl = decl_of(plain)
    vg = VaultGuard(tmp_path)
    submit_all(vg, "up", key, decl, chunks)
    path = vg.seal("up", key)
    return vg, plain, path


def _ct_offset(path) -> int:
    blob = path.read_bytes()
    (hlen,) = struct.unpack(">I", blob[4:8])
    return 8 + hlen + 32


def test_tamper_ciphertext_rejected(tmp_path, key):
    vg, plain, path = _sealed(tmp_path, key)
    blob = bytearray(path.read_bytes())
    blob[-5] ^= 0xFF  # 篡改末块密文
    path.write_bytes(bytes(blob))
    with pytest.raises(IntegrityError):
        vg.read_chunk("up", key, 3)
    with pytest.raises(IntegrityError):
        vg.read_all("up", key)
    vg.close()


def test_tamper_header_metadata_rejected(tmp_path, key):
    vg, plain, path = _sealed(tmp_path, key)
    blob = bytearray(path.read_bytes())
    (hlen,) = struct.unpack(">I", blob[4:8])
    header = bytes(blob[8 : 8 + hlen])
    # 修改头部 JSON 中的 total_length 数字（保持等长）
    i = header.find(b'"total_length":')
    assert i > 0
    j = i + len(b'"total_length":')
    assert blob[8 + j] != ord("9")
    blob[8 + j] = ord("9")
    path.write_bytes(bytes(blob))
    with pytest.raises(IntegrityError):
        vg.read_chunk("up", key, 0)
    vg.close()


def test_truncated_container_rejected(tmp_path, key):
    vg, plain, path = _sealed(tmp_path, key)
    blob = path.read_bytes()
    path.write_bytes(blob[:-13])
    with pytest.raises(IntegrityError):
        vg.read_chunk("up", key, 0)
    path.write_bytes(blob[: len(blob) // 2])
    with pytest.raises(IntegrityError):
        vg.read_all("up", key)
    vg.close()


def test_swapped_chunks_rejected(tmp_path, key):
    vg, plain, path = _sealed(tmp_path, key)
    blob = bytearray(path.read_bytes())
    off = _ct_offset(path)
    csize = CHUNK + 16  # 密文 + GCM 标签
    c0 = bytes(blob[off : off + csize])
    c1 = bytes(blob[off + csize : off + 2 * csize])
    blob[off : off + csize] = c1
    blob[off + csize : off + 2 * csize] = c0
    path.write_bytes(bytes(blob))
    with pytest.raises(IntegrityError):
        vg.read_chunk("up", key, 0)
    with pytest.raises(IntegrityError):
        vg.read_chunk("up", key, 1)
    vg.close()


def test_wrong_key_rejected(tmp_path, key):
    vg, plain, path = _sealed(tmp_path, key)
    with pytest.raises(IntegrityError):
        vg.read_chunk("up", os.urandom(32), 0)
    vg.close()


# ---------------------------------------------------------------- 明文不落盘

def test_no_plaintext_on_disk(tmp_path, key):
    plain, chunks = make_file(3)
    policy = b"TOP-SECRET-POLICY-777"
    decl = decl_of(plain, policy)
    with VaultGuard(tmp_path) as vg:
        submit_all(vg, "up", key, decl, chunks)
        # 封存前扫描暂存与数据库
        for f in tmp_path.rglob("*"):
            if f.is_file():
                data = f.read_bytes()
                for c in chunks:
                    assert c[:32] not in data
                assert policy not in data
        vg.seal("up", key)
        for f in tmp_path.rglob("*"):
            if f.is_file():
                data = f.read_bytes()
                for c in chunks:
                    assert c[:32] not in data
                assert policy not in data


def test_real_4mib_chunks_end_to_end(tmp_path, key, monkeypatch):
    """使用真实 4MiB 分块大小做一次乱序端到端验证。"""
    monkeypatch.setattr(crypto, "CHUNK_SIZE", 4 * 1024 * 1024)
    size = 4 * 1024 * 1024 * 2 + 999
    plain = os.urandom(size)
    decl = decl_of(plain)
    chunks = [plain[i : i + 4 * 1024 * 1024] for i in range(0, size, 4 * 1024 * 1024)]
    with VaultGuard(tmp_path) as vg:
        submit_all(vg, "big", key, decl, chunks, order=[2, 0, 1])
        vg.seal("big", key)
        assert vg.read_all("big", key) == plain
        assert hashlib.sha256(vg.read_all("big", key)).hexdigest() == decl.sha256_hex
