# VaultGuard 加密续传库

面向机构用户敏感文件上传的加密续传模块，以库的形式供上层调用。
上传进度存于 SQLite，加密分块暂存与最终 `.vault` 容器存于本地目录；
仅依赖 Python 3.10+ 与 `cryptography`，无需任何外部服务。

## 能力

- **提交分块** `submit_chunk`：明文按 4 MiB 分块（末块可不足），可乱序、可重试。
- **封存文件** `seal`：分块齐全且拼接后的明文长度、SHA-256 均符合声明才封存，
  产出唯一不可变的 `.vault` 容器；重复封存返回同一文件。
- **逐段读回** `read_chunk` / `read_all`：每段经 AEAD 认证后才交给调用方。

## 快速开始

```python
import hashlib, os
from vaultguard import VaultGuard, UploadDecl

key = os.urandom(32)                      # 调用方持有的文件密钥，库绝不落盘
plain = open("secret.bin", "rb").read()
decl = UploadDecl(
    total_length=len(plain),              # 非空文件总长度
    sha256_hex=hashlib.sha256(plain).hexdigest(),
    policy=b'{"level":"secret"}',         # 策略元数据（加密保护）
)

with VaultGuard("/var/lib/vaultguard") as vg:
    # 乱序提交；相同内容重试幂等，不同内容抛 ChunkConflictError
    for seq in (1, 0, 2):
        part = plain[seq * 4*1024*1024 : (seq + 1) * 4*1024*1024]
        vg.submit_chunk("upload-001", key, decl, seq, part)

    vault_path = vg.seal("upload-001", key)   # 重复调用返回同一路径
    chunk1 = vg.read_chunk("upload-001", key, 1)  # 逐段读回
    whole = vg.read_all("upload-001", key)        # 或整体读回
```

## 安全设计

- **密钥**：32 字节文件密钥由调用方每次调用传入；HKDF 派生分块、策略、
  头部、指纹四把子密钥；密钥本身永不写入磁盘或数据库。
- **加密**：文件内容与策略元数据均用 AES-256-GCM 加密。分块 AAD 绑定
  上传标识、序号、总长度、明文 SHA-256 与策略密文哈希——调换分块、
  篡改密文或元数据、截断容器都会使校验失败，未认证数据绝不返回。
- **容器**：`MAGIC | 头部长度 | 头部JSON | 头部HMAC | 逐块密文`。
  头部携带文件身份、策略密文、分块 nonce 与长度信息，整体受 HMAC 保护。
- **重试语义**：每块内容以 HMAC 指纹登记在 SQLite；同内容重试幂等成功
  （含封存后的迟到重试），不同内容拒绝且不破坏已确认数据。
- **声明不可变**：同一上传标识的总长度、SHA-256、策略元数据不可改变，
  冲突抛 `DeclarationConflictError`。
- **落盘安全**：暂存分块、SQLite、`.vault` 中只存在密文、哈希与指纹，
  无任何明文；写入均为 临时文件 + fsync + os.replace 原子提交。

## 目录布局

```
data_dir/
├── progress.db      # SQLite：上传声明（含策略密文）、分块指纹、封存状态
├── staging/<id>/    # 暂存加密分块（封存后删除，指纹保留用于迟到重试比对）
└── vaults/<id>.vault# 封存后的不可变容器
```

## 异常

`DeclarationConflictError`、`ChunkConflictError`、`InvalidChunkError`、
`UploadNotFoundError`、`NotSealReadyError`、`IntegrityError`，
均继承自 `VaultGuardError`。

## 运行测试

```bash
python3 -m pytest tests/ -q
```

覆盖：乱序上传、相同/冲突重试、重复封存（成品不重复）、SHA-256 独立校验、
篡改密文/头部元数据/截断/调块/错误密钥拒绝、明文不落盘扫描、
真实 4 MiB 分块端到端。
