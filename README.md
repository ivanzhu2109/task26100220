# VaultGuard 加密续传库

机构用户敏感文件的加密断点续传模块，以库的形式供上层调用。
上传进度存于 SQLite，加密分块与最终 `.vault` 容器存于本地目录；
不依赖任何数据库/缓存/消息队列服务，不监听端口。

## 安全模型

- 调用方负责鉴权，并为每次上传提供独立的 32 字节文件密钥；
  密钥只存在于内存，绝不落盘。
- 文件内容与策略元数据均以 AES-256-GCM 加密保护；
  SQLite 与暂存目录中只保存密文与带密钥的 HMAC，不出现明文。
- 分块 nonce 由 (上传标识, 序号) 确定性派生，AAD 绑定
  (总长度, 分块数, 序号)，防止调序与跨声明移植。
- 容器头以 HMAC 保护文件身份、长度、SHA-256 与元数据密文；
  截断、追加、调块、篡改密文/元数据都会在读回时被拒绝。
- 未经 GCM 认证成功的分块明文不会返回给调用方。

## 目录结构

```
work_dir/
  state.sqlite    # 上传进度：声明、各分块 HMAC、封存状态（无明文、无密钥）
  staging/<hash>/ # 暂存的加密分块，封存后自动清理
  vaults/<hash>.vault  # 最终不可变容器
```

## API 用法

```python
import hashlib, os
from vaultguard import VaultGuard

vg = VaultGuard("/var/lib/vaultguard")     # 工作目录

key  = os.urandom(32)                       # 每次上传独立的文件密钥（调用方保管）
data = open("report.pdf", "rb").read()
sha  = hashlib.sha256(data).hexdigest()
meta = b'{"retention":"7y","level":"secret"}'

CHUNK = 4 * 1024 * 1024                     # 4 MiB，最后一块可不足
parts = [data[i:i+CHUNK] for i in range(0, len(data), CHUNK)]

# 1) 提交分块：可乱序、可重试；重复提交相同内容幂等返回 False，
#    同一序号提交不同内容抛 ChunkConflictError 且原内容不受影响。
for seq in reversed(range(len(parts))):
    vg.submit_chunk(key, "upload-001", len(data), sha, meta, seq, parts[seq])

# 2) 封存：全部分块齐全且拼接后的长度与 SHA-256 符合声明才成功；
#    重复封存返回同一个 .vault 路径，不会生成第二份。
vault_path = vg.seal(key, "upload-001", len(data), sha, meta)

# 3) 逐段读回 / 整体读回 / 读回策略元数据
chunk0 = vg.read_chunk(key, vault_path, 0)
whole  = vg.read_all(key, vault_path)       # 校验整体 SHA-256
policy = vg.read_metadata(key, vault_path)

vg.close()
```

同一上传标识的 `total_length`、`sha256_hex`、`metadata` 一经登记不可改变，
不一致的声明会抛 `DeclarationConflictError`。

## 异常

| 异常 | 含义 |
| --- | --- |
| `DeclarationConflictError` | 同一上传标识的声明被试图改变 |
| `ChunkConflictError` | 同一序号提交了不同内容（原内容保留） |
| `InvalidChunkError` | 序号越界、长度不符、声明格式非法 |
| `UploadIncompleteError` | 分块未齐就请求封存 |
| `IntegrityError` | 容器/状态认证失败（篡改、截断、调块、错密钥） |
| `UnknownUploadError` | 上传标识不存在 |

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖：乱序上传、相同/冲突重试、重复封存（成品不重复）、
读回逐字节一致且 SHA-256 独立校验、明文与密钥不落盘、
篡改密文/头部/元数据、截断、追加、调块、伪造分块、错误密钥、
重启后已确认分块保留。
