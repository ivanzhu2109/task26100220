"""VaultGuard 异常类型定义。"""


class VaultGuardError(Exception):
    """库内所有异常的基类。"""


class DeclarationConflictError(VaultGuardError):
    """同一上传标识的声明（总长度/SHA-256/策略元数据）与已登记不一致。"""


class ChunkConflictError(VaultGuardError):
    """同一上传标识同一序号被提交了不同的分块内容。"""


class InvalidChunkError(VaultGuardError):
    """分块序号越界或分块长度不符合 4MiB 分块规则。"""


class UploadNotFoundError(VaultGuardError):
    """上传标识不存在。"""


class NotSealReadyError(VaultGuardError):
    """分块未齐全，或明文长度/SHA-256 与声明不符，不能封存。"""


class IntegrityError(VaultGuardError):
    """容器或分块完整性校验失败（被篡改、截断或调换）。"""
