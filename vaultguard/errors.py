"""VaultGuard 异常类型定义。"""


class VaultGuardError(Exception):
    """库内所有异常的基类。"""


class DeclarationConflictError(VaultGuardError):
    """同一上传标识的声明（长度/哈希/策略元数据）与已登记的不一致。"""


class ChunkConflictError(VaultGuardError):
    """同一上传标识同一序号被提交了不同的内容。"""


class InvalidChunkError(VaultGuardError):
    """分块序号、长度或内容不合法。"""


class UploadIncompleteError(VaultGuardError):
    """尚有分块缺失，无法封存。"""


class IntegrityError(VaultGuardError):
    """容器或状态完整性校验失败。"""


class UnknownUploadError(VaultGuardError):
    """上传标识不存在。"""
