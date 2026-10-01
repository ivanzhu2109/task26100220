"""VaultGuard：加密续传库（提交分块 / 封存文件 / 逐段读回）。"""

from .core import UploadDecl, VaultGuard
from .errors import (
    ChunkConflictError,
    DeclarationConflictError,
    IntegrityError,
    InvalidChunkError,
    NotSealReadyError,
    UploadNotFoundError,
    VaultGuardError,
)

__all__ = [
    "VaultGuard",
    "UploadDecl",
    "VaultGuardError",
    "DeclarationConflictError",
    "ChunkConflictError",
    "InvalidChunkError",
    "UploadNotFoundError",
    "NotSealReadyError",
    "IntegrityError",
]
