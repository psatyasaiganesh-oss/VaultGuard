"""VaultGuard: a local, integrity-verifying snapshot repository."""

from .errors import (
    CorruptionError,
    NotFoundError,
    RepositoryError,
    RetentionError,
    SecurityError,
    ValidationError,
)
from .repository import VaultRepository

__all__ = [
    "CorruptionError",
    "NotFoundError",
    "RepositoryError",
    "RetentionError",
    "SecurityError",
    "ValidationError",
    "VaultRepository",
]
__version__ = "1.0.0"
