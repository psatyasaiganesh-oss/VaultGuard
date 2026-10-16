"""Domain exceptions exposed by VaultGuard."""


class VaultGuardError(Exception):
    """Base class for expected, user-facing failures."""


class ValidationError(VaultGuardError):
    """Input or repository metadata failed validation."""


class SecurityError(VaultGuardError):
    """An unsafe path, link, or filesystem object was rejected."""


class RepositoryError(VaultGuardError):
    """The repository is missing, invalid, or already exists."""


class NotFoundError(VaultGuardError):
    """A requested snapshot does not exist."""


class RetentionError(VaultGuardError):
    """A retention policy blocked a destructive operation."""


class CorruptionError(VaultGuardError):
    """Stored content did not pass an integrity check."""
