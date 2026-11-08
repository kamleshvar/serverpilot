"""Field-level encryption for OAuth tokens, secrets and agent credentials."""

from __future__ import annotations

import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from flask import Flask, current_app

_PREFIX = "enc:v1:"


class EncryptionError(RuntimeError):
    """Raised when encrypted data cannot be decrypted."""


class EncryptionService:
    def __init__(self, keys: list[str] | list[bytes]) -> None:
        if not keys:
            raise EncryptionError("At least one encryption key is required")
        self._fernet = MultiFernet(
            [Fernet(key.encode() if isinstance(key, str) else key) for key in keys]
        )

    def encrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        token = self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return f"{_PREFIX}{token}"

    def decrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith(_PREFIX):
            raise EncryptionError("Unsupported ciphertext format")
        token = value[len(_PREFIX) :]
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            raise EncryptionError("Ciphertext could not be decrypted") from exc

    def encrypt_json(self, value: Any) -> str:
        return (
            self.encrypt(json.dumps(value, separators=(",", ":"), sort_keys=True)) or ""
        )

    def decrypt_json(self, value: str | None) -> Any:
        plaintext = self.decrypt(value)
        return json.loads(plaintext) if plaintext else None

    def rotate(self, value: str | None) -> str | None:
        if value is None:
            return None
        token = value.removeprefix(_PREFIX)
        try:
            rotated = self._fernet.rotate(token.encode("ascii"))
        except (InvalidToken, ValueError) as exc:
            raise EncryptionError("Ciphertext could not be rotated") from exc
        return f"{_PREFIX}{rotated.decode('ascii')}"


def init_encryption(app: Flask) -> EncryptionService:
    keys = app.config.get("ENCRYPTION_KEYS") or []
    if not keys:
        raise EncryptionError("ENCRYPTION_KEYS was not initialized")
    service = EncryptionService(keys)
    app.extensions["serverpilot_encryption"] = service
    return service


def get_encryption() -> EncryptionService:
    try:
        return current_app.extensions["serverpilot_encryption"]
    except KeyError as exc:  # pragma: no cover - app setup bug
        raise EncryptionError("Encryption service is not initialized") from exc
