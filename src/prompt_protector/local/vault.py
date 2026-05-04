"""Reversible-redaction storage.

The vault holds per-request placeholder→original mappings. After the LLM
responds with text containing the placeholders, ``protector.unredact``
restores the originals by looking up the vault entry.

Two implementations:

* ``InMemoryVault`` — process-local dict with TTL. Default for most uses.
* ``EncryptedFileVault`` — Fernet-encrypted on-disk store. For multi-
  process or after-the-fact lookup. Requires ``cryptography``.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Optional


class InMemoryVault:
    """Process-local vault. Entries auto-expire after ``ttl_seconds``."""

    def __init__(self, *, ttl_seconds: float = 3600.0) -> None:
        self._ttl = ttl_seconds
        self._items: dict[str, tuple[float, list[tuple[str, str]]]] = {}
        self._lock = threading.Lock()

    def put(self, vault_id: str, mapping: list[tuple[str, str]]) -> None:
        self._gc()
        with self._lock:
            self._items[vault_id] = (time.time() + self._ttl, list(mapping))

    def get(self, vault_id: str) -> list[tuple[str, str]]:
        with self._lock:
            entry = self._items.get(vault_id)
            if entry is None:
                return []
            expires_at, mapping = entry
            if expires_at < time.time():
                self._items.pop(vault_id, None)
                return []
            return list(mapping)

    def delete(self, vault_id: str) -> None:
        with self._lock:
            self._items.pop(vault_id, None)

    def _gc(self) -> None:
        now = time.time()
        with self._lock:
            stale = [k for k, (exp, _) in self._items.items() if exp < now]
            for k in stale:
                self._items.pop(k, None)

    def __len__(self) -> int:
        return len(self._items)


class EncryptedFileVault:
    """Fernet-encrypted on-disk vault.

    Each entry is one file under ``directory`` named by ``vault_id``. The
    Fernet key is supplied by the caller (typically from a KMS or env var).
    """

    def __init__(
        self,
        directory: str,
        key: bytes,
        *,
        ttl_seconds: float = 3600.0,
    ) -> None:
        try:
            from cryptography.fernet import Fernet  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "EncryptedFileVault requires the 'cryptography' package. "
                "Install with: pip install prompt-protector[vault]"
            ) from exc
        self._fernet = Fernet(key)
        os.makedirs(directory, exist_ok=True)
        self._dir = directory
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def put(self, vault_id: str, mapping: list[tuple[str, str]]) -> None:
        payload = json.dumps({"expires_at": time.time() + self._ttl, "mapping": mapping}).encode()
        token = self._fernet.encrypt(payload)
        with self._lock:
            with open(os.path.join(self._dir, _safe(vault_id)), "wb") as fh:
                fh.write(token)

    def get(self, vault_id: str) -> list[tuple[str, str]]:
        path = os.path.join(self._dir, _safe(vault_id))
        with self._lock:
            if not os.path.exists(path):
                return []
            with open(path, "rb") as fh:
                token = fh.read()
            try:
                payload = json.loads(self._fernet.decrypt(token).decode())
            except Exception:  # noqa: BLE001
                return []
            if payload.get("expires_at", 0) < time.time():
                self._delete_locked(path)
                return []
        return [tuple(item) for item in payload.get("mapping", [])]

    def delete(self, vault_id: str) -> None:
        path = os.path.join(self._dir, _safe(vault_id))
        with self._lock:
            self._delete_locked(path)

    def _delete_locked(self, path: str) -> None:
        try:
            os.remove(path)
        except FileNotFoundError:
            return


def _safe(name: str) -> str:
    """Strip path separators so callers can't escape the vault dir."""
    return "".join(c for c in name if c.isalnum() or c in "-_")[:128] or "_"


__all__ = ["EncryptedFileVault", "InMemoryVault"]
