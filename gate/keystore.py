"""Local key generation, rotation and revocation.

Keys are symmetric HMAC secrets kept purely in local storage. Rotation does
not delete the old key -- it stays around so historical signatures stay
explainable -- but only the *active* key may validate signatures for a new
admission. That is what makes "signed before the latest rotation" fail
verification while remaining auditable.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable

from gate.models import StoredKey
from gate.storage import LocalStore

DEFAULT_KEY_TTL: float | None = None  # keys do not auto-expire by default


class KeyStore:
    def __init__(
        self,
        store: LocalStore,
        clock: Callable[[], float] | None = None,
        key_ttl: float | None = DEFAULT_KEY_TTL,
    ) -> None:
        self._store = store
        self._clock = clock or _system_clock
        self._key_ttl = key_ttl

    @property
    def clock(self) -> Callable[[], float]:
        return self._clock

    # -- lifecycle -------------------------------------------------------

    def generate_key(self) -> str:
        """Generate the initial active key. Fails if one already exists."""
        with self._store.lock:
            if self._store.active_key_id is not None:
                raise RuntimeError("active key already exists; rotate instead")
            return self._mint_key()

    def rotate_key(self) -> str:
        """Mint a new active key; the previous one is retained as history."""
        with self._store.lock:
            return self._mint_key()

    def revoke_key(self, key_id: str) -> None:
        with self._store.lock:
            key = self._store.keys.get(key_id)
            if key is None:
                raise KeyError(key_id)
            key.revoked = True

    # -- reads -----------------------------------------------------------

    def active_key_id(self) -> str | None:
        with self._store.lock:
            return self._store.active_key_id

    def get_active_key(self) -> StoredKey:
        with self._store.lock:
            key_id = self._store.active_key_id
            if key_id is None:
                raise RuntimeError("no active key")
            key = self._store.keys[key_id]
            return key

    def get_key(self, key_id: str) -> StoredKey | None:
        with self._store.lock:
            return self._store.keys.get(key_id)

    def list_keys(self) -> list[StoredKey]:
        with self._store.lock:
            return [self._store.keys[k] for k in self._store.key_order]

    # -- internals -------------------------------------------------------

    def _mint_key(self) -> str:
        now = self._clock()
        key_id = "key-" + secrets.token_hex(6)
        expires_at = now + self._key_ttl if self._key_ttl is not None else None
        key = StoredKey(
            key_id=key_id,
            secret=secrets.token_bytes(32),
            created_at=now,
            expires_at=expires_at,
        )
        self._store.keys[key_id] = key
        self._store.key_order.append(key_id)
        self._store.active_key_id = key_id
        return key_id


def _system_clock() -> float:
    import time

    return time.time()
