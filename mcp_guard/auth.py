import os
import json
import hmac
import hashlib
import time
from typing import Optional, Dict, Set
from dataclasses import dataclass, field


@dataclass
class ClientIdentity:
    caller_id: str
    allowed_tools: Optional[Set[str]] = None
    rate_multiplier: float = 1.0
    expires_at: Optional[float] = None
    disabled: bool = False
    metadata: dict = field(default_factory=dict)


class KeyManager:
    """
    Multi-tenant Key Manager for MCP clients.
    - Stores keys as SHA-256 digests (never plaintext in-memory lookups).
    - Constant-time comparison using hmac.compare_digest.
    - File-based dynamic reloading (fail-safe: keeps previous valid snapshot on read errors).
    """

    def __init__(self, key_file_path: Optional[str] = None):
        self.key_file_path = key_file_path
        self._keys: Dict[str, ClientIdentity] = {}  # sha256(key) -> ClientIdentity
        self._last_mtime: float = 0.0
        if key_file_path and os.path.exists(key_file_path):
            self.reload()

    @staticmethod
    def hash_key(raw_key: str) -> str:
        """Compute SHA-256 hex digest for key matching."""
        return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()

    def add_key(
        self,
        raw_key: str,
        caller_id: str,
        allowed_tools: Optional[list[str]] = None,
        rate_multiplier: float = 1.0,
        expires_at: Optional[float] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        """Register a key in-memory."""
        key_hash = self.hash_key(raw_key)
        self._keys[key_hash] = ClientIdentity(
            caller_id=caller_id,
            allowed_tools=set(allowed_tools) if allowed_tools else None,
            rate_multiplier=rate_multiplier,
            expires_at=expires_at,
            disabled=False,
            metadata=metadata or {},
        )

    def authenticate(self, raw_token: str) -> Optional[ClientIdentity]:
        """
        Authenticate bearer token with constant-time comparison.
        Returns ClientIdentity if valid, else None.
        """
        if not raw_token:
            return None

        # Check for reload if backing file exists
        self._check_reload()

        incoming_hash = self.hash_key(raw_token)
        now = time.time()

        for registered_hash, identity in list(self._keys.items()):
            if hmac.compare_digest(registered_hash, incoming_hash):
                if identity.disabled:
                    return None
                if identity.expires_at and now > identity.expires_at:
                    return None
                return identity

        return None

    def _check_reload(self) -> None:
        """Auto reload from file if file mtime changed."""
        if not self.key_file_path or not os.path.exists(self.key_file_path):
            return
        try:
            mtime = os.path.getmtime(self.key_file_path)
            if mtime > self._last_mtime:
                self.reload()
        except OSError:
            pass

    def reload(self) -> bool:
        """
        Reload keys from JSON file.
        Fail-safe: On parse or read error, existing keys snapshot is retained.
        """
        if not self.key_file_path or not os.path.exists(self.key_file_path):
            return False

        try:
            with open(self.key_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            new_keys: Dict[str, ClientIdentity] = {}
            for item in data:
                raw_key = item.get("key")
                caller_id = item.get("caller_id") or item.get("owner", "unknown")
                if not raw_key or not caller_id:
                    continue

                allowed = item.get("allowed_tools")
                khash = self.hash_key(raw_key)
                new_keys[khash] = ClientIdentity(
                    caller_id=caller_id,
                    allowed_tools=set(allowed) if allowed else None,
                    rate_multiplier=float(item.get("rate_multiplier", 1.0)),
                    expires_at=item.get("expires_at"),
                    disabled=bool(item.get("disabled", False)),
                    metadata=item.get("metadata", {}),
                )

            self._keys = new_keys
            self._last_mtime = os.path.getmtime(self.key_file_path)
            return True
        except Exception:
            # Fail-safe: Keep old snapshot
            return False
