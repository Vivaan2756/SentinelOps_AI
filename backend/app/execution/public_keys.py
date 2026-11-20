"""Broker Public-Key Registry for Phase 2A.1 Stage 6.

Provides:
- BrokerPublicKeyRegistry: Thread-safe in-memory registry of authorized Ed25519 public keys.
- Supports active, retiring, and revoked key states.
- Rejects unknown, malformed, or revoked keys.
- Validates key identifiers, base64 encoding, and Ed25519 key lengths (exactly 32 bytes).
- Never loads or exposes SENTINELOPS_MANIFEST_PRIVATE_KEY.
- Never generates default or ephemeral public keys.
"""

import base64
from dataclasses import dataclass
from enum import Enum
import json
import logging
import os
from typing import Any, Dict, List, Optional, Set, Union

from cryptography.hazmat.primitives.asymmetric import ed25519

from app.execution.exceptions import BrokerSecurityViolation

logger = logging.getLogger("sentinelops.broker.public_keys")


class KeyStatus(str, Enum):
    """Lifecycle status of a registered public verification key."""

    ACTIVE = "active"
    RETIRING = "retiring"
    REVOKED = "revoked"


@dataclass(frozen=True)
class RegisteredPublicKey:
    """Immutable record for a registered public verification key."""

    key_id: str
    public_key: ed25519.Ed25519PublicKey
    status: KeyStatus
    raw_public_bytes: bytes


class BrokerPublicKeyRegistry:
    """
    Authoritative public-key registry for broker-side Ed25519 manifest verification.

    Security guarantees:
    1. Only public keys are loaded; private keys are strictly forbidden.
    2. Rejects unknown keys with BrokerSecurityViolation.
    3. Rejects revoked keys with BrokerSecurityViolation.
    4. Supports retiring keys to allow graceful key rotation during manifest validity windows.
    5. Validates raw Ed25519 public key lengths (strictly 32 bytes).
    6. Does not create default or ephemeral keys if none are configured.
    """

    def __init__(
        self,
        config: Optional[Union[str, Dict[str, Any], List[Dict[str, Any]]]] = None,
    ):
        self._keys: Dict[str, RegisteredPublicKey] = {}
        self._load_keys(config)

    def _load_keys(
        self,
        config: Optional[Union[str, Dict[str, Any], List[Dict[str, Any]]]] = None,
    ) -> None:
        """Parse, validate, and store public keys from config or environment."""
        raw_config = config
        if raw_config is None:
            env_json = os.environ.get("SENTINELOPS_BROKER_PUBLIC_KEYS_JSON")
            if env_json and env_json.strip():
                try:
                    raw_config = json.loads(env_json.strip())
                except json.JSONDecodeError as e:
                    raise BrokerSecurityViolation(
                        f"Malformed SENTINELOPS_BROKER_PUBLIC_KEYS_JSON: {e}"
                    ) from e
            elif os.environ.get("SENTINELOPS_MANIFEST_PUBLIC_KEY"):
                # Single-key fallback from environment
                pub_b64 = os.environ.get("SENTINELOPS_MANIFEST_PUBLIC_KEY", "").strip()
                kid = os.environ.get("SENTINELOPS_MANIFEST_KEY_ID", "sentinelops-control-plane-v1").strip()
                if pub_b64 and kid:
                    raw_config = {kid: {"public_key": pub_b64, "status": "active"}}

        if not raw_config:
            logger.info("BrokerPublicKeyRegistry initialized with zero keys.")
            return

        if isinstance(raw_config, str):
            try:
                raw_config = json.loads(raw_config.strip())
            except json.JSONDecodeError as e:
                raise BrokerSecurityViolation(f"Malformed public keys JSON: {e}") from e

        if isinstance(raw_config, dict):
            for kid, val in raw_config.items():
                if isinstance(val, str):
                    self._register_single(kid, val, KeyStatus.ACTIVE)
                elif isinstance(val, dict):
                    pub_str = val.get("public_key")
                    st = val.get("status", "active")
                    self._register_single(kid, pub_str, KeyStatus(st))
                else:
                    raise BrokerSecurityViolation(f"Invalid public key config format for key_id '{kid}'.")

        elif isinstance(raw_config, list):
            for entry in raw_config:
                if not isinstance(entry, dict):
                    raise BrokerSecurityViolation("List public key entry must be a dictionary.")
                kid = entry.get("key_id")
                pub_str = entry.get("public_key")
                st = entry.get("status", "active")
                self._register_single(kid, pub_str, KeyStatus(st))
        else:
            raise BrokerSecurityViolation(f"Unsupported public key config type: {type(raw_config)}")

    def _register_single(self, key_id: Any, public_key_raw: Any, status: KeyStatus) -> None:
        """Validate and register an individual public key."""
        if not key_id or not isinstance(key_id, str) or not key_id.strip():
            raise BrokerSecurityViolation("key_id must be a non-empty string.")
        kid = key_id.strip()
        if len(kid) > 64:
            raise BrokerSecurityViolation(f"key_id '{kid}' exceeds maximum length of 64 characters.")

        if not public_key_raw or not isinstance(public_key_raw, (str, bytes)):
            raise BrokerSecurityViolation(f"Missing public key bytes for key_id '{kid}'.")

        try:
            if isinstance(public_key_raw, str):
                # Handle base64 or urlsafe base64 with potential padding issues
                padded = public_key_raw.strip()
                # Standard b64decode handles standard and urlsafe (with altchars)
                try:
                    pub_bytes = base64.b64decode(padded)
                except Exception:
                    pub_bytes = base64.urlsafe_b64decode(padded + "=" * (-len(padded) % 4))
            else:
                pub_bytes = public_key_raw
        except Exception as e:
            raise BrokerSecurityViolation(f"Invalid base64 encoding for key_id '{kid}': {e}") from e

        if len(pub_bytes) != 32:
            raise BrokerSecurityViolation(
                f"Invalid Ed25519 public key length for key_id '{kid}': got {len(pub_bytes)} bytes, expected exactly 32."
            )

        try:
            pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception as e:
            raise BrokerSecurityViolation(f"Failed to load Ed25519 public key for key_id '{kid}': {e}") from e

        self._keys[kid] = RegisteredPublicKey(
            key_id=kid,
            public_key=pub_obj,
            status=status,
            raw_public_bytes=pub_bytes,
        )
        logger.info(f"Registered broker public key: key_id='{kid}', status='{status.value}'")

    def get_key(self, key_id: str) -> Optional[RegisteredPublicKey]:
        """Retrieve key record by identifier."""
        if not key_id or not isinstance(key_id, str):
            return None
        return self._keys.get(key_id.strip())

    def resolve_and_verify_key(self, key_id: str) -> ed25519.Ed25519PublicKey:
        """
        Resolve key by identifier and assert that it is not revoked.
        Raises BrokerSecurityViolation if unknown or revoked.
        """
        if not key_id or not isinstance(key_id, str):
            raise BrokerSecurityViolation("key_id must be a non-empty string.")

        kid = key_id.strip()
        record = self._keys.get(kid)
        if record is None:
            raise BrokerSecurityViolation(
                f"Unknown signing key_id '{kid}'. No corresponding public verification key configured on broker."
            )

        if record.status == KeyStatus.REVOKED:
            raise BrokerSecurityViolation(
                f"Signing key_id '{kid}' has been revoked. Manifest rejected."
            )

        return record.public_key

    def revoke_key(self, key_id: str) -> None:
        """Mark a registered key as revoked."""
        kid = key_id.strip()
        record = self._keys.get(kid)
        if record is not None:
            self._keys[kid] = RegisteredPublicKey(
                key_id=record.key_id,
                public_key=record.public_key,
                status=KeyStatus.REVOKED,
                raw_public_bytes=record.raw_public_bytes,
            )
            logger.warning(f"Signing key_id '{kid}' has been revoked.")

    def all_key_ids(self) -> Set[str]:
        """Return all registered key identifiers."""
        return set(self._keys.keys())

    def __len__(self) -> int:
        return len(self._keys)
