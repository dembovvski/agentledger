"""
core/identity.py — Concrete AgentIdentity backed by Ed25519 (cryptography lib).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from agentledger.interfaces import AgentIdentity as AgentIdentityABC, PrincipalBinding


class AgentIdentityImpl(AgentIdentityABC):
    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        principal_id: str,
        binding_type: str,
        binding_signature: bytes,
        derived_from: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> None:
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()
        self._principal_id = principal_id
        self._binding_type = binding_type
        self._binding_signature = binding_signature
        self._derived_from = derived_from
        self._created_at = created_at or datetime.now(timezone.utc).isoformat()

    # ── ABC properties ────────────────────────────────────────────────────────

    @property
    def agent_id(self) -> str:
        raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw.hex()

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def binding_type(self) -> str:
        return self._binding_type

    # ── Crypto ────────────────────────────────────────────────────────────────

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(payload)

    def verify_signature(self, payload: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, payload)
            return True
        except Exception:
            return False

    # ── Serialisation ─────────────────────────────────────────────────────────

    def serialize(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "binding_signature": self._binding_signature.hex(),
            "binding_type": self._binding_type,
            "created_at": self._created_at,
            "derived_from": self._derived_from,
            "principal_id": self._principal_id,
            "schema_version": "0.1",
        }

    @classmethod
    def deserialize(cls, data: dict[str, Any]) -> AgentIdentityImpl:
        raise NotImplementedError(
            "Cannot reconstruct private key from identity file. "
            "Load the private key separately and call create()."
        )

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        *,
        binding: PrincipalBinding,
        principal_id: Optional[str] = None,
        derived_from: Optional[str] = None,
    ) -> AgentIdentityImpl:
        private_key = Ed25519PrivateKey.generate()
        pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pid = principal_id or pub_bytes.hex()
        sig = binding.bind(pub_bytes, pid)
        return cls(
            private_key=private_key,
            principal_id=pid,
            binding_type=binding.binding_type,
            binding_signature=sig,
            derived_from=derived_from,
        )

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.serialize(), f, indent=2)
