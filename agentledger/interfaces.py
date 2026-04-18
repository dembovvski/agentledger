"""
AgentLedger Protocol v0.1 — interfaces.py
==========================================
Czyste ABCs + type stubs. ZERO implementacji.
Wszystkie kontrakty muszą być stabilne przed rozpoczęciem kodowania.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Literal, Optional
import threading


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class ActionStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class ActionType(str, Enum):
    TOOL_CALL = "tool_call"
    LLM_INVOKE = "llm_invoke"
    DECISION = "decision"
    CROSS_AGENT = "cross_agent"


class Framework(str, Enum):
    LANGCHAIN = "langchain"
    AUTOGEN = "autogen"
    CREWAI = "crewai"
    CUSTOM = "custom"


# ─────────────────────────────────────────────────────────────────────────────
# Cross-agent reference
# ─────────────────────────────────────────────────────────────────────────────

class CrossAgentRefStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"


@dataclass(frozen=True)
class CrossAgentRef:
    target_agent_id: Optional[str] = None
    ref_receipt_id: Optional[str] = None
    status: CrossAgentRefStatus = CrossAgentRefStatus.PENDING

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_agent_id": self.target_agent_id,
            "ref_receipt_id": self.ref_receipt_id,
            "status": self.status.value,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Receipt — immutable once created
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Receipt:
    receipt_id: str                    # UUIDv4
    chain_id: str                      # = agent_id (Ed25519 public key hex)
    timestamp: str                     # ISO8601 UTC
    agent_id: str
    principal_id: str
    action: ActionData
    prev_hash: Optional[str] = None    # SHA256 hex; null iff first in chain
    cross_agent_ref: Optional[CrossAgentRef] = None
    signature: Optional[str] = None    # Ed25519 hex; None = not yet signed
    schema_version: str = "0.1"

    def to_dict(self) -> dict[str, Any]:
        """Serialise to canonical dict (keys sorted lexicographically).

        NOTE: signature excluded when computing signing payload — use
        canonicalise_for_signing() for hash computation.
        """
        raise NotImplementedError


@dataclass
class ActionData:
    type: ActionType
    framework: Framework
    tool_name: Optional[str] = None
    status: ActionStatus = ActionStatus.PENDING
    payload_hash: Optional[str] = None   # SHA256 hex of canonical JSON input
    result_hash: Optional[str] = None     # SHA256 hex of canonical JSON output
    error: Optional[str] = None           # non-null only when status == FAILED


# ─────────────────────────────────────────────────────────────────────────────
# AgentIdentity
# ─────────────────────────────────────────────────────────────────────────────

class AgentIdentity(abc.ABC):
    """
    Manages a single agent's Ed25519 keypair and principal binding.

    The private key NEVER leaves this instance.
    """

    @property
    @abc.abstractmethod
    def agent_id(self) -> str:
        """Ed25519 public key as lowercase hex."""
        ...

    @property
    @abc.abstractmethod
    def principal_id(self) -> str:
        """Principal identifier (format depends on binding type)."""
        ...

    @property
    @abc.abstractmethod
    def binding_type(self) -> str:
        """e.g. 'ethereum', 'x509', 'custom'."""
        ...

    @abc.abstractmethod
    def sign(self, payload: bytes) -> bytes:
        """
        Sign arbitrary payload with agent's Ed25519 private key.
        Returns raw 64-byte Ed25519 signature.
        """
        ...

    @abc.abstractmethod
    def verify_signature(self, payload: bytes, signature: bytes) -> bool:
        """Verify Ed25519 signature against agent_id."""
        ...

    @abc.abstractmethod
    def serialize(self) -> dict[str, Any]:
        """
        Return identity file dict (Section 3.1 of spec).
        Includes binding_signature.
        """
        ...

    @classmethod
    @abc.abstractmethod
    def deserialize(cls, data: dict[str, Any]) -> AgentIdentity:
        """Reconstruct from identity file dict."""
        ...

    # ─── Factory (still ABC — let core provide concrete implementation) ─────

    @classmethod
    @abc.abstractmethod
    def create(
        cls,
        *,
        binding: PrincipalBinding,
        principal_id: Optional[str] = None,
        derived_from: Optional[str] = None,
    ) -> AgentIdentity:
        """
        Generate fresh Ed25519 keypair, bind to principal, write identity file.
        """
        ...


# ─────────────────────────────────────────────────────────────────────────────
# PrincipalBinding — pluggable interface
# ─────────────────────────────────────────────────────────────────────────────

class PrincipalBinding(abc.ABC):
    """
    Pluggable principal-binding interface.
    Every binding implementation must satisfy this contract.
    """

    binding_type: str  # "ethereum" | "x509" | "custom" — class attribute

    @abc.abstractmethod
    def bind(
        self,
        agent_public_key: bytes,    # Ed25519 public key raw bytes
        principal_id: str,         # identifier in this binding's scheme
    ) -> bytes:
        """
        Return bytes signature proving ``principal_id`` authorised ``agent_public_key``.
        """
        ...

    @abc.abstractmethod
    def verify(
        self,
        agent_public_key: bytes,
        principal_id: str,
        signature: bytes,
    ) -> bool:
        """Return True if signature is valid and matches principal."""
        ...

    @abc.abstractmethod
    def serialize_binding_info(self) -> dict[str, Any]:
        """Return serialisable dict for identity file."""
        ...


# ─────────────────────────────────────────────────────────────────────────────
# ReceiptChain — append-only log with checkpoints
# ─────────────────────────────────────────────────────────────────────────────

class ReceiptChain(abc.ABC):
    """
    Per-agent append-only receipt chain.

    Thread-safety: concurrent append() calls MUST be serialised.
    Subclass MUST expose a ``.lock`` attribute (threading.RLock or similar).
    """

    def __init__(
        self,
        identity: AgentIdentity,
        *,
        storage_path: str,
        checkpoint_interval: int = 100,
    ) -> None:
        self.identity = identity
        self.storage_path = storage_path
        self.checkpoint_interval = checkpoint_interval

    @property
    @abc.abstractmethod
    def lock(self) -> threading.RLock:
        """Lock used to serialise append/finalize_last. Exposed for integrations."""
        ...

    @abc.abstractmethod
    def append(
        self,
        action_type: ActionType,
        framework: Framework,
        *,
        tool_name: Optional[str] = None,
        payload: Any = None,         # actual content — stored separately, hash stored in receipt
        cross_agent_ref: Optional[CrossAgentRef] = None,
    ) -> str:
        """
        Append a PENDING receipt to the chain.

        Returns ``receipt_id`` (UUIDv4) of the new receipt.
        Thread-safe: callers do NOT need to hold .lock.
        """
        ...

    @abc.abstractmethod
    def finalize_last(
        self,
        *,
        status: ActionStatus,
        result: Any = None,
        error: Optional[str] = None,
    ) -> None:
        """
        Finalise the most recently appended PENDING receipt.

        Transitions status: pending → completed | failed.
        Sets result_hash or error accordingly.
        Thread-safe: callers do NOT need to hold .lock.
        """
        ...

    @abc.abstractmethod
    def verify(self, *, checkpoint_only: bool = False) -> bool:
        """
        Verify the entire chain.

        If checkpoint_only=True: jump to nearest checkpoint, verify
        cumulative hash, walk only the tail.
        Returns True if chain is valid and tamper-free.
        Raises ChainVerificationError on corruption.
        """
        ...

    @abc.abstractmethod
    def get_receipt(self, receipt_id: str) -> Receipt:
        """Retrieve a receipt by ID. Raises KeyError if not found."""
        ...

    @abc.abstractmethod
    def iter_receipts(self) -> list[Receipt]:
        """Return all receipts in order (including checkpoints stripped)."""
        ...


class ChainVerificationError(Exception):
    """Raised when chain verification fails."""
    ...


# ─────────────────────────────────────────────────────────────────────────────
# Canonical serialisation helpers (implemented in core/receipt.py)
# ─────────────────────────────────────────────────────────────────────────────

def canonicalise_for_signing(receipt: Receipt) -> bytes:
    """
    Return deterministic UTF-8 bytes of receipt dict with:
      - 'signature' field excluded
      - all keys sorted lexicographically at every nesting level
    Used by AgentIdentity.sign() and chain verification.
    Delegates to core/receipt.py — imported here as single entry point.
    """
    from agentledger.core.receipt import canonicalise_for_signing as _impl
    return _impl(receipt)


def sha256_hex(data: bytes) -> str:
    """SHA-256 of bytes, returns lowercase hex string."""
    from agentledger.core.receipt import sha256_hex as _impl
    return _impl(data)
