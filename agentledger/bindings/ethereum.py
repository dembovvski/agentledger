"""
EthereumBinding — crypto-native principal binding via web3.py.

principal_id = Ethereum address (0x...)
binding_signature = eth_sign(agent_id_hex) via personal_sign
"""

from __future__ import annotations

import json
from typing import Any

try:
    from web3 import Web3
    from eth_account import Account
except ImportError as e:
    raise ImportError(
        "EthereumBinding requires web3.py and eth-account. "
        "Install: pip install agentledger[ethereum]"
    ) from e

from agentledger.interfaces import PrincipalBinding


class EthereumBinding(PrincipalBinding):
    """
    Ethereum-based principal binding.

    The principal signs the agent's Ed25519 public key using
    eth_sign (personal_sign) with their Ethereum private key.

    Usage:
        binding = EthereumBinding(private_key=os.getenv("ETH_PRIVATE_KEY"))
        sig = binding.bind(agent_public_key=ed25519_pubkey_bytes, principal_id="0x...")
        is_valid = binding.verify(agent_public_key, principal_id, sig)
    """

    binding_type = "ethereum"

    def __init__(self, private_key: str | None = None) -> None:
        """
        Args:
            private_key: Ethereum private key (hex str, 0x...).
                        If None, binding is read-only (verification only).
        """
        self._private_key = private_key
        self._account = Account.from_key(private_key) if private_key else None

    @property
    def address(self) -> str | None:
        """Ethereum address derived from the private key."""
        if self._account is None:
            return None
        return self._account.address

    def bind(
        self,
        agent_public_key: bytes,
        principal_id: str,
    ) -> bytes:
        """
        Sign agent_public_key with Ethereum private key.

        Args:
            agent_public_key: Raw Ed25519 public key bytes (32 bytes).
            principal_id: Ethereum address (0x...). Must match our key.

        Returns:
            65-byte signature (r[32] + s[32] + v[1]).
        """
        if self._account is None:
            raise ValueError(
                "Cannot sign: EthereumBinding was initialised without a private key. "
                "Provide private_key to enable signing."
            )

        # Recover address from principal_id and verify it matches
        addr = principal_id.lower().replace("0x", "")
        expected = self._account.address.lower().replace("0x", "")
        if addr != expected:
            raise ValueError(
                f"principal_id {principal_id} does not match "
                f"the Ethereum address derived from the private key ({self._account.address})."
            )

        # Message: agent_id as hex string (same as spec's agent_id field)
        agent_id_hex = agent_public_key.hex()
        # Ethereum signature: prefix the message per EIP-191
        # "\x19Ethereum Signed Message:\n" + len(message) + message
        prefix = f"\x19Ethereum Signed Message:\n{len(agent_id_hex)}{agent_id_hex}"
        prefix_bytes = prefix.encode("utf-8")

        signed = self._account.sign_message(dict(rawMsg=prefix_bytes))
        return bytes(signed.signature)

    def verify(
        self,
        agent_public_key: bytes,
        principal_id: str,
        signature: bytes,
    ) -> bool:
        """
        Verify an Ethereum signature over agent_public_key.

        Args:
            agent_public_key: Raw Ed25519 public key bytes.
            principal_id: Ethereum address (0x...).
            signature: 65-byte signature (r + s + v).

        Returns:
            True if signature is valid and signer matches principal_id.
        """
        if len(signature) != 65:
            return False

        try:
            recovered = Account.recover_message(
                raw_message=f"\x19Ethereum Signed Message:\n{len(agent_public_key.hex())}{agent_public_key.hex()}".encode("utf-8"),
                signature=signature,
            )
        except Exception:
            return False

        # Normalise both addresses
        recovered_addr = Web3.to_checksum_address(recovered)
        expected_addr = Web3.to_checksum_address(principal_id)
        return recovered_addr == expected_addr

    def serialize_binding_info(self) -> dict[str, Any]:
        """Return serialisable dict for identity file."""
        return {
            "binding_type": self.binding_type,
            "address": self._account.address if self._account else None,
        }
