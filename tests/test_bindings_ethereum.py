"""
Tests for EthereumBinding — web3.py-based principal binding.

RED: These tests define the expected contract.
GREEN: The implementation in agentledger/bindings/ethereum.py satisfies them.
"""

import pytest


class TestEthereumBindingBind:
    """bind() creates an Ethereum personal_sign signature over the agent pubkey."""

    def test_bind_returns_65_bytes(self, eth_binding_with_key):
        """Signature must be 65 bytes (r=32 + s=32 + v=1)."""
        sig = eth_binding_with_key.bind(AGENT_PUBKEY, eth_binding_with_key.address)
        assert isinstance(sig, bytes)
        assert len(sig) == 65

    def test_bind_message_is_agent_pubkey_hex(self, eth_binding_with_key):
        """
        The signed message is the agent's Ed25519 public key as a hex string,
        EIP-191 prefixed. This is the canonical message used by both bind and verify.
        """
        # bind() should not raise — happy path
        sig = eth_binding_with_key.bind(AGENT_PUBKEY, eth_binding_with_key.address)
        assert len(sig) == 65

    def test_bind_principal_id_must_match_key(self, eth_binding_with_key):
        """Providing a mismatched principal_id raises ValueError."""
        bad_address = "0x0000000000000000000000000000000000000001"
        with pytest.raises(ValueError, match="does not match"):
            eth_binding_with_key.bind(AGENT_PUBKEY, bad_address)

    def test_bind_no_private_key_raises(self, eth_binding_readonly):
        """Read-only binding (no private key) raises ValueError on bind()."""
        with pytest.raises(ValueError, match="without a private key"):
            eth_binding_readonly.bind(AGENT_PUBKEY, eth_binding_readonly.address)


class TestEthereumBindingVerify:
    """verify() checks the signature against the Ethereum address."""

    def test_verify_valid_signature(self, eth_binding_with_key):
        """A valid personal_sign signature returns True."""
        sig = eth_binding_with_key.bind(AGENT_PUBKEY, eth_binding_with_key.address)
        result = eth_binding_with_key.verify(AGENT_PUBKEY, eth_binding_with_key.address, sig)
        assert result is True

    def test_verify_wrong_address_returns_false(self, eth_binding_with_key):
        """Signature for a different address returns False."""
        sig = eth_binding_with_key.bind(AGENT_PUBKEY, eth_binding_with_key.address)
        wrong = "0x0000000000000000000000000000000000000001"
        result = eth_binding_with_key.verify(AGENT_PUBKEY, wrong, sig)
        assert result is False

    def test_verify_wrong_pubkey_returns_false(self, eth_binding_with_key):
        """Signature over a different pubkey returns False."""
        sig = eth_binding_with_key.bind(AGENT_PUBKEY, eth_binding_with_key.address)
        other_pubkey = b"\x00" * 32
        result = eth_binding_with_key.verify(other_pubkey, eth_binding_with_key.address, sig)
        assert result is False

    def test_verify_tampered_signature_returns_false(self, eth_binding_with_key):
        """Modified signature bytes return False, not an exception."""
        sig = bytearray(eth_binding_with_key.bind(AGENT_PUBKEY, eth_binding_with_key.address))
        sig[0] ^= 0xFF
        result = eth_binding_with_key.verify(AGENT_PUBKEY, eth_binding_with_key.address, bytes(sig))
        assert result is False

    def test_verify_wrong_length_signature_returns_false(self, eth_binding_with_key):
        """Signature of wrong length is rejected without exception."""
        result = eth_binding_with_key.verify(AGENT_PUBKEY, eth_binding_with_key.address, b"too-short")
        assert result is False

    def test_verify_readonly_binding_works(self, eth_binding_readonly):
        """Read-only binding can verify (no private key needed for verify)."""
        # Create a valid sig using the signing binding, then verify with read-only
        from agentledger.bindings.ethereum import EthereumBinding
        signer = EthereumBinding(private_key=ETH_PRIVKEY)
        sig = signer.bind(AGENT_PUBKEY, signer.address)
        result = eth_binding_readonly.verify(AGENT_PUBKEY, signer.address, sig)
        assert result is True


class TestEthereumBindingSerialization:
    """serialize_binding_info() returns a dict with binding metadata."""

    def test_serialize_contains_type_and_address(self, eth_binding_with_key):
        info = eth_binding_with_key.serialize_binding_info()
        assert info["binding_type"] == "ethereum"
        assert info["address"] == eth_binding_with_key.address

    def test_serialize_readonly_is_none_address(self, eth_binding_readonly):
        info = eth_binding_readonly.serialize_binding_info()
        assert info["address"] is None


# ─── Fixtures ────────────────────────────────────────────────────────────────

# Pre-generated keypair used by all tests (not sensitive — only for testing)
ETH_PRIVKEY = "0x" + "ab" * 32
AGENT_PUBKEY = bytes.fromhex("a1b2c3d4e5f6" + "00" * 26)


@pytest.fixture
def eth_binding_with_key():
    from agentledger.bindings.ethereum import EthereumBinding
    return EthereumBinding(private_key=ETH_PRIVKEY)


@pytest.fixture
def eth_binding_readonly():
    from agentledger.bindings.ethereum import EthereumBinding
    return EthereumBinding(private_key=None)
