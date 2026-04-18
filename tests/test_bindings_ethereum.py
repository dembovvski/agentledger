"""
Tests for EthereumBinding — web3.py-based principal binding.

When web3 is not installed, all tests are skipped (importorskip).
This matches the optional-extra pattern: pip install agentledger[ethereum]
"""

import pytest

# Eager import — if web3 is missing, ALL tests in this file are skipped.
web3 = pytest.importorskip("web3", reason="web3 not installed — pip install agentledger[ethereum]")

from agentledger.bindings.ethereum import EthereumBinding

# Fixed test key — not sensitive, only for unit tests
ETH_PRIVKEY = "0x" + "ab" * 32
AGENT_PUBKEY = bytes.fromhex("a1b2c3d4e5f6" + "00" * 26)


class TestEthereumBindingBind:
    """bind() creates an Ethereum personal_sign signature over the agent pubkey."""

    def test_bind_returns_65_bytes(self):
        """Signature must be 65 bytes (r=32 + s=32 + v=1)."""
        binding = EthereumBinding(private_key=ETH_PRIVKEY)
        sig = binding.bind(AGENT_PUBKEY, binding.address)
        assert isinstance(sig, bytes)
        assert len(sig) == 65

    def test_bind_message_is_agent_pubkey_hex(self):
        """bind() signs the Ed25519 pubkey as a hex string (EIP-191 prefixed)."""
        binding = EthereumBinding(private_key=ETH_PRIVKEY)
        sig = binding.bind(AGENT_PUBKEY, binding.address)
        assert len(sig) == 65

    def test_bind_principal_id_must_match_key(self):
        """Mismatched principal_id raises ValueError."""
        binding = EthereumBinding(private_key=ETH_PRIVKEY)
        bad_address = "0x0000000000000000000000000000000000000001"
        with pytest.raises(ValueError, match="does not match"):
            binding.bind(AGENT_PUBKEY, bad_address)

    def test_bind_no_private_key_raises(self):
        """Read-only binding raises ValueError on bind()."""
        binding = EthereumBinding(private_key=None)
        with pytest.raises(ValueError, match="without a private key"):
            binding.bind(AGENT_PUBKEY, "0x0000000000000000000000000000000000000000")


class TestEthereumBindingVerify:
    """verify() checks the personal_sign signature against the Ethereum address."""

    def test_verify_valid_signature(self):
        """Valid signature returns True."""
        binding = EthereumBinding(private_key=ETH_PRIVKEY)
        sig = binding.bind(AGENT_PUBKEY, binding.address)
        assert binding.verify(AGENT_PUBKEY, binding.address, sig) is True

    def test_verify_wrong_address_returns_false(self):
        """Signature for a different address returns False."""
        binding = EthereumBinding(private_key=ETH_PRIVKEY)
        sig = binding.bind(AGENT_PUBKEY, binding.address)
        assert binding.verify(AGENT_PUBKEY, "0x0000000000000000000000000000000000000001", sig) is False

    def test_verify_wrong_pubkey_returns_false(self):
        """Signature over a different pubkey returns False."""
        binding = EthereumBinding(private_key=ETH_PRIVKEY)
        sig = binding.bind(AGENT_PUBKEY, binding.address)
        other_pubkey = bytes.fromhex("00" * 32)
        assert binding.verify(other_pubkey, binding.address, sig) is False

    def test_verify_tampered_signature_returns_false(self):
        """Modified signature bytes return False, not an exception."""
        binding = EthereumBinding(private_key=ETH_PRIVKEY)
        sig = bytearray(binding.bind(AGENT_PUBKEY, binding.address))
        sig[0] ^= 0xFF
        assert binding.verify(AGENT_PUBKEY, binding.address, bytes(sig)) is False

    def test_verify_wrong_length_signature_returns_false(self):
        """Signature of wrong length is rejected without exception."""
        binding = EthereumBinding(private_key=ETH_PRIVKEY)
        assert binding.verify(AGENT_PUBKEY, binding.address, b"too-short") is False

    def test_verify_readonly_binding_works(self):
        """Read-only binding can verify without a private key."""
        signer = EthereumBinding(private_key=ETH_PRIVKEY)
        sig = signer.bind(AGENT_PUBKEY, signer.address)
        readonly = EthereumBinding(private_key=None)
        assert readonly.verify(AGENT_PUBKEY, signer.address, sig) is True


class TestEthereumBindingSerialization:
    """serialize_binding_info() returns binding metadata dict."""

    def test_serialize_contains_type_and_address(self):
        binding = EthereumBinding(private_key=ETH_PRIVKEY)
        info = binding.serialize_binding_info()
        assert info["binding_type"] == "ethereum"
        assert info["address"] == binding.address

    def test_serialize_readonly_has_none_address(self):
        binding = EthereumBinding(private_key=None)
        info = binding.serialize_binding_info()
        assert info["address"] is None
