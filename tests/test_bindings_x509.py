"""
Tests for X509Binding — PKI-based principal binding via cryptography library.

cryptography is an optional extra: pip install agentledger[x509]
All tests are skipped if cryptography is not installed.
"""

import pytest

cryptography = pytest.importorskip(
    "cryptography", reason="cryptography not installed — pip install agentledger[x509]"
)

from agentledger.bindings.x509 import X509Binding

# Fixed test agent pubkey (not sensitive, only for unit tests)
AGENT_PUBKEY = bytes.fromhex("a1b2c3d4e5f6" + "00" * 26)

# ─── Key/cert fixture helpers ────────────────────────────────────────────────


def _generate_test_cert_and_key():
    """Generate a self-signed RSA cert + key for testing. Returns (cert_pem, key_pem)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.NoEncryption(),
        serialization.PrivateFormat.TraditionalOpenSSL,
    )
    return cert_pem, key_pem


@pytest.fixture
def rsa_cert_and_key():
    cert_pem, key_pem = _generate_test_cert_and_key()
    return cert_pem, key_pem


@pytest.fixture
def x509_binding_signing(rsa_cert_and_key):
    cert_pem, key_pem = rsa_cert_and_key
    return X509Binding(cert_bytes=cert_pem, key_bytes=key_pem)


@pytest.fixture
def x509_binding_readonly(rsa_cert_and_key):
    cert_pem, _ = rsa_cert_and_key
    return X509Binding(cert_bytes=cert_pem)


class TestX509BindingBind:
    """bind() signs the agent pubkey with the certificate's private key."""

    def test_bind_returns_signature_bytes(self, x509_binding_signing):
        """bind() returns raw signature bytes (not PEM)."""
        pid = x509_binding_signing.fingerprint
        sig = x509_binding_signing.bind(AGENT_PUBKEY, pid)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_bind_uses_cert_fingerprint_as_default_principal_id(self, x509_binding_signing):
        """principal_id defaults to sha256:fingerprint when not provided."""
        expected_fp = f"sha256:{x509_binding_signing.fingerprint}"
        sig = x509_binding_signing.bind(AGENT_PUBKEY, expected_fp)
        assert isinstance(sig, bytes)

    def test_bind_accepts_subject_dn_as_principal_id(self, x509_binding_signing, rsa_cert_and_key):
        """principal_id can be the certificate's Subject DN."""
        cert_pem, _ = rsa_cert_and_key
        binding = X509Binding(cert_bytes=cert_pem)
        dn = binding.subject_dn
        sig = binding.bind(AGENT_PUBKEY, dn)
        assert isinstance(sig, bytes)

    def test_bind_mismatched_principal_id_raises(self, x509_binding_signing):
        """Mismatched principal_id raises ValueError."""
        with pytest.raises(ValueError, match="does not match"):
            x509_binding_signing.bind(AGENT_PUBKEY, "sha256:0000000000000000000000000000000000000000000000")

    def test_bind_no_private_key_raises(self, x509_binding_readonly):
        """Read-only binding raises ValueError on bind()."""
        pid = f"sha256:{x509_binding_readonly.fingerprint}"
        with pytest.raises(ValueError, match="without a private key"):
            x509_binding_readonly.bind(AGENT_PUBKEY, pid)


class TestX509BindingVerify:
    """verify() checks the signature against the certificate's public key."""

    def test_verify_valid_signature(self, x509_binding_signing):
        """Valid RSA-PSS signature returns True."""
        pid = f"sha256:{x509_binding_signing.fingerprint}"
        sig = x509_binding_signing.bind(AGENT_PUBKEY, pid)
        assert x509_binding_signing.verify(AGENT_PUBKEY, pid, sig) is True

    def test_verify_wrong_pubkey_returns_false(self, x509_binding_signing):
        """Signature over a different pubkey returns False."""
        pid = f"sha256:{x509_binding_signing.fingerprint}"
        sig = x509_binding_signing.bind(AGENT_PUBKEY, pid)
        other_pubkey = bytes.fromhex("00" * 32)
        assert x509_binding_signing.verify(other_pubkey, pid, sig) is False

    def test_verify_tampered_signature_returns_false(self, x509_binding_signing):
        """Modified signature returns False, not an exception."""
        pid = f"sha256:{x509_binding_signing.fingerprint}"
        sig = bytearray(x509_binding_signing.bind(AGENT_PUBKEY, pid))
        sig[0] ^= 0xFF
        assert x509_binding_signing.verify(AGENT_PUBKEY, pid, bytes(sig)) is False

    def test_verify_wrong_principal_id_returns_false(self, x509_binding_signing):
        """Signature for wrong principal_id returns False."""
        sig = x509_binding_signing.bind(AGENT_PUBKEY, x509_binding_signing.fingerprint)
        wrong_pid = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        assert x509_binding_signing.verify(AGENT_PUBKEY, wrong_pid, sig) is False

    def test_verify_no_cert_returns_false(self):
        """Binding initialised without a cert returns False on verify."""
        binding = X509Binding()
        assert binding.verify(AGENT_PUBKEY, "sha256:whatever", b"sig") is False


class TestX509BindingSerialization:
    """serialize_binding_info() returns certificate metadata."""

    def test_serialize_contains_type_fingerprint_and_dn(self, x509_binding_signing):
        info = x509_binding_signing.serialize_binding_info()
        assert info["binding_type"] == "x509"
        assert "fingerprint" in info
        assert "subject_dn" in info

    def test_serialize_no_cert_returns_none(self):
        binding = X509Binding()
        info = binding.serialize_binding_info()
        assert info["fingerprint"] is None
        assert info["subject_dn"] is None
