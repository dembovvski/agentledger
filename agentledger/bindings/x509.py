"""
X509Binding — enterprise principal binding via corporate certificates.

principal_id = certificate Subject DN or SHA-256 fingerprint
binding_signature = signature over agent_id using certificate private key
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
except ImportError as e:
    raise ImportError(
        "X509Binding requires cryptography. "
        "Install: pip install agentledger[x509]"
    ) from e

from agentledger.interfaces import PrincipalBinding


class X509Binding(PrincipalBinding):
    """
    X509 certificate-based principal binding.

    The principal proves authorisation by signing the agent's Ed25519
    public key with their certificate's private key (RSA or ECDSA).

    enterprise teams with existing PKI (Active Directory, Okta, HSM-backed
    certificates) can bind agents to their corporate identity.

    Usage:
        binding = X509Binding(cert_path="corp_cert.pem", key_path="corp_key.pem")
        sig = binding.bind(agent_public_key=ed25519_pubkey_bytes, principal_id=cert_sha256_fingerprint)
        is_valid = binding.verify(agent_public_key, principal_id, sig)
    """

    binding_type = "x509"

    def __init__(
        self,
        cert_path: str | None = None,
        key_path: str | None = None,
        cert_bytes: bytes | None = None,
        key_bytes: bytes | None = None,
        password: bytes | None = None,
    ) -> None:
        """
        Args:
            cert_path: Path to PEM/DER X509 certificate file.
            key_path: Path to PEM private key file (optional — enables signing).
            cert_bytes: Certificate as bytes (alternative to cert_path).
            key_bytes: Private key as bytes (alternative to key_path).
            password: Password to decrypt the private key (if encrypted).
        """
        self._cert: x509.Certificate | None = None
        self._private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None = None

        if cert_bytes:
            self._cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        elif cert_path:
            with open(cert_path, "rb") as f:
                self._cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        if key_bytes:
            self._private_key = serialization.load_pem_private_key(
                key_bytes, password=password, backend=default_backend()
            )
        elif key_path:
            with open(key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(), password=password, backend=default_backend()
                )

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the certificate (hex)."""
        if self._cert is None:
            raise ValueError("No certificate loaded.")
        return self._cert.fingerprint(hashes.SHA256()).hex()

    @property
    def subject_dn(self) -> str:
        """Certificate Subject Distinguished Name as a string."""
        if self._cert is None:
            raise ValueError("No certificate loaded.")
        return self._cert.subject.rfc4514_string()

    def _principal_id_from_cert(self) -> str:
        """Default principal_id = SHA-256 fingerprint."""
        return f"sha256:{self.fingerprint}"

    def bind(
        self,
        agent_public_key: bytes,
        principal_id: str,
    ) -> bytes:
        """
        Sign agent_public_key with the certificate's private key.

        Args:
            agent_public_key: Raw Ed25519 public key bytes (32 bytes).
            principal_id: Must match our certificate's fingerprint or Subject DN.

        Returns:
            Raw signature bytes (RSA-PSS or ECDSA-DER depending on key type).
        """
        if self._private_key is None:
            raise ValueError(
                "Cannot sign: X509Binding was initialised without a private key. "
                "Provide key_path or key_bytes to enable signing."
            )

        # Verify principal_id matches our certificate
        expected_fp = f"sha256:{self.fingerprint}"
        expected_dn = self.subject_dn
        if principal_id != expected_fp and principal_id != expected_dn:
            raise ValueError(
                f"principal_id '{principal_id}' does not match certificate. "
                f"Expected fingerprint '{expected_fp}' or DN '{expected_dn}'."
            )

        # Canonical message: agent_id as hex string (same as spec)
        agent_id_hex = agent_public_key.hex()
        message = agent_id_hex.encode("utf-8")

        if isinstance(self._private_key, rsa.RSAPrivateKey):
            sig = self._private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif isinstance(self._private_key, ec.EllipticCurvePrivateKey):
            sig = self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        else:
            raise TypeError(f"Unsupported private key type: {type(self._private_key)}")

        return sig

    def verify(
        self,
        agent_public_key: bytes,
        principal_id: str,
        signature: bytes,
    ) -> bool:
        """
        Verify signature over agent_public_key using the certificate's public key.

        Args:
            agent_public_key: Raw Ed25519 public key bytes.
            principal_id: Certificate fingerprint 'sha256:...' or Subject DN.
            signature: Raw signature bytes.

        Returns:
            True if signature is valid.
        """
        if self._cert is None:
            return False

        # Verify principal_id matches cert
        expected_fp = f"sha256:{self.fingerprint}"
        expected_dn = self.subject_dn
        if principal_id != expected_fp and principal_id != expected_dn:
            return False

        public_key = self._cert.public_key()
        agent_id_hex = agent_public_key.hex()
        message = agent_id_hex.encode("utf-8")

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            else:
                return False
        except Exception:
            return False

        return True

    def serialize_binding_info(self) -> dict[str, Any]:
        """Return serialisable dict for identity file."""
        return {
            "binding_type": self.binding_type,
            "subject_dn": self.subject_dn if self._cert else None,
            "fingerprint": self.fingerprint if self._cert else None,
        }
