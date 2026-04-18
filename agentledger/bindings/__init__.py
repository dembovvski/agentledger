"""
PrincipalBinding — pluggable binding interface re-export.
Concrete implementations: EthereumBinding, X509Binding.
"""

from agentledger.interfaces import PrincipalBinding

try:
    from agentledger.bindings.ethereum import EthereumBinding
except ImportError:
    EthereumBinding = None  # type: ignore[assignment,misc]

try:
    from agentledger.bindings.x509 import X509Binding
except ImportError:
    X509Binding = None  # type: ignore[assignment,misc]

__all__ = ["PrincipalBinding", "EthereumBinding", "X509Binding"]
