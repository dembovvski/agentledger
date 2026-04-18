"""
PrincipalBinding — pluggable binding interface re-export.
Concrete implementations: EthereumBinding, X509Binding.
"""

from agentledger.interfaces import PrincipalBinding

__all__ = ["PrincipalBinding"]
