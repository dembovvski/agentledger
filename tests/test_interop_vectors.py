"""
Cross-implementation test vectors for policy_digest interoperability.

Vectors confirmed matching across:
  - AgentLedger (Python) — reference implementation
  - Nobulex (TypeScript/Node.js) — arian-gogani, github.com/arian-gogani/nobulex

Canonicalization: RFC 8785 JCS (sorted keys, no whitespace, arrays pre-sorted
by implementation before hashing). Hash: SHA-256 of canonical UTF-8 bytes.

If this test fails, the Python implementation has diverged from the agreed
cross-implementation wire format.
"""

import hashlib
import jcs
import pytest


VECTORS = [
    (
        {"denied": ["delete_file"], "type": "denylist"},
        "sha256:e9527aa54a4bae62ddbf3157475aa2d8fd2d6c7a4bb3f30b6dba624ff189e833",
    ),
    (
        {"denied": ["delete_file", "send_email"], "type": "denylist"},
        "sha256:051a6f9e19eb3e7966dd43c1db77af7c20b4bdb68eafdfe4ff7a7bb58d9c9175",
    ),
    (
        {"allowed": ["read_file", "web_search"], "type": "allowlist"},
        "sha256:c373ee900e001b4b61cd0c727b978146b99a76e2b9eabd93740f041a6970d0a4",
    ),
]


@pytest.mark.parametrize("config,expected", VECTORS)
def test_policy_digest_cross_impl(config, expected):
    """policy_digest must match Nobulex (TypeScript) for the same canonical input."""
    digest = "sha256:" + hashlib.sha256(jcs.canonicalize(config)).hexdigest()
    assert digest == expected


def test_array_order_invariant():
    """Arrays must be sorted before hashing — construction order must not affect digest."""
    from agentledger.policies import DenylistPolicy, AllowlistPolicy

    assert DenylistPolicy(["send_email", "delete_file"]).policy_id == \
           DenylistPolicy(["delete_file", "send_email"]).policy_id

    assert AllowlistPolicy(["web_search", "read_file"]).policy_id == \
           AllowlistPolicy(["read_file", "web_search"]).policy_id
