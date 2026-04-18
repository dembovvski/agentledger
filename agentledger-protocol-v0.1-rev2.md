# AgentLedger Protocol — v0.1 Draft Specification

> Status: DRAFT — not for public release  
> Authors: working draft  
> Date: 2026-04-18  
> Changelog: rev2 — pluggable binding, async/sync cross-agent refs, checkpoint hashes

---

## 1. Problem Statement

Multi-agent AI systems deployed in production lack a standardized,
tamper-evident mechanism for recording what agents did, on whose authority,
and at what cost. Existing frameworks (LangChain, AutoGen, CrewAI) provide
observability hooks but not compliance-grade audit trails.

This protocol defines the minimum viable standard for:

- **Who** executed an action (Identity, Layer 1)
- **What** was executed and when (Audit Trail, Layer 3)

Budget enforcement (Layer 2) and compliance reporting (Layer 4) are
defined as extensions in v0.2+.

---

## 2. Scope of v0.1

**In scope:**

- Agent identity (Ed25519 keypair + pluggable principal binding)
- Per-agent append-only receipt chain
- Cross-agent receipt references (async and sync)
- Optional checkpoint hashes for fast chain verification
- LangChain callback integration
- Local storage (`.jsonl` append-only log)

**Out of scope in v0.1:**

- Budget enforcement (Layer 2) — v0.2
- Compliance reporting exports (Layer 4) — v0.3
- Distributed replication — v0.2
- AutoGen / CrewAI integrations — v0.2

---

## 3. Core Data Structures

### 3.1 Agent Identity

Every agent has exactly one Ed25519 keypair. The public key is the agent's
permanent identifier. The private key never leaves the agent's runtime.

Principal binding is established once at agent initialization:

```json
{
  "agent_id": "<ed25519-public-key-hex>",
  "principal_id": "<identifier — format depends on binding_type>",
  "binding_type": "ethereum | x509 | custom",
  "derived_from": "<parent-agent-id | null>",
  "binding_signature": "<signature of agent_id by principal>",
  "created_at": "2026-04-18T10:00:00Z",
  "schema_version": "0.1"
}
```

**Key derivation:**

- Agent generates its own Ed25519 keypair independently
- Principal signs `agent_id` using their preferred binding method
- This creates non-repudiable proof: "this principal authorized this agent"
- Binding method is pluggable — see Section 3.4

**Sub-agents:**

- Child agent sets `derived_from` = parent agent's `agent_id`
- Parent agent signs child's identity with its own Ed25519 key
- Creates verifiable delegation chain: Principal → Agent → Sub-agent

---

### 3.2 Receipt (single action record)

Each agent maintains its own independent receipt chain.
`prev_hash` references only the previous receipt in **this agent's chain**.

```json
{
  "receipt_id": "<uuid-v4>",
  "schema_version": "0.1",
  "prev_hash": "<sha256-of-previous-receipt-json | null-if-first>",
  "chain_id": "<agent_id>",
  "timestamp": "2026-04-18T10:01:23.456Z",
  "agent_id": "<ed25519-public-key-hex>",
  "principal_id": "<identifier matching identity file>",
  "action": {
    "type": "tool_call | llm_invoke | decision | cross_agent",
    "framework": "langchain | autogen | crewai | custom",
    "tool_name": "<string | null>",
    "status": "pending | completed | failed",
    "payload_hash": "<sha256-of-actual-input-payload>",
    "result_hash": "<sha256-of-actual-output | null-if-pending-or-failed>",
    "error": "<error message string | null-if-not-failed>"
  },
  "cross_agent_ref": {
    "target_agent_id": "<agent_id | null>",
    "ref_receipt_id": "<receipt_id in target chain | null>",
    "status": "pending | confirmed"
  },
  "signature": "<ed25519-signature-of-all-above-fields>"
}
```

**Rules:**

- `prev_hash` is `null` only for the first receipt in a chain
- `signature` covers entire JSON object minus `signature` field,
  keys canonically sorted (lexicographic, all levels)
- `payload_hash` and `result_hash` use SHA-256 of canonical JSON
- Actual payloads stored separately — receipts contain only hashes
- `cross_agent_ref` is `null` for non-delegation actions
- `action.status` transitions: `pending` → `completed` (success) or `failed` (error)
- `action.error` is non-null only when `status = "failed"`; contains stringified error message
- Failed receipts are first-class audit records — absence of failure receipts is itself suspicious

---

### 3.3 Cross-Agent References

When Agent A delegates to Agent B, A issues a receipt with
`action.type = "cross_agent"`. Chains remain independent, linked by refs.

**Async delegation (default):**

Agent A does not wait for B. Records `pending` immediately.
After reconciliation, appends a `confirmed` update receipt.

```json
// emitted immediately on delegation
"cross_agent_ref": {
  "target_agent_id": "B_agent_id",
  "ref_receipt_id": null,
  "status": "pending"
}

// emitted after B's receipt_id is known
"cross_agent_ref": {
  "target_agent_id": "B_agent_id",
  "ref_receipt_id": "B_receipt_uuid",
  "status": "confirmed"
}
```

**Sync delegation (optional):**

Agent A blocks until B returns receipt ID. Use when regulations
require proof that B executed before A continued.

```json
"cross_agent_ref": {
  "target_agent_id": "B_agent_id",
  "ref_receipt_id": "B_receipt_uuid",
  "status": "confirmed"
}
```

**Chain structure:**

```text
Agent A chain:                        Agent B chain:
  receipt_1                             receipt_1
  receipt_2 (pending → B)               receipt_2  ← B executes
  receipt_3                             receipt_3
  receipt_4 (confirmed → B:receipt_2)
```

Layer 4 reconstructs the full execution graph from confirmed refs.

---

### 3.4 Principal Binding (pluggable interface)

Any implementation satisfying this interface is protocol-compliant:

```python
class PrincipalBinding:
    binding_type: str  # "ethereum" | "x509" | "custom"

    def bind(self, agent_public_key: bytes, principal_id: str) -> bytes:
        """Returns signature proving principal authorized this agent."""
        ...

    def verify(
        self,
        agent_public_key: bytes,
        principal_id: str,
        signature: bytes
    ) -> bool:
        """Returns True if signature is valid."""
        ...
```

**Two reference implementations in v0.1:**

`EthereumBinding` — crypto-native teams:

- `principal_id` = Ethereum address (`0x...`)
- `binding_signature` = `eth_sign(agent_id_hex)` via web3.py
- Verification: recover signer, compare to principal_id

`X509Binding` — traditional enterprise:

- `principal_id` = certificate Subject DN or SHA-256 fingerprint
- `binding_signature` = PKCS#7 signature via corporate certificate
- Compatible with Active Directory, Okta, HSM-backed PKI
- Enterprise teams never encounter blockchain concepts

---

## 4. Storage Format

### 4.1 File structure

```text
receipts/
  {agent_id_short}_{date}_{session_id}.jsonl
  {agent_id_short}_{date}_{session_id}.jsonl.deleted
identity/
  {agent_id_short}.json
payloads/
  {receipt_id}.json     ← actual content, referenced by hash only
```

`agent_id_short` = first 8 hex characters of agent public key.

### 4.2 JSONL format

One receipt per line. Append-only. Never modify existing lines.
Checkpoint entries are interspersed, distinguished by `"checkpoint": true`.

```jsonl
{"receipt_id":"uuid-1","prev_hash":null,...,"signature":"..."}
{"receipt_id":"uuid-2","prev_hash":"abc123",...,"signature":"..."}
{"checkpoint":true,"at_receipt_id":"uuid-2","receipt_count":2,"cumulative_hash":"sha256...","signature":"..."}
```

### 4.3 GDPR compliance

Deletion = rename to `.deleted` + append:

```json
{"deleted_at": "2026-04-18T12:00:00Z", "reason": "gdpr_erasure_request"}
```

Content preserved for chain integrity. Compliance layer (v0.3) treats
`.deleted` files as redacted in reports.

### 4.4 Checkpoint hashes (optional, recommended)

Every N receipts (default N=100, configurable):

```json
{
  "checkpoint": true,
  "at_receipt_id": "<last receipt_id in batch>",
  "receipt_count": 100,
  "cumulative_hash": "<sha256 of receipts 1–N concatenated>",
  "signature": "<ed25519 signature of this checkpoint>"
}
```

Enables fast verification: jump to nearest checkpoint, validate
cumulative hash, walk only the tail. Without checkpoints, verification
is O(n) — correct but slower for long-running agents.

---

## 5. LangChain Integration (v0.1 reference)

```python
from langchain.callbacks.base import BaseCallbackHandler
from agentledger import AgentIdentity, ReceiptChain

class AgentLedgerCallback(BaseCallbackHandler):
    def __init__(self, identity: AgentIdentity, chain: ReceiptChain):
        self.identity = identity
        self.chain = chain

    def on_tool_start(self, serialized, input_str, **kwargs):
        self.chain.append(
            action_type="tool_call",
            framework="langchain",
            tool_name=serialized.get("name"),
            payload=input_str,
        )

    def on_tool_end(self, output, **kwargs):
        self.chain.finalize_last(result=output)

    def on_llm_start(self, serialized, prompts, **kwargs):
        self.chain.append(
            action_type="llm_invoke",
            framework="langchain",
            payload=prompts,
        )

    def on_llm_end(self, response, **kwargs):
        self.chain.finalize_last(result=response)

    def on_agent_action(self, action, **kwargs):
        self.chain.append(
            action_type="decision",
            framework="langchain",
            payload=action,
        )

    def on_tool_error(self, error, **kwargs):
        self.chain.finalize_last(status="failed", error=str(error))

    def on_llm_error(self, error, **kwargs):
        self.chain.finalize_last(status="failed", error=str(error))

    def on_agent_finish(self, finish, **kwargs):
        self.chain.finalize_last(status="completed", result=finish)

    def on_chain_error(self, error, **kwargs):
        self.chain.finalize_last(status="failed", error=str(error))
```

**Usage:**

```python
from agentledger import AgentIdentity, ReceiptChain, EthereumBinding
from agentledger.integrations.langchain import AgentLedgerCallback

identity = AgentIdentity.create(
    binding=EthereumBinding(private_key=os.getenv("PRINCIPAL_ETH_KEY"))
)
chain = ReceiptChain(identity=identity, storage_path="./receipts")
callback = AgentLedgerCallback(identity=identity, chain=chain)

agent = initialize_agent(..., callbacks=[callback])
```

**Observer guarantee:** Callback registered externally — agent cannot
suppress it or modify receipts after they are written.

**Thread safety requirement:** `finalize_last` MUST be thread-safe.
In parallel agent execution (e.g. tool calls dispatched concurrently),
two threads may call `finalize_last` simultaneously — once for each
completing operation. Without a lock or atomic compare-and-swap on the
"pending" receipt slot, one thread overwrites the other's `result_hash`
or corrupts `prev_hash` linkage. Implementations MUST serialize writes
to the pending-receipt slot (mutex or equivalent). This is a correctness
requirement, not a performance concern — silent data corruption is worse
than a serialization bottleneck.

---

## 6. Chain Verification

```text
1. Load identity file
2. Verify binding: binding.verify(agent_id, principal_id, binding_signature)
3. Load .jsonl line by line
4. Each receipt: verify Ed25519 signature against agent_id
5. Each receipt except first: verify prev_hash matches SHA-256 of previous
6. Checkpoint entries: verify cumulative_hash matches recomputed batch hash
7. Confirmed cross_agent_refs: optionally load target chain, verify ref exists
```

All pass → chain is tamper-evident, authorship proven, delegation graph
reconstructable by Layer 4.

---

## 7. What v0.1 Does NOT Claim

This version **records** — it does not **enforce**.

A misconfigured agent can refuse to load the callback. The protocol
does not prevent this in v0.1. Mandatory enforcement is Layer 2 (v0.2).

**What v0.1 guarantees:** if receipts exist, they are authentic and unmodified.  
**What v0.1 does not guarantee:** receipts are complete.

---

## 8. Open Questions for Community RFC

1. SHA-256 vs BLAKE3? SHA-256 for v0.1 (compliance-recognized),
   BLAKE3 as opt-in in v0.2.

2. Key rotation: new `agent_id` on compromise (simpler), or rotation
   record in identity file (preserves history)?

3. Async reconciliation mechanism: how does Agent A learn Agent B's
   `receipt_id`? Left to implementor in v0.1. Standard reconciliation
   protocol targeted for v0.2.

4. Checkpoint interval N=100 — appropriate for high-frequency agents
   (thousands of actions/minute)?

---

## 9. Implementation Checklist (v0.1)

- [ ] `agentledger` Python package — core data structures
- [ ] `EthereumBinding` (web3.py)
- [ ] `X509Binding` (cryptography library)
- [ ] `ReceiptChain` — JSONL storage, checkpoint support, finalize_last (thread-safe)
- [ ] `AgentLedgerCallback` for LangChain — complete with tests
- [ ] CLI: `agentledger verify ./receipts/agent123_*.jsonl`
- [ ] CLI: `agentledger inspect ./receipts/` — human-readable summary
- [ ] RFC comment to langchain #35691 and autogen #7353

## 10. v0.2 Scope (for reference)

- Budget enforcement (Layer 2): reserve → execute → commit/rollback
- AutoGen hook integration
- Standard async reconciliation protocol for cross-agent refs
- SQLite backend option for queryable storage

---

This document is a working draft. Do not publish without review.
