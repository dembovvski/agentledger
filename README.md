# AgentLedger

**Tamper-evident audit trail and pre-execution policy enforcement for multi-agent AI systems.**

[![IETF Draft](https://img.shields.io/badge/IETF-draft--dembowski--agentledger--proof--of--behavior--00-blue)](https://datatracker.ietf.org/doc/draft-dembowski-agentledger-proof-of-behavior/)

```
$ python examples/demo.py

AgentLedger Protocol — Python Demo
==================================================

Agent Alpha  id: 6c24573e…
Agent Beta   id: 520244a4…

Agent Alpha declares policy: forbid delete_file, forbid send_email

Agent Alpha executes actions…
  ✓  read_file          "data/users.csv"   — allowed   [cc8fa3ff…]
  ✓  web_search         "market analysis"  — allowed   [d6e6e878…]
  ✓  write_file         "report.md"        — allowed   [c334b844…]
  ✗  delete_file        "data/users.csv"   — BLOCKED by policy
  ✓  read_file          "config.yaml"      — allowed   [0b23c0b2…]

Verifying Agent Alpha's chain…
  ✓  Hash linkage:       5 receipts, chain intact
  ✓  Ed25519 signatures: all valid
  ✓  Policy enforcement: 1 DENIED receipt — delete_file blocked before execution
  ✓  policy_hash in signed payload — policy config tamper-evident

Agent Beta creates cross-agent receipt referencing Alpha…
  ✓  Cross-agent ref resolved: True
  ✓  Alpha receipt cc8fa3ff… signature verified by Beta

Agent Mallory presents tampered log…
  ✗  mallory.jsonl:4: prev_hash mismatch — expected be01b3…, got d49bfb…
  ✓  Tamper detected — chain rejected

==================================================
  Receipts written : 5 (1 DENIED, 4 COMPLETED)
  Chain verified   : ✓ PASS
  Tamper detected  : ✓ PASS
  Cross-agent ref  : ✓ PASS
```

---

## What is AgentLedger?

AI agents that can edit files, call APIs, and execute code need an answer to: *what did this agent do, under what rules, and can a third party verify it?*

AgentLedger provides three primitives:

**Declare** — define behavioral rules in Python before deployment  
**Enforce** — every action evaluated by the policy gate before execution  
**Prove** — Ed25519-signed, SHA-256 hash-chained receipts anyone can verify

The key property: a **DENIED receipt is written before execution**. If a policy blocks an action, the refusal is signed and chain-linked — the agent physically cannot suppress it.

---

## Quick Start

```bash
pip install agentledger
```

```python
from agentledger.core.identity import AgentIdentityImpl
from agentledger.core.chain import ReceiptChainImpl
from agentledger.policies import DenylistPolicy
from agentledger.interfaces import ActionType, ActionStatus, Framework, PolicyViolationError

# 1. Create agent identity (Ed25519 keypair)
identity = AgentIdentityImpl.create(binding=your_binding, principal_id="agent@example.com")

# 2. Declare behavioral policy
policy = DenylistPolicy(["delete_file", "send_email", "exec_shell"])

# 3. Create receipt chain
chain = ReceiptChainImpl(identity, storage_path="./receipts", policy=policy)

# 4. Record actions — policy evaluated before every append()
try:
    rid = chain.append(ActionType.TOOL_CALL, Framework.CUSTOM, tool_name="delete_file")
    chain.finalize_last(status=ActionStatus.COMPLETED)
except PolicyViolationError:
    # Signed DENIED receipt already written to chain — execution never happened
    pass

# 5. Verify from disk — catches tampering even after process restart
ok, msg = chain.verify_from_disk()
print(msg)  # "5 receipts verified — chain valid"
```

```bash
# CLI verification — works without Python, just the JSONL file and public key
agentledger verify ./receipts/agent_20260420.jsonl --agent-public-key <hex>
```

---

## Framework Integrations

Drop-in callbacks for existing agent frameworks — no changes to agent code required.

### LangChain

```python
from agentledger.integrations.langchain import AgentLedgerCallback

callback = AgentLedgerCallback(identity=identity, chain=chain)
agent = initialize_agent(tools, llm, callbacks=[callback])  # that's it
```

### AutoGen

```python
from agentledger.integrations.autogen import AgentLedgerAutoGenHook

hook = AgentLedgerAutoGenHook(identity=identity, chain=chain)
hook.attach(agent)
```

### CrewAI

```python
from agentledger.integrations.crewai import AgentLedgerCrewCallback

callback = AgentLedgerCrewCallback(identity=identity, chain=chain)
crew = Crew(agents=[...], tasks=[...], step_callback=callback.step_callback)
```

---

## Policy Gate

Actions are evaluated before execution. If denied, a signed DENIED receipt is written to the chain before `PolicyViolationError` is raised — the agent cannot execute the action or suppress the refusal.

```python
from agentledger.policies import DenylistPolicy, AllowlistPolicy, CompositePolicy

# Block specific tools
policy = DenylistPolicy(["rm_rf", "exec_shell", "send_email"])

# Allow only specific tools (everything else denied)
policy = AllowlistPolicy(["web_search", "read_file", "write_file"])

# Chain policies — first DENY wins
policy = CompositePolicy([DenylistPolicy(["rm_rf"]), AllowlistPolicy(["search"])])
```

Each policy has a stable `policy_id` (SHA-256 of config) that is embedded in every receipt's signed payload. A verifier can confirm not just that an action was recorded, but that a specific policy was enforced at that moment.

---

## Cross-Agent Receipts

When agents collaborate, handoffs are chain-linked. Agent Beta can verify that Agent Alpha actually completed a specific action — with Ed25519 signature verification on the referenced receipt.

```python
from agentledger.interfaces import CrossAgentRef, CrossAgentRefStatus

# Agent Beta references Agent Alpha's completed receipt
ref = CrossAgentRef(
    target_agent_id=alpha_identity.agent_id,  # Ed25519 public key
    ref_receipt_id=alpha_receipt_id,
    status=CrossAgentRefStatus.PENDING,
)
chain_beta.append(ActionType.CROSS_AGENT, Framework.CUSTOM, cross_agent_ref=ref)

# Verify — reads Alpha's JSONL, checks Ed25519 signature on the specific receipt
resolved = chain_beta.resolve_cross_ref(ref)  # True if Alpha's receipt is valid
```

---

## Receipt Schema

Every receipt is a signed JSON object, hash-chained to the previous one.

```json
{
  "receipt_id": "uuid-v4",
  "agent_id": "ed25519-public-key-hex",
  "principal_id": "agent@example.com",
  "chain_id": "ed25519-public-key-hex",
  "timestamp": "2026-04-20T10:00:00+00:00",
  "prev_hash": "sha256-of-previous-receipt",
  "schema_version": "0.1",
  "action": {
    "type": "tool_call",
    "framework": "langchain",
    "tool_name": "web_search",
    "status": "completed",
    "payload_hash": "sha256-of-input",
    "result_hash": "sha256-of-output",
    "policy_hash": "sha256-of-policy-config"
  },
  "signature": "ed25519-signature-hex"
}
```

The `signature` covers everything except itself — keys sorted, no whitespace (JCS-compatible). `policy_hash` is inside the signed payload: swapping policy config breaks all signatures.

---

## Verification

```bash
# Verify hash linkage + Ed25519 signatures
agentledger verify ./receipts/agent_20260420.jsonl --agent-public-key <hex>

# Fast path — verify from nearest checkpoint
agentledger verify ./receipts/ --checkpoint-only

# Human-readable inspection
agentledger inspect ./receipts/agent_20260420.jsonl --verbose
```

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Tamper evidence | SHA-256 hash chain — any modification breaks all subsequent links |
| Non-repudiation | Ed25519 signature per receipt — proves agent identity |
| Pre-execution enforcement | DENIED receipt written before `PolicyViolationError` raised |
| Policy binding | `policy_hash` in signed payload — policy swap breaks signatures |
| External observer | Callback registered outside agent code — agent cannot suppress |
| Key persistence | `save_private_key()` + `load()` — survives process restarts |

**Known limitations:**
- No key revocation — compromised keys remain trusted until replaced out-of-band
- `verify()` checks in-memory state only — use `verify_from_disk()` for tamper detection
- Single-operator deployments: operator with write access can rewrite the JSONL; mitigate with external checkpointing or bilateral signing

---

## Install

```bash
# Core (Ed25519, hash chain, policy gate)
pip install agentledger

# With LangChain integration
pip install 'agentledger[langchain]'

# With compliance dashboard
pip install 'agentledger[dashboard]'
agentledger dashboard --storage ./receipts --port 8000

# Everything
pip install 'agentledger[all]'
```

Python 3.11+. No external services required.

---

## Standards

- [LangChain RFC #35691](https://github.com/langchain-ai/langchain/discussions/35691) — ComplianceCallbackHandler, active cross-framework discussion
- NIST AI Agent Standards Initiative — Q4 2026 Interoperability Profile

---

## License

MIT — use for anything.

Enterprise features (cross-agent receipt dashboard, advanced policy engine, compliance reports, SLA support) available for licensed deployments.
