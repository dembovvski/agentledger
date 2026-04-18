langchain #35691 — "RFC: ComplianceCallbackHandler — tamper-evident audit trails"
    30 comments, 9 unique commenters, 3+ niezależnych implementacji (asqav, AgentMint, Aira, SteelSpine, Agent Passport, Signet)
    Komentujący zgłosili się z gotowymi rozwiązaniami KAŻDY NIEZALEŻNIE — klasyczny sygnał że ból jest szeroki.
    Ból: LangChain ma observability hooks, ale nie compliance-grade audit trails. Trzy regulatory drivers: EU AI Act Art. 12, AIUC-1, ISO 42001.
    
microsoft/autogen #7353 — "Cryptographic action receipts for enterprise governance (AAR)"
    28 comments, 14 unique commenters
    Najszersze zaangażowanie ze wszystkich znalezionych. AAR = append-only, tamper-evident receipt dla każdej akcji agenta. 14 różnych osób — największa różnorodność komentarzy.
langchain #36306 — "Payment primitive integration — x402"
    11 comments, 6 unique commenters, 3+ niezależnych firm
    Komentujący: MAXIA (AI-to-AI marketplace), LortuArte (agentwallet-sdk), WTRMRK, Agent Passport System, up2itnow0822 (te same osoby co w AutoGen)
 Ból: "LangChain has 1000+ integrations but no payment execution layer" — albo hardkodujesz API key bez governance, albo dajesz agentowi unlimited spend. Żadnego środka.
    Rozwiązanie: x402 payment protocol + per-agent wallet z enforce-on-contract.
    
  autogen #7492 — "Payment primitive for multi-agent systems"
    14 comments, 4 unique commenters
    Komentujący: up2itnow0822, msaleme (3x), pshkv (3x), enigma-zeroclaw (2x)
    Ból ten sam co wyżej, ale w kontekście AutoGen. Wątek rozwinął się w konkretną dyskusję o attack surface:
    - Loop billing (mikropłatności w retry loop omijające cap)
    - Receipt replay across agent identities
    - Escalation budget exhaustion (approval fatigue)
    pshkv wysłał sogar conformance matrix jako executable fixtures — `payment-governance.v1.json`.
 
crewAI #4877 — "GuardrailProvider interface for pre-tool-call authorization"**
31 comments, 12 unique commenters
Pre-tool authorization zamiast post-hoc guardrails. 12 niezależnych osób, łącznie z pshkv i douglasborthwick (te same nicki co w innych wątkach).
    
openai/openai-agents-python #2775 — "Runtime governance guardrails"**
21 comments, 10 unique commenters
To samo co wyżej ale w OpenAI Agents SDK. pshkv, Jairooh, mrperfectness-sketch — ci sami gracze.
    
crewAI #4560 — "Cryptographic Identity for Crew Members"
 69 comments, 8 unique commenters
Kryptograficzna tożsamość agentów. 8 różnych osób, 69 wpisów — głęboka dyskusja o identity proofing.

Warstwa Czego szukają
Budget enforcement| per-task caps, session limits, daily rollups, fail-closed |
Audit trail | tamper-evident, hash-chained, human-readable receipts tied to agent identity |
Pre-tool authorization quote → reserve → commit lifecycle, budget check before LLM decides 
Agent identity cryptographic proof of who authorized what 
Compliance EU AI Act Art. 12/13/14, GDPR/PSD2, ISO 42001-ready 
Escrow/settlementpayment held until output verified 
 Firmy które się zgłaszają: agentwallet-sdk, AgentPassport, AgentMint, asqav, Aira, SteelSpine, Signet, WTRMRK, MAXIA — każda buduje inną część tej samej układanki. Żadna nie ma pełnego stacka.

 