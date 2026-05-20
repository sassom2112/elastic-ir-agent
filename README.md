# IR Agent — Elastic + Gemini Incident Response Agent

> Hackathon submission: Elastic Agent Builder × Google Cloud Agent Builder

An autonomous incident response agent that ingests real attack telemetry, reasons over it with
Gemini, and surfaces actionable findings — built on Elastic's MCP tools for hybrid search,
ES|QL analytics, and write-back memory.

## What It Does

1. **Ingest** — Real Windows attack logs (278 EVTX-ATTACK-SAMPLES, 36,951 events) indexed into Elastic Cloud Serverless
2. **Search** — Elastic Agent Builder exposes hybrid semantic + keyword + vector search as MCP tools
3. **Reason** — Google Cloud Agent Builder (Gemini) calls those tools to investigate alerts, correlate events, and map to MITRE ATT&CK
4. **Remember** — Findings are written back into Elasticsearch and scoped to the investigation session, so the agent builds context within a case without contaminating other investigations
5. **Report** — Structured IR report: timeline, affected hosts, technique IDs, recommended containment

## Stack

| Layer | Technology |
|-------|-----------|
| Data storage | Elastic Cloud Serverless (Elasticsearch) |
| Search + MCP | Elastic Agent Builder |
| Agent reasoning | Google Cloud Agent Builder + Gemini |
| Attack data | EVTX-ATTACK-SAMPLES (278 files, 36,951 events) |
| Log shipper | Winlogbeat → Elasticsearch |

## Demo Scenario

**Attack chain:** Brute force → credential dumping → lateral movement
**Dataset:** EVTX-ATTACK-SAMPLES technique T1110 → T1003 → T1021
**Agent flow:** Alert triggers → agent searches logs → correlates timeline → maps ATT&CK → writes IR report to Elastic

## Quick Start

```bash
# 1. Set up environment
cp .env.example .env
# Fill in ELASTIC_CLOUD_ID, ELASTIC_API_KEY, GOOGLE_PROJECT_ID

# 2. Download attack data
python scripts/download_data.py

# 3. Index into Elastic
python scripts/index_data.py

# 4. Deploy ES|QL tools to Elastic Agent Builder
python scripts/deploy_tools.py

# 5. Connect MCP endpoint to Google Cloud Agent Builder
# See docs/setup.md
```

## Project Structure

```
ir-agent/
├── data/
│   ├── raw/          # Downloaded EVTX and JSON attack samples
│   ├── processed/    # Normalized ECS-formatted events
│   └── indexes/      # Elasticsearch index configs
├── elastic/
│   ├── mappings/     # Index mappings (ECS schema)
│   ├── ingest/       # Ingest pipeline configs
│   └── esql_tools/   # ES|QL queries wrapped as agent tools
├── agent/
│   ├── local_agent.py # Gemini REST client + 8 investigation tools
│   ├── elastic_client.py
│   ├── tools/        # Tool definitions for Elastic Agent Builder
│   ├── memory/       # Memory index schema + write-back queries
│   └── prompts/      # System prompts for Gemini agent
├── workflows/        # Elastic Workflow definitions (JSON)
├── scripts/          # Data download, normalization, indexing scripts
└── docs/             # Architecture diagrams, demo script
```

## Security Model

The security boundary is structural, not prompt-dependent — bad actions are made architecturally impossible rather than instructed away.

### Forensic Isolation

Agent memory introduces a contamination risk that doesn't exist in traditional tooling: without hard session isolation, IOCs from one investigation bleed into the next, and the model reasons across them — attributing infrastructure to a threat actor based on a prior case, not the current evidence.

IR Agent closes this at the architecture layer. The dispatch enforces the current `session_id` on every memory call regardless of what the model passes, and `search_memory` has no cross-session fallback — the Elasticsearch filter is always applied. A finding from Case A is physically unreachable during Case B.

Each investigation is forensically isolated — the agent cannot remember what it saw in a previous case, by design.

| Control | Implementation |
|---------|---------------|
| **Input validation** | Every tool argument is validated before any Elasticsearch call — `time_window` against `\d+[smhdwy]`, `host_name` against an alphanumeric allowlist, integer range checks on `threshold` and `top_k` |
| **Memory content sanitization** | `write_memory` input strips control characters and is hard-capped at 10,000 chars before touching Elasticsearch, blocking indirect prompt injection via poisoned retrieval |
| **Write index allowlist** | `write_memory` resolves the target index and checks it against a hardcoded allowlist (`ir-agent-memory`). Misconfiguring `ELASTIC_INDEX_MEMORY=ir-events` is blocked at write time |
| **Split read/write API keys** | `ELASTIC_API_KEY_READ` (ES\|QL queries) and `ELASTIC_API_KEY_WRITE` (memory index only) — separate scoped keys, falling back to a single key for local dev |
| **Chain-of-custody audit log** | Every tool call — allowed or blocked — is atomically appended to `reports/audit_log.jsonl` using `os.open`/`os.write` (not buffered IO). Blocked calls log the rejection reason; successful calls log duration |
| **Forensic Auditor** | After each investigation, a second independent Gemini pass receives only the finished IR report — no access to the Triage Agent's tool history or `write_memory` — and re-queries Elastic to label each claim VERIFIED / REFUTED / UNVERIFIABLE |
| **Session isolation** | `search_memory` is hard-scoped to the current `session_id` — the LLM cannot query across investigations. The dispatch layer enforces this regardless of what the model passes, preventing IOC contamination and false attribution between forensically distinct cases |

## License

MIT
