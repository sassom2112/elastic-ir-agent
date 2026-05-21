# Elastic IR Agent

> **Hackathon submission — Elastic Track**
> Google Cloud × Elastic Agent Builder Hackathon 2026

An autonomous incident response agent that turns raw attack telemetry into a structured, evidence-backed IR report — without a human analyst in the loop.

Gemini 2.5 Flash reasons over 73,909 real Windows attack events indexed in Elastic, calls ES|QL detection tools via the Elastic MCP server, writes findings back into Elasticsearch memory, and runs an independent Forensic Auditor pass that challenges every MITRE ATT&CK claim with fresh evidence before the report is saved.

---

## What It Does

```
Alert / prompt
      │
      ▼
┌─────────────────────────────────────────────────┐
│              Triage Agent (Gemini)              │
│                                                 │
│  Elastic MCP tools (via Agent Builder):         │
│  · unique_hosts_by_technique  ← blast radius    │
│  · credential_access_events   ← LSASS / SAM    │
│  · suspicious_process_execution  ← LOLBins      │
│  · lateral_movement_detection                   │
│  · attack_timeline    ← per-host chain          │
│  · failed_logins_by_host                        │
│                                                 │
│  Elasticsearch memory (direct):                 │
│  · search_memory   ← prior context              │
│  · write_memory    ← persist findings           │
└─────────────────────────────────────────────────┘
      │
      │  IR Report (Attack Chain + MITRE + IOCs)
      ▼
┌─────────────────────────────────────────────────┐
│         Forensic Auditor (second Gemini pass)   │
│  — no shared context with Triage Agent          │
│  — re-queries Elastic independently             │
│  — labels each claim VERIFIED / REFUTED /       │
│    UNVERIFIABLE with raw evidence citations     │
└─────────────────────────────────────────────────┘
      │
      ▼
reports/ir_report_<session>_<timestamp>.md
reports/verification_<session>_<timestamp>.md
reports/audit_log.jsonl
```

**6 ES|QL detection tools run inside Elastic Agent Builder** and are exposed to both agents via the Elastic MCP server. `search_memory` and `write_memory` talk directly to Elasticsearch — no custom tool-serving infrastructure required.

---

## Demo Output (sample)

```markdown
## Incident Summary
- Severity: CRITICAL
- Status: ACTIVE
- Timeframe: 2019-07-18 → 2021-12-07

## Attack Chain
| Step | Time | Host | User | Technique | Evidence |
|------|------|------|------|-----------|---------|
| 6  | 2021-04-22T22:09:25Z | MSEDGEWIN10 | IEUser | T1003.001 LSASS Memory | PPLdump.exe -v lsass lsass.dmp |
| 8  | 2021-08-07T23:33:01Z | MSEDGEWIN10 | IEUser | T1566.001 Spearphishing | WINWORD.EXE opening stats.doc |
| 10 | 2021-08-07T23:33:08Z | MSEDGEWIN10 | IEUser | T1218.011 Rundll32 | rundll32.exe loading memViewData.jpg,PluginInit |
| 12 | 2021-12-07T17:33:01Z | MSEDGEWIN10 | IEUser | T1003.001 LSASS Memory | MalSeclogon.exe -p 636 -d 2 |

## MITRE ATT&CK Mapping
- Credential Access: T1003.001 — **Evidence**: 314 events, 6 hosts — PPLdump.exe, MalSeclogon.exe, samir.exe
- Initial Access:   T1566.001 — **Evidence**: WINWORD.EXE opening stats.doc on MSEDGEWIN10
- Defense Evasion:  T1218.011 — **Evidence**: rundll32.exe loading .jpg as DLL via mshta parent
```

Forensic Auditor verification: `Verified: 8 | Refuted: 8 | Unverifiable: 2` — every refuted claim cites the specific tool output that contradicted it.

---

## Architecture

| Layer | Technology |
|-------|-----------|
| Data | Elastic Cloud Serverless — `ir-events` (73,909 docs), `ir-agent-memory` |
| Tools | Elastic Agent Builder — 6 ES\|QL tools + memory read/write, exposed via MCP |
| Reasoning (cloud) | Google Cloud Agent Engine — Gemini 2.5 Flash, deployed resource `8923515974506774528` |
| Reasoning (local) | `agent/local_agent.py` — same tools, Gemini REST API, full agentic loop |
| Memory | Elasticsearch hybrid search — ELSER sparse vectors + BM25 via RRF |
| Verification | `agent/auditor.py` — independent second Gemini pass, read-only tools |
| Audit | `reports/audit_log.jsonl` — atomic JSONL append per tool call |

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/sassom2112/Elastic-ir-agent.git
cd Elastic-ir-agent
cp .env.example .env
# Fill in ELASTIC_URL, ELASTIC_API_KEY, GOOGLE_API_KEY
```

### 2. Install dependencies

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Index attack data

```bash
# Download 278 EVTX attack sample files
python scripts/download_data.py

# Normalize to ECS format
python scripts/normalize_evtx.py

# Create indexes and index 73,909 events
python scripts/setup_indexes.py
python scripts/index_data.py
```

### 4. Deploy ES|QL tools to Elastic Agent Builder

```bash
python scripts/deploy_tools.py
```

Or manually in Kibana → Search → Agent Builder → Tools — paste each query from `elastic/esql_tools/queries.yaml`.

### 5. Run a demo investigation

```bash
python agent/local_agent.py --demo
```

The agent runs a full investigation across 6 Elastic detection tools plus memory read/write, maps findings to MITRE ATT&CK, and saves the IR report and Forensic Auditor verification to `reports/`.

---

## Connect via Browser (Google Cloud Agent Builder)

For a fully browser-based demo without running any local code:

1. Open [Google Cloud Agent Builder](https://console.cloud.google.com/vertex-ai/agents)
2. Create a new agent → select **Gemini 2.5 Flash**
3. Add a tool → **MCP Server** → paste your Elastic MCP endpoint:
   ```
   https://<your-project>.kb.<region>.gcp.elastic.cloud/api/agent_builder/mcp
   ```
   Auth: `Authorization: ApiKey <your_api_key>`
4. Paste the contents of `agent/prompts/system_prompt.md` as the system instruction
5. In the playground, send:
   ```
   Run a full threat hunt across all indexed data (time_window=10y).
   Start with unique_hosts_by_technique, then credential_access_events,
   then attack_timeline for the most suspicious host.
   Map everything to MITRE ATT&CK with evidence.
   ```

All 6 ES|QL tools are immediately available. Gemini calls them via the Elastic MCP server and reasons over the results in the browser — no Python required.

---

## Deploy to GCP Agent Engine

```bash
# Requires Python 3.10+
python3.10 -m venv .venv-gcp && source .venv-gcp/bin/activate
pip install "google-cloud-aiplatform[agent_engines]" elasticsearch

gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID

python scripts/create_gcp_agent.py
```

The deployed agent runs the full agentic loop — 6 Elastic detection tools + memory, session-isolated, 12-turn reasoning — on Google's managed infrastructure using Application Default Credentials. No API key stored locally.

---

## Project Structure

```
Elastic-ir-agent/
├── agent/
│   ├── local_agent.py        # Full agentic loop — 8 tools, 12 turns, Forensic Auditor
│   ├── auditor.py            # Independent verification pass (read-only tools)
│   ├── gemini_client.py      # Shared Gemini REST client with retry + rate limiting
│   ├── elastic_client.py     # Elasticsearch client factory (split read/write keys)
│   ├── audit_log.py          # Atomic chain-of-custody JSONL logger
│   ├── prompts/
│   │   └── system_prompt.md  # System prompt shared by local agent and GCP deployment
│   └── tools/
│       └── memory_tools.py   # Hybrid ELSER+BM25 search_memory, write_memory
├── elastic/
│   ├── esql_tools/
│   │   └── queries.yaml      # 6 ES|QL detection tools (deploy to Agent Builder)
│   ├── mappings/             # ir-events and ir-agent-memory index schemas
│   └── ingest/               # MITRE enrichment ingest pipeline
├── scripts/
│   ├── download_data.py      # Fetch EVTX-ATTACK-SAMPLES dataset
│   ├── normalize_evtx.py     # Parse EVTX → ECS-formatted JSON
│   ├── index_data.py         # Bulk-index into ir-events
│   ├── setup_indexes.py      # Create indexes with mappings + pipelines
│   ├── deploy_tools.py       # Push ES|QL tools to Elastic Agent Builder
│   ├── create_gcp_agent.py   # Deploy ElasticIRAgent to GCP Agent Engine
│   └── run_investigation.py  # Query a deployed GCP agent by resource ID
├── reports/                  # Saved IR reports, verification outputs, audit log
├── workflows/                # Elastic Workflow definitions
└── .env.example              # All required environment variables with comments
```

---

## Security Model

The security boundary is structural — bad actions are architecturally impossible, not just instructed away.

| Control | Implementation |
|---------|---------------|
| **Session isolation** | `search_memory` is hard-scoped to the current `session_id` in the dispatch layer — the model cannot query across investigations. IOC contamination between cases is physically blocked at the Elasticsearch filter, not by prompt instruction. |
| **Input validation** | Every tool argument is validated before any Elasticsearch call — `time_window` against `\d+[smhdwy]`, `host_name` against an alphanumeric allowlist, integer range checks on `threshold` and `top_k`. |
| **Write index allowlist** | `write_memory` checks the target index against a hardcoded allowlist (`ir-agent-memory`). Misconfiguring `ELASTIC_INDEX_MEMORY=ir-events` is blocked at write time. |
| **Memory content sanitization** | `write_memory` strips control characters and caps input at 10,000 chars before touching Elasticsearch — blocks indirect prompt injection via poisoned retrieval. |
| **Split read/write API keys** | `ELASTIC_API_KEY_READ` (ES\|QL queries) and `ELASTIC_API_KEY_WRITE` (memory index only) — separate scoped keys. |
| **Chain-of-custody audit log** | Every tool call is atomically appended to `reports/audit_log.jsonl` via `os.open`/`os.write` (not buffered IO). Blocked calls log the rejection reason; allowed calls log duration. |
| **Forensic Auditor** | A second independent Gemini pass re-queries Elastic with read-only tools and labels every MITRE claim VERIFIED / REFUTED / UNVERIFIABLE with specific event evidence — no access to the Triage Agent's tool history. |

---

## Dataset

[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden — 278 EVTX files covering real Windows attack techniques from 2017–2023. Events are normalized to [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) at ingest time with MITRE ATT&CK technique IDs enriched from behavioral signals (event codes, process names, command-line patterns) — not pre-baked metadata.

---

## License

MIT
