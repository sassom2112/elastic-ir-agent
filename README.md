# IR Agent — Elastic + Gemini Incident Response Agent

> Hackathon submission: Elastic Agent Builder × Google Cloud Agent Builder

An autonomous incident response agent that ingests real attack telemetry, reasons over it with Gemini, and surfaces actionable findings — built on Elastic's MCP tools for hybrid search, ES|QL analytics, and write-back memory.

## What It Does

1. **Ingest** — Real Windows attack logs (EVTX-ATTACK-SAMPLES + Splunk Attack Data) indexed into Elastic Cloud Serverless
2. **Search** — Elastic Agent Builder exposes hybrid semantic + keyword + vector search as MCP tools
3. **Reason** — Google Cloud Agent Builder (Gemini) calls those tools to investigate alerts, correlate events, and map to MITRE ATT&CK
4. **Remember** — Findings are written back into Elasticsearch so the agent builds context over time
5. **Report** — Structured IR report: timeline, affected hosts, technique IDs, recommended containment

## Stack

| Layer | Technology |
|-------|-----------|
| Data storage | Elastic Cloud Serverless (Elasticsearch) |
| Search + MCP | Elastic Agent Builder |
| Agent reasoning | Google Cloud Agent Builder + Gemini |
| Attack data | EVTX-ATTACK-SAMPLES, Splunk Attack Data |
| Log shipper | Winlogbeat → Elasticsearch |

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
│   ├── tools/        # Tool definitions for Elastic Agent Builder
│   ├── memory/       # Memory index schema + write-back queries
│   └── prompts/      # System prompts for Gemini agent
├── workflows/        # Elastic Workflow definitions (JSON)
├── scripts/          # Data download, normalization, indexing scripts
└── docs/             # Architecture diagrams, demo script
```

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

## Demo Scenario

**Attack chain:** Brute force → credential dumping → lateral movement  
**Dataset:** EVTX-ATTACK-SAMPLES technique T1110 → T1003 → T1021  
**Agent flow:** Alert triggers → agent searches logs → correlates timeline → maps ATT&CK → writes IR report to Elastic

## License

MIT
