# IR Agent — Elastic + Gemini Incident Response Agent

> Hackathon submission: Elastic Agent Builder × Google Cloud Agent Builder

An autonomous incident response agent that ingests real attack telemetry, reasons over it with
Gemini, and surfaces actionable findings — built on Elastic's MCP tools for hybrid search,
ES|QL analytics, and write-back memory.

## What It Does

1. **Ingest** — Real Windows attack logs (278 EVTX-ATTACK-SAMPLES, 36,951 events) indexed into Elastic Cloud Serverless
2. **Search** — Elastic Agent Builder exposes hybrid semantic + keyword + vector search as MCP tools
3. **Reason** — Google Cloud Agent Builder (Gemini) calls those tools to investigate alerts, correlate events, and map to MITRE ATT&CK
4. **Remember** — Findings are written back into Elasticsearch so the agent builds context over time across sessions
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

---

## Three-Tool Platform

IR Agent is one of three independent tools covering the full evidence stack of a Windows
intrusion. Each runs standalone; together they provide convergent detection backed by the
same attack corpus.

| Tool | Data layer | AI model | Unique capability |
|------|-----------|----------|-------------------|
| **[ADVERSA](https://github.com/sassom2112/adversa)** | Disk image (offline) | Claude (Anthropic) | Adversarial training, physical verification, false-positive elimination |
| **[Splunk Agentic IR](https://github.com/sassom2112/splunk-agentic-ir)** | Splunk / SPL | Claude (Anthropic) | Alert-triggered workflow, playbook recommendations |
| **IR Agent** | Elasticsearch / ES\|QL | Gemini (Google) | Cross-session memory, hybrid semantic + keyword search |

### IOC Exchange

The shared IOC bridge (in [splunk-agentic-ir](https://github.com/sassom2112/splunk-agentic-ir/blob/main/agent/ioc_bridge.py))
translates findings between all three tools:

```bash
# ADVERSA confirmed IOCs → ES|QL hunt in Elastic
python3 -m agent.ioc_bridge adversa-to-esql /path/to/adversa-iocs.json \
    --index ir-events

# Elastic memory records → ADVERSA IOC format (for disk investigation)
python3 -m agent.ioc_bridge elastic-to-adversa /path/to/memory.jsonl

# Merge ADVERSA disk findings + Elastic memory → unified IOC dict
python3 -m agent.ioc_bridge merge adversa-iocs.json memory.jsonl --source elastic
```

---

## License

MIT
