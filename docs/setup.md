# Setup Guide

## Step 1: Elastic Cloud Serverless

1. Sign up at https://cloud.elastic.co (free trial)
2. Create a **Serverless Elasticsearch** project
   - Choose a Google Cloud region (e.g. `us-central1`)
3. Copy your **Cloud ID** and generate an **API key** with write access
4. Paste both into `.env`

## Step 2: Enable Agent Builder

1. In Kibana, go to **Search → Agent Builder**
2. Enable it for your project
3. Note the **MCP endpoint URL** (shown in the Tools UI)

## Step 3: Index Attack Data

```bash
# Install deps
pip install -r requirements.txt

# Download raw data (EVTX-ATTACK-SAMPLES + Splunk Attack Data)
python scripts/download_data.py

# Normalize EVTX to ECS JSON (coming Day 4)
python scripts/normalize_evtx.py

# Index into Elastic
python scripts/index_data.py
```

## Step 4: Create Index Mappings

Run once to set up both indexes:

```bash
python scripts/setup_indexes.py
```

## Step 5: Deploy ES|QL Tools

1. Open Elastic Agent Builder UI
2. Create a new tool for each query in `elastic/esql_tools/queries.yaml`
3. Use the ES|QL from the yaml as the tool body

## Step 6: Connect to Google Cloud Agent Builder

1. Create a new agent in [Google Cloud Agent Builder](https://cloud.google.com/agent-builder)
2. Add a tool source → **MCP**
3. Enter your Elastic MCP endpoint URL
4. Authenticate with your Elastic API key
5. Paste the system prompt from `agent/prompts/system_prompt.md`
6. Select Gemini model (recommend `gemini-2.0-flash` for speed)

## Step 7: Test

Trigger an investigation:

```
Investigate: Multiple failed logins detected on WORKSTATION-04 in the last 2 hours
```

The agent should call `failed_logins_by_host`, pivot to `attack_timeline`, and produce an IR report.
