# Google Cloud Agent Builder Setup

## Prerequisites

- Elastic Cloud Serverless project running with data indexed (`python scripts/test_agent.py` passes)
- Google account (for AI Studio free key) or GCP project (for Agent Builder)

---

## Option A — Local agent with AI Studio key (start here, no GCP needed)

Get a free Gemini API key at **aistudio.google.com → Get API key**.

```bash
# Add to .env
GOOGLE_API_KEY=your_key_here

# Run the demo investigation
source .venv/bin/activate
python agent/local_agent.py --demo

# Or investigate interactively
python agent/local_agent.py --list-hosts       # see what hosts are in the data
python agent/local_agent.py --prompt "investigate LSASS access on any host in the last 30 days"
```

This uses Gemini 2.0 Flash via the REST API. Same model, same tools, no GCP billing.

---

## Option B — Deploy to Google Cloud Agent Builder (for the demo video)

### 1. Create a GCP project

```bash
gcloud projects create ir-agent-hackathon
gcloud config set project ir-agent-hackathon
gcloud services enable aiplatform.googleapis.com
```

### 2. Add to .env

```
GOOGLE_PROJECT_ID=ir-agent-hackathon
GOOGLE_REGION=us-central1
```

### 3. Create the agent via UI (recommended — no Python 3.10+ required)

1. Go to **console.cloud.google.com → Agent Builder → Create Agent**
2. Select **Gemini Agent**
3. Set display name: `IR Agent — Elastic Incident Responder`
4. Paste system prompt from `agent/prompts/system_prompt.md`
5. Under **Tools → Add tool source → MCP**:
   - Server URL: value of `ELASTIC_MCP_ENDPOINT` from your .env
   - Auth: API Key header `Authorization`, value `ApiKey <your elastic api key>`
6. Verify all 8 tools appear (failed_logins_by_host, attack_timeline, etc.)
7. Select model: **gemini-2.0-flash-001**
8. Save → **Test in playground**

### 4. Wire up Elastic Agent Builder MCP

In your Elastic project:

1. Kibana → **Search → Agent Builder**
2. Enable Agent Builder for your project
3. Create tools from `elastic/esql_tools/queries.yaml` (one per query)
4. Copy the **MCP endpoint URL** from the Tools UI
5. Paste it as `ELASTIC_MCP_ENDPOINT` in .env

### 5. Test the production agent

```bash
# After saving GCP_AGENT_ID in .env
python scripts/run_investigation.py \
  --prompt "What are the top MITRE ATT&CK techniques in the last 30 days?"
```

---

## Connecting the workflows

To run the full `investigate_alert` workflow from GCP:

1. In Agent Builder, go to **Workflows**
2. Import `workflows/investigate_alert.json`
3. Map tool references to your deployed Elastic tools
4. Trigger via the playground or the Agent Builder API

---

## Demo script (for the 3-minute video)

```
1. Show Kibana → Agent Builder → Tools (your ES|QL tools listed)
2. Open GCP Agent Builder playground
3. Type: "Run a full threat hunt. What attacked us in the last 30 days?"
4. Agent calls: search_memory → unique_hosts_by_technique → credential_access_events
              → attack_timeline → write_memory
5. Agent produces IR report with ATT&CK mapping
6. Show Kibana → ir-agent-memory index with the written findings
```
