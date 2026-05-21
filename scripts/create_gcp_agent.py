"""
Create or update the Elastic IR Agent in Google Cloud Agent Builder (Agent Engine).

Agent Engine is the GA managed runtime for code-first agents under the
Vertex AI Agent Builder product suite.

Prerequisites:
  pip install "google-cloud-aiplatform[agent_engines]" elasticsearch
  gcloud auth application-default login
  gcloud config set project YOUR_PROJECT_ID

Run:
  python scripts/create_gcp_agent.py
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

load_dotenv()

try:
    import vertexai
    from vertexai import agent_engines
except ImportError:
    print("ERROR: Install Vertex AI SDK with agent_engines extras:")
    print("  pip install 'google-cloud-aiplatform[agent_engines]'")
    sys.exit(1)

PROJECT_ID  = os.getenv("GOOGLE_PROJECT_ID")
REGION      = os.getenv("GOOGLE_REGION", "us-central1")
ELASTIC_URL = os.getenv("ELASTIC_URL")
ELASTIC_KEY = os.getenv("ELASTIC_API_KEY")

SYSTEM_PROMPT_PATH = Path(__file__).parent.parent / "agent" / "prompts" / "system_prompt.md"


def validate_env() -> None:
    missing = [k for k in ["GOOGLE_PROJECT_ID", "ELASTIC_URL", "ELASTIC_API_KEY"] if not os.getenv(k)]
    if missing:
        print(f"ERROR: Missing env vars: {', '.join(missing)}")
        sys.exit(1)


def get_system_prompt() -> str:
    with open(SYSTEM_PROMPT_PATH) as f:
        return f.read()


# ── Agent class (serialised into Agent Engine) ─────────────────────────────────

class ElasticIRAgent:
    """
    Agent Engine-compatible IR agent.

    Agent Engine unpickles this class inside the cloud runtime, calls set_up()
    once to initialise the Vertex AI model and Elasticsearch client, then
    routes user queries to query(). The full agentic tool-call loop runs here,
    identical in logic to local_agent.py but using the Vertex AI SDK for
    Gemini (no separate API key required — uses Application Default Credentials).

    NOTE: elastic_api_key is stored in the Agent Engine pickle in GCS.
    For production, move it to Secret Manager and fetch it in set_up().
    """

    def __init__(
        self,
        system_prompt: str,
        elastic_url: str,
        elastic_api_key: str,
        elastic_index_events: str = "ir-events",
        elastic_index_memory: str = "ir-agent-memory",
    ) -> None:
        self._system_prompt      = system_prompt
        self._elastic_url        = elastic_url
        self._elastic_api_key    = elastic_api_key
        self._index_events       = elastic_index_events
        self._index_memory       = elastic_index_memory
        self._model              = None
        self._es                 = None

    # ── Initialisation (called once in cloud runtime) ──────────────────────────

    def set_up(self) -> None:
        from elasticsearch import Elasticsearch
        from vertexai.generative_models import FunctionDeclaration, GenerativeModel, Tool

        self._es = Elasticsearch(self._elastic_url, api_key=self._elastic_api_key)

        declarations = [
            FunctionDeclaration(
                name="failed_logins_by_host",
                description="Count failed login attempts grouped by host. Detects brute force and credential stuffing.",
                parameters={
                    "type": "object",
                    "properties": {
                        "time_window": {"type": "string", "description": "Look-back period, e.g. 10y, 7d, 24h"},
                        "threshold":   {"type": "integer", "description": "Minimum failure count to include"},
                    },
                },
            ),
            FunctionDeclaration(
                name="lateral_movement_detection",
                description="Find users logging into multiple hosts, remote service creation, SMB access.",
                parameters={
                    "type": "object",
                    "properties": {
                        "time_window": {"type": "string"},
                    },
                },
            ),
            FunctionDeclaration(
                name="credential_access_events",
                description="Surface LSASS access, SAM reads, and known credential dumping tool signatures.",
                parameters={
                    "type": "object",
                    "properties": {
                        "time_window": {"type": "string"},
                    },
                },
            ),
            FunctionDeclaration(
                name="attack_timeline",
                description="Build chronological event timeline for a host. Use * for all hosts.",
                parameters={
                    "type": "object",
                    "properties": {
                        "host_name":   {"type": "string", "description": "Hostname to investigate, or * for all"},
                        "time_window": {"type": "string"},
                    },
                },
            ),
            FunctionDeclaration(
                name="unique_hosts_by_technique",
                description="Count hosts affected by each MITRE ATT&CK technique. Shows blast radius.",
                parameters={
                    "type": "object",
                    "properties": {
                        "time_window": {"type": "string"},
                    },
                },
            ),
            FunctionDeclaration(
                name="suspicious_process_execution",
                description="Find LOLBin abuse, encoded PowerShell, and processes from unusual parents.",
                parameters={
                    "type": "object",
                    "properties": {
                        "time_window": {"type": "string"},
                    },
                },
            ),
            FunctionDeclaration(
                name="search_memory",
                description="Retrieve prior IR findings from agent memory. Always scoped to current session.",
                parameters={
                    "type": "object",
                    "required": ["query", "session_id"],
                    "properties": {
                        "query":      {"type": "string"},
                        "session_id": {"type": "string"},
                        "top_k":      {"type": "integer"},
                    },
                },
            ),
            FunctionDeclaration(
                name="write_memory",
                description="Persist a finding, IOC, or summary to agent memory for future investigations.",
                parameters={
                    "type": "object",
                    "required": ["content", "memory_type", "session_id"],
                    "properties": {
                        "content":     {"type": "string"},
                        "memory_type": {"type": "string", "description": "finding|summary|ioc|hypothesis|timeline_entry"},
                        "session_id":  {"type": "string"},
                        "confidence":  {"type": "number"},
                    },
                },
            ),
        ]

        self._model = GenerativeModel(
            "gemini-2.5-flash",
            system_instruction=self._system_prompt,
            tools=[Tool(function_declarations=declarations)],
            generation_config={"temperature": 0.2, "max_output_tokens": 8192},
        )

    # ── ES|QL helpers ──────────────────────────────────────────────────────────

    def _esql(self, query: str) -> List[Dict]:
        try:
            resp = self._es.esql.query(body={"query": query.strip()})
            cols = [c["name"] for c in resp.get("columns", [])]
            return [dict(zip(cols, row)) for row in resp.get("values", [])]
        except Exception as e:
            return [{"error": str(e)}]

    # ── Tool dispatch ──────────────────────────────────────────────────────────

    def _execute_tool(self, fn_name: str, fn_args: Dict, session_id: str) -> Any:
        tw = fn_args.get("time_window", "10y")

        if fn_name == "failed_logins_by_host":
            threshold = fn_args.get("threshold", 5)
            return self._esql(f"""
FROM {self._index_events}
| WHERE @timestamp >= NOW() - {tw}
| WHERE event.code == "4625" OR event.action == "logon-failed"
| STATS failure_count = COUNT(*) BY host.name, user.name
| WHERE failure_count >= {threshold}
| SORT failure_count DESC
""")

        if fn_name == "lateral_movement_detection":
            return self._esql(f"""
FROM {self._index_events}
| WHERE @timestamp >= NOW() - {tw}
| WHERE event.code IN ("4624", "7045", "5140", "4648") OR event.action == "explicit-credentials-logon"
| STATS host_count = COUNT_DISTINCT(host.name) BY user.name
| WHERE host_count > 1
| SORT host_count DESC
""")

        if fn_name == "credential_access_events":
            return self._esql(f"""
FROM {self._index_events}
| WHERE @timestamp >= NOW() - {tw}
| WHERE event.code IN ("4656", "4663")
    OR threat.technique.id IN ("T1003", "T1003.001")
| KEEP @timestamp, host.name, user.name, process.name, event.code, threat.technique.id
| SORT @timestamp DESC
| LIMIT 50
""")

        if fn_name == "attack_timeline":
            host = fn_args.get("host_name", "*")
            host_filter = f'| WHERE host.name == "{host}"' if host != "*" else ""
            return self._esql(f"""
FROM {self._index_events}
| WHERE @timestamp >= NOW() - {tw}
{host_filter}
| KEEP @timestamp, host.name, user.name, event.code, event.action,
       event.category, process.name, threat.technique.id
| SORT @timestamp ASC
| LIMIT 200
""")

        if fn_name == "unique_hosts_by_technique":
            return self._esql(f"""
FROM {self._index_events}
| WHERE @timestamp >= NOW() - {tw}
| WHERE threat.technique.id IS NOT NULL
| STATS affected_hosts = COUNT_DISTINCT(host.name), event_count = COUNT(*)
  BY threat.technique.id, threat.technique.name
| SORT affected_hosts DESC
""")

        if fn_name == "suspicious_process_execution":
            return self._esql(f"""
FROM {self._index_events}
| WHERE @timestamp >= NOW() - {tw}
| WHERE event.category == "process" AND process.name IS NOT NULL
| KEEP @timestamp, host.name, user.name, process.name,
       process.command_line, process.parent.name
| SORT @timestamp DESC
| LIMIT 100
""")

        if fn_name == "search_memory":
            try:
                resp = self._es.search(
                    index=self._index_memory,
                    body={
                        "size": fn_args.get("top_k", 5),
                        "query": {
                            "bool": {
                                "must": [{"match": {"content": fn_args["query"]}}],
                                "filter": [{"term": {"session_id": session_id}}],
                            }
                        },
                        "_source": ["content", "memory_type", "@timestamp"],
                    },
                )
                return [{"score": h["_score"], **h["_source"]} for h in resp["hits"]["hits"]]
            except Exception as e:
                return [{"error": str(e)}]

        if fn_name == "write_memory":
            import uuid
            from datetime import datetime, timezone
            try:
                self._es.index(
                    index=self._index_memory,
                    id=str(uuid.uuid4()),
                    document={
                        "@timestamp":  datetime.now(timezone.utc).isoformat(),
                        "session_id":  session_id,
                        "memory_type": fn_args.get("memory_type", "finding"),
                        "content":     fn_args.get("content", ""),
                        "confidence":  fn_args.get("confidence", 0.9),
                    },
                )
                return {"status": "written"}
            except Exception as e:
                return {"status": "error", "error": str(e)}

        return {"error": f"Unknown tool: {fn_name}"}

    # ── Public query entry point ───────────────────────────────────────────────

    def query(self, *, input: str, session_id: str = "gcp-001") -> str:
        """Run a full IR investigation and return the structured report."""
        if self._model is None:
            self.set_up()

        from vertexai.generative_models import Content, Part

        contents = [Content(role="user", parts=[Part.from_text(input)])]
        max_turns = 12

        for _ in range(max_turns):
            response = self._model.generate_content(contents)
            candidate = response.candidates[0]

            fn_calls  = [p for p in candidate.content.parts if p.function_call.name]
            text_parts = [p.text for p in candidate.content.parts
                          if hasattr(p, "text") and p.text]

            if text_parts and not fn_calls:
                return "\n".join(text_parts)

            if not fn_calls:
                break

            contents.append(candidate.content)

            fn_responses = []
            for part in fn_calls:
                fn_name = part.function_call.name
                fn_args = dict(part.function_call.args)
                # Session isolation — memory tools always use this session's ID
                if fn_name in ("search_memory", "write_memory"):
                    fn_args["session_id"] = session_id
                result = self._execute_tool(fn_name, fn_args, session_id)
                fn_responses.append(
                    Part.from_function_response(name=fn_name, response={"result": result})
                )

            contents.append(Content(role="user", parts=fn_responses))

        return "Investigation complete (max turns reached)."


# ── Deploy ─────────────────────────────────────────────────────────────────────

def create_agent() -> None:
    validate_env()
    vertexai.init(
        project=PROJECT_ID,
        location=REGION,
        staging_bucket=f"gs://{PROJECT_ID}-vertex-staging",
    )

    system_prompt = get_system_prompt()
    index_events = os.getenv("ELASTIC_INDEX_EVENTS", "ir-events")
    index_memory = os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory")

    print(f"Deploying Elastic IR Agent to Agent Engine — {PROJECT_ID} / {REGION} ...")

    agent = agent_engines.create(
        ElasticIRAgent(
            system_prompt=system_prompt,
            elastic_url=ELASTIC_URL,
            elastic_api_key=ELASTIC_KEY,
            elastic_index_events=index_events,
            elastic_index_memory=index_memory,
        ),
        requirements=[
            "google-cloud-aiplatform[agent_engines]",
            "elasticsearch>=8.0.0",
        ],
        display_name="Elastic IR Agent — Incident Responder",
        description=(
            "Autonomous IR agent. Investigates security alerts using Elastic ES|QL tools, "
            "maps findings to MITRE ATT&CK, and produces structured IR reports."
        ),
    )

    print(f"\nAgent deployed successfully!")
    print(f"Resource name: {agent.resource_name}")
    print(f"\nAdd to .env:")
    print(f"  GCP_AGENT_ID={agent.resource_name.split('/')[-1]}")
    print(f"\nTest it:")
    print(f"  python scripts/run_investigation.py --agent-id {agent.resource_name.split('/')[-1]}")


if __name__ == "__main__":
    create_agent()
