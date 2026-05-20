"""
Local IR agent — runs investigations using Gemini REST API + Elastic directly.

Works on Python 3.8+, no Gemini SDK required. Uses the same system prompt
and tools as the production GCP agent.

Usage:
  python agent/local_agent.py
  python agent/local_agent.py --prompt "investigate failed logins on WORKSTATION-04"
  python agent/local_agent.py --demo   # runs the canned demo scenario
  python agent/local_agent.py --list-hosts   # show available hostnames in data

Requires in .env:
  GOOGLE_API_KEY=...   (get one free at aistudio.google.com)
  ELASTIC_CLOUD_ID=... + ELASTIC_API_KEY=...
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent.parent))
from agent.elastic_client import get_es

SYSTEM_PROMPT = (Path(__file__).parent / "prompts" / "system_prompt.md").read_text()
GEMINI_REST_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
DEFAULT_MODEL = "gemini-2.0-flash"


def _run_esql(es: Elasticsearch, query: str) -> List[Dict]:
    try:
        resp = es.esql.query(body={"query": query.strip()})
        cols = [c["name"] for c in resp.get("columns", [])]
        rows = resp.get("values", [])
        return [dict(zip(cols, row)) for row in rows]
    except Exception as e:
        return [{"error": str(e)}]


# ── Tool implementations ───────────────────────────────────────────────────────

def tool_failed_logins_by_host(es: Elasticsearch, time_window: str = "24h", threshold: int = 5) -> List[Dict]:
    return _run_esql(es, f"""
FROM ir-events
| WHERE @timestamp >= NOW() - {time_window}
| WHERE event.code == "4625" OR event.action == "logon-failed"
| STATS failure_count = COUNT(*) BY host.name, user.name
| WHERE failure_count >= {threshold}
| SORT failure_count DESC
""")


def tool_lateral_movement_detection(es: Elasticsearch, time_window: str = "24h") -> List[Dict]:
    return _run_esql(es, f"""
FROM ir-events
| WHERE @timestamp >= NOW() - {time_window}
| WHERE event.code IN ("4624", "7045", "5140", "4648") OR event.action == "explicit-credentials-logon"
| STATS host_count = COUNT_DISTINCT(host.name) BY user.name
| WHERE host_count > 1
| SORT host_count DESC
""")


def tool_credential_access_events(es: Elasticsearch, time_window: str = "24h") -> List[Dict]:
    return _run_esql(es, f"""
FROM ir-events
| WHERE @timestamp >= NOW() - {time_window}
| WHERE event.code IN ("4656", "4663")
    OR threat.technique.id IN ("T1003", "T1003.001")
| KEEP @timestamp, host.name, user.name, process.name, event.code, threat.technique.id
| SORT @timestamp DESC
| LIMIT 50
""")


def tool_attack_timeline(es: Elasticsearch, host_name: str = "*", time_window: str = "24h") -> List[Dict]:
    host_filter = f'| WHERE host.name == "{host_name}"' if host_name != "*" else ""
    return _run_esql(es, f"""
FROM ir-events
| WHERE @timestamp >= NOW() - {time_window}
{host_filter}
| KEEP @timestamp, host.name, user.name, event.code, event.action,
       event.category, process.name, threat.technique.id
| SORT @timestamp ASC
| LIMIT 200
""")


def tool_unique_hosts_by_technique(es: Elasticsearch, time_window: str = "30d") -> List[Dict]:
    return _run_esql(es, f"""
FROM ir-events
| WHERE @timestamp >= NOW() - {time_window}
| WHERE threat.technique.id IS NOT NULL
| STATS affected_hosts = COUNT_DISTINCT(host.name), event_count = COUNT(*)
  BY threat.technique.id, threat.technique.name
| SORT affected_hosts DESC
""")


def tool_suspicious_process_execution(es: Elasticsearch, time_window: str = "24h") -> List[Dict]:
    return _run_esql(es, f"""
FROM ir-events
| WHERE @timestamp >= NOW() - {time_window}
| WHERE event.category == "process" AND process.name IS NOT NULL
| KEEP @timestamp, host.name, user.name, process.name,
       process.command_line, process.parent.name
| SORT @timestamp DESC
| LIMIT 100
""")


def tool_search_memory(es: Elasticsearch, query: str,
                       session_id: Optional[str] = None, top_k: int = 5) -> List[Dict]:
    index = os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory")
    body: Dict = {
        "size": top_k,
        "query": {"match": {"content": query}},
        "_source": ["content", "memory_type", "@timestamp", "mitre_techniques", "affected_hosts"],
    }
    if session_id:
        body["query"] = {
            "bool": {
                "must": [{"match": {"content": query}}],
                "filter": [{"term": {"session_id": session_id}}],
            }
        }
    try:
        resp = es.search(index=index, body=body)
        return [{"score": h["_score"], **h["_source"]} for h in resp["hits"]["hits"]]
    except Exception:
        return []


def tool_write_memory(es: Elasticsearch, content: str, memory_type: str,
                      session_id: str, mitre_techniques: Optional[List] = None,
                      affected_hosts: Optional[List] = None, confidence: float = 0.9) -> Dict:
    index = os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory")
    doc: Dict = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "memory_type": memory_type,
        "content": content,
        "confidence": confidence,
    }
    if mitre_techniques:
        doc["mitre_techniques"] = mitre_techniques
    if affected_hosts:
        doc["affected_hosts"] = affected_hosts
    try:
        es.index(index=index, id=str(uuid.uuid4()), document=doc)
        return {"status": "written"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


TOOL_FNS = {
    "failed_logins_by_host": tool_failed_logins_by_host,
    "lateral_movement_detection": tool_lateral_movement_detection,
    "credential_access_events": tool_credential_access_events,
    "attack_timeline": tool_attack_timeline,
    "unique_hosts_by_technique": tool_unique_hosts_by_technique,
    "suspicious_process_execution": tool_suspicious_process_execution,
    "search_memory": tool_search_memory,
    "write_memory": tool_write_memory,
}

# Gemini function declarations (REST format)
TOOL_DECLARATIONS = {
    "functionDeclarations": [
        {
            "name": "failed_logins_by_host",
            "description": "Count failed login attempts grouped by host. Detects brute force.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "time_window": {"type": "STRING", "description": "e.g. 1h, 24h, 7d"},
                    "threshold": {"type": "INTEGER", "description": "Minimum failures to include"},
                },
            },
        },
        {
            "name": "lateral_movement_detection",
            "description": "Find lateral movement: logins across multiple hosts, remote service creation.",
            "parameters": {
                "type": "OBJECT",
                "properties": {"time_window": {"type": "STRING"}},
            },
        },
        {
            "name": "credential_access_events",
            "description": "Surface credential dumping events: LSASS access, SAM reads.",
            "parameters": {
                "type": "OBJECT",
                "properties": {"time_window": {"type": "STRING"}},
            },
        },
        {
            "name": "attack_timeline",
            "description": "Build chronological event timeline for a host. Use * for all hosts.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "host_name": {"type": "STRING", "description": "Hostname or * for all"},
                    "time_window": {"type": "STRING"},
                },
            },
        },
        {
            "name": "unique_hosts_by_technique",
            "description": "Count hosts affected by each MITRE ATT&CK technique. Shows blast radius.",
            "parameters": {
                "type": "OBJECT",
                "properties": {"time_window": {"type": "STRING"}},
            },
        },
        {
            "name": "suspicious_process_execution",
            "description": "Find LOLBin abuse and processes from unusual parents.",
            "parameters": {
                "type": "OBJECT",
                "properties": {"time_window": {"type": "STRING"}},
            },
        },
        {
            "name": "search_memory",
            "description": "Search prior IR findings from agent memory.",
            "parameters": {
                "type": "OBJECT",
                "required": ["query"],
                "properties": {
                    "query": {"type": "STRING"},
                    "session_id": {"type": "STRING"},
                    "top_k": {"type": "INTEGER"},
                },
            },
        },
        {
            "name": "write_memory",
            "description": "Persist a finding or summary to agent memory for future investigations.",
            "parameters": {
                "type": "OBJECT",
                "required": ["content", "memory_type", "session_id"],
                "properties": {
                    "content": {"type": "STRING"},
                    "memory_type": {"type": "STRING", "description": "finding|summary|ioc|hypothesis|timeline_entry"},
                    "session_id": {"type": "STRING"},
                    "confidence": {"type": "NUMBER"},
                },
            },
        },
    ]
}


# ── Gemini REST client ─────────────────────────────────────────────────────────

def _gemini_call(api_key: str, contents: List[Dict], model: str = DEFAULT_MODEL) -> Dict:
    url = GEMINI_REST_URL.format(model=model, key=api_key)
    payload = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "tools": [TOOL_DECLARATIONS],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 8192},
        "contents": contents,
    }
    resp = requests.post(url, json=payload, timeout=60)
    resp.raise_for_status()
    return resp.json()


def _extract_parts(response: Dict) -> List[Dict]:
    return response.get("candidates", [{}])[0].get("content", {}).get("parts", [])


# ── Agent loop ─────────────────────────────────────────────────────────────────

def run_investigation(prompt: str, session_id: str = "local-001",
                      model: str = DEFAULT_MODEL, verbose: bool = True) -> str:
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("ERROR: Set GOOGLE_API_KEY in .env — get a free key at aistudio.google.com")
        sys.exit(1)

    es = get_es()

    if verbose:
        print(f"\n{'='*60}")
        print("IR Agent — Local Investigation")
        print(f"{'='*60}")
        print(f"Prompt: {prompt}\n")

    # Conversation history in Gemini REST format
    contents: List[Dict] = [{"role": "user", "parts": [{"text": prompt}]}]
    max_turns = 12

    for _ in range(max_turns):
        raw = _gemini_call(api_key, contents, model=model)
        parts = _extract_parts(raw)

        # Collect any function calls in this turn
        fn_calls = [p["functionCall"] for p in parts if "functionCall" in p]
        text_parts = [p.get("text", "") for p in parts if "text" in p]

        if text_parts and not fn_calls:
            # Final answer
            final = "\n".join(t for t in text_parts if t)
            if verbose:
                print(final)
            return final

        if not fn_calls:
            # No text and no function calls — shouldn't happen, bail
            break

        # Append model turn to history
        contents.append({"role": "model", "parts": parts})

        # Execute each function call and build the response turn
        fn_response_parts = []
        for fc in fn_calls:
            fn_name = fc["name"]
            fn_args = fc.get("args", {})

            if verbose:
                print(f"[Tool] {fn_name}({json.dumps(fn_args, default=str)[:120]})")

            fn = TOOL_FNS.get(fn_name)
            result = fn(es, **fn_args) if fn else {"error": f"Unknown tool: {fn_name}"}

            fn_response_parts.append({
                "functionResponse": {
                    "name": fn_name,
                    "response": {"result": result},
                }
            })

        contents.append({"role": "user", "parts": fn_response_parts})

    return "Investigation complete (max turns reached)."


# ── Utility commands ───────────────────────────────────────────────────────────

def list_hosts() -> None:
    es = get_es()
    results = _run_esql(es, """
FROM ir-events
| STATS event_count = COUNT(*) BY host.name
| SORT event_count DESC
| LIMIT 20
""")
    print("\nHosts in ir-events index:")
    for r in results:
        print(f"  {r.get('host.name', '?'):40s}  {r.get('event_count', 0):>6} events")


# ── Demo scenario ──────────────────────────────────────────────────────────────

DEMO_PROMPT = (
    "Run a full threat hunt across all data. "
    "Start by checking memory for prior context, then: "
    "(1) find the top ATT&CK techniques with the most affected hosts, "
    "(2) look for any credential access or LSASS activity, "
    "(3) check for lateral movement, "
    "(4) build a timeline for the most suspicious host. "
    "Map everything to MITRE ATT&CK and produce a complete IR report. "
    "Session ID: demo-001"
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local IR Agent")
    parser.add_argument("--prompt", "-p", type=str, help="Investigation prompt")
    parser.add_argument("--session", "-s", type=str, default="local-001")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL)
    parser.add_argument("--demo", action="store_true", help="Run full demo scenario")
    parser.add_argument("--list-hosts", action="store_true", help="List hosts in the index")
    args = parser.parse_args()

    if args.list_hosts:
        list_hosts()
    elif args.demo:
        run_investigation(DEMO_PROMPT, session_id="demo-001", model=args.model)
    elif args.prompt:
        run_investigation(args.prompt, session_id=args.session, model=args.model)
    else:
        print("IR Agent — interactive mode (Ctrl+C to exit)\n")
        session = f"interactive-{uuid.uuid4().hex[:6]}"
        while True:
            try:
                prompt = input(">>> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if prompt.lower() in ("quit", "exit", "q"):
                break
            if prompt:
                run_investigation(prompt, session_id=session, model=args.model)


if __name__ == "__main__":
    main()
