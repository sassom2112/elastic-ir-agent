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
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent.parent))
from agent.audit_log import log_tool_call
from agent.elastic_client import get_es

SYSTEM_PROMPT = (Path(__file__).parent / "prompts" / "system_prompt.md").read_text()
GEMINI_REST_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
DEFAULT_MODEL = "gemini-2.5-flash"

# ── Input validation ───────────────────────────────────────────────────────────

_TIME_WINDOW_RE = re.compile(r"^\d+[smhdwy]$")
_HOST_NAME_RE = re.compile(r"^[\w\-\.\* ]+$")
_MEMORY_CONTENT_MAX = 10_000
_MEMORY_STRIP_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ALLOWED_WRITE_INDEXES = frozenset({"ir-agent-memory"})


def _validate_tool_args(fn_name: str, fn_args: Dict) -> Optional[str]:
    """Return an error string if args fail validation, else None. Mutates fn_args in place for sanitization."""
    if "time_window" in fn_args:
        val = str(fn_args["time_window"])
        if not _TIME_WINDOW_RE.match(val):
            return f"Invalid time_window {val!r} — must match \\d+[smhdwy] (e.g. 24h, 7d, 10y)"
    if "host_name" in fn_args:
        val = str(fn_args["host_name"])
        if not _HOST_NAME_RE.match(val) or len(val) > 253:
            return f"Invalid host_name {val!r} — only alphanumeric, hyphens, dots, underscores, * allowed"
    if "threshold" in fn_args:
        val = fn_args["threshold"]
        if not isinstance(val, int) or not (1 <= val <= 10_000):
            return f"Invalid threshold {val!r} — must be integer 1–10000"
    if "top_k" in fn_args:
        val = fn_args["top_k"]
        if not isinstance(val, int) or not (1 <= val <= 100):
            return f"Invalid top_k {val!r} — must be integer 1–100"
    if fn_name == "write_memory" and "content" in fn_args:
        cleaned = _MEMORY_STRIP_RE.sub("", fn_args["content"])
        fn_args["content"] = cleaned[:_MEMORY_CONTENT_MAX]
    return None


def _run_esql(es: Elasticsearch, query: str) -> List[Dict]:
    try:
        resp = es.esql.query(body={"query": query.strip()})
        cols = [c["name"] for c in resp.get("columns", [])]
        rows = resp.get("values", [])
        return [dict(zip(cols, row)) for row in rows]
    except Exception as e:
        return [{"error": str(e)}]


# ── Tool implementations ───────────────────────────────────────────────────────

def tool_failed_logins_by_host(es: Elasticsearch, time_window: str = "10y", threshold: int = 5) -> List[Dict]:
    return _run_esql(es, f"""
FROM ir-events
| WHERE @timestamp >= NOW() - {time_window}
| WHERE event.code == "4625" OR event.action == "logon-failed"
| STATS failure_count = COUNT(*) BY host.name, user.name
| WHERE failure_count >= {threshold}
| SORT failure_count DESC
""")


def tool_lateral_movement_detection(es: Elasticsearch, time_window: str = "10y") -> List[Dict]:
    return _run_esql(es, f"""
FROM ir-events
| WHERE @timestamp >= NOW() - {time_window}
| WHERE event.code IN ("4624", "7045", "5140", "4648") OR event.action == "explicit-credentials-logon"
| STATS host_count = COUNT_DISTINCT(host.name) BY user.name
| WHERE host_count > 1
| SORT host_count DESC
""")


def tool_credential_access_events(es: Elasticsearch, time_window: str = "10y") -> List[Dict]:
    return _run_esql(es, f"""
FROM ir-events
| WHERE @timestamp >= NOW() - {time_window}
| WHERE event.code IN ("4656", "4663")
    OR threat.technique.id IN ("T1003", "T1003.001")
| KEEP @timestamp, host.name, user.name, process.name, event.code, threat.technique.id
| SORT @timestamp DESC
| LIMIT 50
""")


def tool_attack_timeline(es: Elasticsearch, host_name: str = "*", time_window: str = "10y") -> List[Dict]:
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


def tool_suspicious_process_execution(es: Elasticsearch, time_window: str = "10y") -> List[Dict]:
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
                       session_id: str, top_k: int = 5) -> List[Dict]:
    # session_id is always required — cross-session queries are forbidden to
    # prevent IOC contamination between forensically distinct investigations.
    index = os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory")
    body: Dict = {
        "size": top_k,
        "query": {
            "bool": {
                "must": [{"match": {"content": query}}],
                "filter": [{"term": {"session_id": session_id}}],
            }
        },
        "_source": ["content", "memory_type", "@timestamp", "mitre_techniques", "affected_hosts"],
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
    if index not in _ALLOWED_WRITE_INDEXES:
        return {"status": "error", "error": f"Write target {index!r} is not in the approved index allowlist"}
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
            "description": "Search prior IR findings from agent memory. Scoped strictly to the current session — never searches across investigations.",
            "parameters": {
                "type": "OBJECT",
                "required": ["query", "session_id"],
                "properties": {
                    "query": {"type": "STRING"},
                    "session_id": {"type": "STRING", "description": "Must match the current investigation session ID"},
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

VERIFIER_SYSTEM_PROMPT = """\
You are a Forensic Auditor. A Triage Analyst has produced the IR report below.
Your job: independently verify each factual claim by running your own tool queries.
Never accept claims on faith — confirm them directly against the data.

For each significant claim (techniques used, affected hosts, credential access, lateral movement):
1. Run the relevant tool to check whether supporting evidence actually exists in the data
2. Label the claim: VERIFIED, REFUTED, or UNVERIFIABLE (explain why)

Output format:
## Verification Summary
Verified: N  |  Refuted: N  |  Unverifiable: N

## Claim-by-Claim Results
| Claim | Status | Evidence |
|-------|--------|---------|

You do not have write_memory access. Do not attempt to persist anything.\
"""

VERIFIER_TOOL_DECLARATIONS = {
    "functionDeclarations": [
        d for d in TOOL_DECLARATIONS["functionDeclarations"]
        if d["name"] != "write_memory"
    ]
}


# ── Gemini REST client ─────────────────────────────────────────────────────────

def _gemini_call(api_key: str, contents: List[Dict], model: str = DEFAULT_MODEL,
                 system_prompt: Optional[str] = None,
                 tool_declarations: Optional[Dict] = None) -> Dict:
    url = GEMINI_REST_URL.format(model=model, key=api_key)
    payload = {
        "system_instruction": {"parts": [{"text": system_prompt or SYSTEM_PROMPT}]},
        "tools": [tool_declarations or TOOL_DECLARATIONS],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 8192},
        "contents": contents,
    }
    for attempt in range(5):
        resp = requests.post(url, json=payload, timeout=120)
        if resp.status_code == 429:
            wait = 15 * (attempt + 1)
            print(f"  [rate limit] waiting {wait}s before retry {attempt + 1}/5 ...")
            time.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.json()
    resp.raise_for_status()
    return resp.json()


def _extract_parts(response: Dict) -> List[Dict]:
    return response.get("candidates", [{}])[0].get("content", {}).get("parts", [])


# ── Forensic Auditor ───────────────────────────────────────────────────────────

def run_verifier(report: str, session_id: str,
                 model: str = DEFAULT_MODEL, verbose: bool = True) -> str:
    """Second-pass verification: independent agent re-queries Elastic to fact-check each IR claim."""
    api_key = os.getenv("GOOGLE_API_KEY")
    es_read = get_es(write=False)

    if verbose:
        print(f"\n{'─'*60}")
        print("Forensic Auditor — Independent Verification Pass")
        print(f"{'─'*60}\n")

    contents: List[Dict] = [
        {"role": "user", "parts": [{"text": f"Verify this IR report:\n\n{report}"}]}
    ]

    for _ in range(8):
        raw = _gemini_call(api_key, contents, model=model,
                           system_prompt=VERIFIER_SYSTEM_PROMPT,
                           tool_declarations=VERIFIER_TOOL_DECLARATIONS)
        parts = _extract_parts(raw)
        fn_calls = [p["functionCall"] for p in parts if "functionCall" in p]
        text_parts = [p.get("text", "") for p in parts if "text" in p]

        if text_parts and not fn_calls:
            verification = "\n".join(t for t in text_parts if t)
            if verbose:
                print(verification)
            return verification

        if not fn_calls:
            break

        contents.append({"role": "model", "parts": parts})
        fn_response_parts = []
        for fc in fn_calls:
            fn_name = fc["name"]
            fn_args = fc.get("args", {})
            if verbose:
                print(f"[Auditor] {fn_name}({json.dumps(fn_args, default=str)[:100]})")

            validation_error = _validate_tool_args(fn_name, fn_args)
            if validation_error:
                result: Any = {"error": validation_error}
            else:
                fn = TOOL_FNS.get(fn_name)
                result = fn(es_read, **fn_args) if fn else {"error": f"Unknown tool: {fn_name}"}

            fn_response_parts.append({
                "functionResponse": {"name": fn_name, "response": {"result": result}}
            })

        contents.append({"role": "user", "parts": fn_response_parts})

    return "Verification complete (max turns reached)."


# ── Agent loop ─────────────────────────────────────────────────────────────────

def run_investigation(prompt: str, session_id: str = "local-001",
                      model: str = DEFAULT_MODEL, verbose: bool = True) -> str:
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("ERROR: Set GOOGLE_API_KEY in .env — get a free key at aistudio.google.com")
        sys.exit(1)

    es_read = get_es(write=False)
    es_write = get_es(write=True)

    if verbose:
        print(f"\n{'='*60}")
        print("Elastic IR Agent — Local Investigation")
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
            # Final answer — then run independent verification pass
            final = "\n".join(t for t in text_parts if t)
            if verbose:
                print(final)
            run_verifier(final, session_id=session_id, model=model, verbose=verbose)
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

            # Enforce session isolation — memory tools always use this investigation's
            # session_id regardless of what the LLM passed, preventing cross-case contamination.
            if fn_name in ("search_memory", "write_memory"):
                fn_args["session_id"] = session_id

            if verbose:
                print(f"[Tool] {fn_name}({json.dumps(fn_args, default=str)[:120]})")

            validation_error = _validate_tool_args(fn_name, fn_args)
            if validation_error:
                result = {"error": validation_error}
                log_tool_call(session_id, fn_name, fn_args, result,
                              blocked_reason=validation_error)
            else:
                t0 = time.monotonic()
                fn = TOOL_FNS.get(fn_name)
                es = es_write if fn_name == "write_memory" else es_read
                result = fn(es, **fn_args) if fn else {"error": f"Unknown tool: {fn_name}"}
                log_tool_call(session_id, fn_name, fn_args, result,
                              duration_ms=int((time.monotonic() - t0) * 1000))

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
    "Run a full threat hunt across all data using a time window of 10y (our log data spans 2017-2023). "
    "Start by checking memory for prior context, then: "
    "(1) find the top ATT&CK techniques with the most affected hosts using time_window=10y, "
    "(2) look for credential access and LSASS activity using time_window=10y, "
    "(3) check for lateral movement using time_window=10y, "
    "(4) build a timeline for the most suspicious host using time_window=10y. "
    "Map everything to MITRE ATT&CK and produce a complete IR report. "
    "Session ID: demo-001"
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Elastic IR Agent — local mode")
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
        print("Elastic IR Agent — interactive mode (Ctrl+C to exit)\n")
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
