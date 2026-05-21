"""
Forensic Auditor — independent second-pass verification of IR findings.

Receives only the finished IR report from the Triage Agent (no shared tool
history, no write_memory access) and re-queries Elastic to label each claim
VERIFIED / REFUTED / UNVERIFIABLE.

Architectural boundary: this module has no import dependency on local_agent.
It shares only the Gemini client and Elastic client utilities.
"""

import json
import os
from typing import Dict, List, Optional

from agent.elastic_client import get_es
from agent.gemini_client import DEFAULT_MODEL, extract_parts, gemini_call

VERIFIER_SYSTEM_PROMPT = """\
You are a Forensic Auditor. A Triage Analyst has produced the IR report below.
Your job: independently verify each factual claim by running your own tool queries.
Never accept claims on faith — confirm them directly against the data.

## Time Window Rule — Read This First
Before running any tool, scan the report for the earliest timestamp mentioned.
Calculate how many years ago that was from today, then add 1 year buffer.
Use that as your time_window for all queries.
Example: if the earliest event is from 2019 and today is 2026, use time_window=8y.
Never default to 1d, 7d, or 30d — this dataset contains historical attack data.

## Verification Process
For each significant claim (techniques used, affected hosts, credential access, lateral movement):
1. Run the relevant tool with the correct time_window to check whether supporting evidence exists
2. Label the claim: VERIFIED, REFUTED, or UNVERIFIABLE (explain why)

Output format:
## Verification Summary
Verified: N  |  Refuted: N  |  Unverifiable: N

## Claim-by-Claim Results
| Claim | Status | Evidence |
|-------|--------|---------|

You do not have write_memory access. Do not attempt to persist anything.\
"""

# Read-only subset of the Triage Agent's tools — write_memory intentionally excluded
VERIFIER_TOOL_DECLARATIONS = {
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
    ]
}


def run_verifier(
    report: str,
    tool_fns: Dict,
    validate_args_fn,
    model: str = DEFAULT_MODEL,
    verbose: bool = True,
) -> str:
    """
    Independent verification pass against a completed IR report.

    Parameters
    ----------
    report : str
        The finished IR report from the Triage Agent.
    tool_fns : dict
        Read-only tool dispatch map (write_memory must be absent).
    validate_args_fn : callable
        Shared input validation function from local_agent.
    """
    es_read = get_es(write=False)

    if verbose:
        print(f"\n{'─'*60}")
        print("Forensic Auditor — Independent Verification Pass")
        print(f"{'─'*60}\n")

    contents: List[Dict] = [
        {"role": "user", "parts": [{"text": f"Verify this IR report:\n\n{report}"}]}
    ]

    for _ in range(8):
        raw = gemini_call(
            contents,
            model=model,
            system_prompt=VERIFIER_SYSTEM_PROMPT,
            tool_declarations=VERIFIER_TOOL_DECLARATIONS,
        )
        parts = extract_parts(raw)
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

            # write_memory is not in VERIFIER_TOOL_DECLARATIONS but guard anyway
            if fn_name == "write_memory":
                result = {"error": "write_memory is not available to the Forensic Auditor"}
            else:
                if verbose:
                    print(f"[Auditor] {fn_name}({json.dumps(fn_args, default=str)[:100]})")
                validation_error = validate_args_fn(fn_name, fn_args)
                if validation_error:
                    result = {"error": validation_error}
                else:
                    fn = tool_fns.get(fn_name)
                    result = fn(es_read, **fn_args) if fn else {"error": f"Unknown tool: {fn_name}"}

            fn_response_parts.append({
                "functionResponse": {"name": fn_name, "response": {"result": result}}
            })

        contents.append({"role": "user", "parts": fn_response_parts})

    return "Verification complete (max turns reached)."
