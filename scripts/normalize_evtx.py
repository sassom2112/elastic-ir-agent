"""
Convert raw EVTX files to ECS-formatted JSONL for indexing into Elasticsearch.

Handles EVTX-ATTACK-SAMPLES directory structure and Splunk JSON datasets.
Maps Windows event IDs to ECS fields and MITRE ATT&CK technique IDs.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

try:
    from evtx import PyEvtxParser
except ImportError:
    print("ERROR: Install evtx parser: pip install evtx")
    sys.exit(1)

RAW_DIR = Path(__file__).parent.parent / "data" / "raw"
PROCESSED_DIR = Path(__file__).parent.parent / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# Windows Event ID → ECS action + category + ATT&CK hints
EVENT_MAP = {
    4624: {
        "action": "logged-in",
        "category": "authentication",
        "type": "start",
        "outcome": "success",
    },
    4625: {
        "action": "logon-failed",
        "category": "authentication",
        "type": "info",
        "outcome": "failure",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic_name": "Credential Access",
    },
    4648: {
        "action": "explicit-credentials-logon",
        "category": "authentication",
        "type": "info",
        "outcome": "success",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic_name": "Lateral Movement",
    },
    4656: {
        "action": "object-handle-requested",
        "category": "file",
        "type": "access",
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic_name": "Credential Access",
    },
    4663: {
        "action": "object-accessed",
        "category": "file",
        "type": "access",
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic_name": "Credential Access",
    },
    4688: {
        "action": "process-created",
        "category": "process",
        "type": "start",
    },
    4698: {
        "action": "scheduled-task-created",
        "category": "iam",
        "type": "creation",
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task",
        "tactic_name": "Persistence",
    },
    4720: {
        "action": "user-account-created",
        "category": "iam",
        "type": "creation",
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic_name": "Persistence",
    },
    5140: {
        "action": "network-share-accessed",
        "category": "network",
        "type": "access",
        "technique_id": "T1021.002",
        "technique_name": "SMB/Windows Admin Shares",
        "tactic_name": "Lateral Movement",
    },
    7045: {
        "action": "service-installed",
        "category": "process",
        "type": "change",
        "technique_id": "T1543.003",
        "technique_name": "Windows Service",
        "tactic_name": "Persistence",
    },
}

# LOLBins that signal suspicious execution
SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "pwdump.exe",
    "mshta.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wscript.exe", "cscript.exe",
}


def safe_get(record: dict, *keys, default=None):
    cur = record
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur is None:
            return default
    return cur


def normalize_evtx_record(record: dict) -> Optional[dict]:
    try:
        event_data = record.get("Event", {})
        system = event_data.get("System", {})
        event_id = int(safe_get(system, "EventID", default=0))
        if event_id == 0:
            return None

        mapping = EVENT_MAP.get(event_id, {})
        timestamp_raw = safe_get(system, "TimeCreated", "#attributes", "SystemTime")

        event_doc: dict = {
            "@timestamp": timestamp_raw or datetime.now(timezone.utc).isoformat(),
            "winlog": {
                "event_id": event_id,
                "channel": safe_get(system, "Channel"),
                "computer_name": safe_get(system, "Computer"),
                "record_id": safe_get(system, "EventRecordID"),
            },
            "event": {
                "code": str(event_id),
                "action": mapping.get("action", f"event-{event_id}"),
                "category": mapping.get("category", "host"),
                "type": mapping.get("type", "info"),
                "outcome": mapping.get("outcome"),
            },
            "host": {
                "name": safe_get(system, "Computer"),
                "hostname": safe_get(system, "Computer"),
            },
        }

        # MITRE ATT&CK
        if "technique_id" in mapping:
            event_doc["threat"] = {
                "technique": {
                    "id": mapping["technique_id"],
                    "name": mapping["technique_name"],
                },
                "tactic": {
                    "name": mapping["tactic_name"],
                },
            }

        # Extract EventData fields
        event_data_fields = event_data.get("EventData", {})
        if isinstance(event_data_fields, dict):
            subject_user = event_data_fields.get("SubjectUserName") or event_data_fields.get("TargetUserName")
            subject_domain = event_data_fields.get("SubjectDomainName") or event_data_fields.get("TargetDomainName")
            if subject_user:
                event_doc["user"] = {
                    "name": subject_user,
                    "domain": subject_domain,
                }

            # Process events (4688)
            if event_id == 4688:
                new_proc = event_data_fields.get("NewProcessName", "")
                proc_name = Path(new_proc).name if new_proc else None
                event_doc["process"] = {
                    "name": proc_name,
                    "command_line": event_data_fields.get("CommandLine"),
                    "parent": {
                        "name": Path(event_data_fields.get("ParentProcessName", "")).name or None,
                    },
                }
                if proc_name and proc_name.lower() in SUSPICIOUS_PROCESSES:
                    event_doc.setdefault("threat", {})
                    event_doc["threat"]["technique"] = {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                    }
                    event_doc["tags"] = ["suspicious-process"]

        # Remove None values recursively
        return _drop_nones(event_doc)

    except Exception:
        return None


def _drop_nones(obj):
    if isinstance(obj, dict):
        return {k: _drop_nones(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_drop_nones(i) for i in obj if i is not None]
    return obj


def process_evtx_file(evtx_path: Path, out_file) -> int:
    count = 0
    try:
        parser = PyEvtxParser(str(evtx_path))
        for record in parser.records_json():
            try:
                raw = json.loads(record["data"])
                doc = normalize_evtx_record(raw)
                if doc:
                    out_file.write(json.dumps(doc) + "\n")
                    count += 1
            except Exception:
                continue
    except Exception as e:
        print(f"  Warning: could not parse {evtx_path.name}: {e}")
    return count


def process_splunk_json(json_path: Path, out_file) -> int:
    count = 0
    try:
        with open(json_path) as f:
            data = json.load(f)
        events = data if isinstance(data, list) else data.get("events", [data])
        for event in events:
            # Splunk data is already somewhat structured; pass through with ECS wrapping
            doc = {
                "@timestamp": event.get("_time") or event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                "event": {
                    "code": str(event.get("EventCode") or event.get("event_id", "0")),
                    "action": event.get("EventType", "unknown"),
                    "category": "host",
                },
                "host": {"name": event.get("ComputerName") or event.get("host")},
                "user": {"name": event.get("user") or event.get("User")},
                "message": event.get("message") or event.get("_raw"),
                "tags": ["splunk-source"],
            }
            out_file.write(json.dumps(_drop_nones(doc)) + "\n")
            count += 1
    except Exception as e:
        print(f"  Warning: could not parse {json_path.name}: {e}")
    return count


def main() -> None:
    total = 0

    # Process EVTX-ATTACK-SAMPLES
    evtx_dir = RAW_DIR / "evtx-attack-samples"
    if evtx_dir.exists():
        evtx_files = list(evtx_dir.rglob("*.evtx"))
        print(f"Found {len(evtx_files)} EVTX files")
        out_path = PROCESSED_DIR / "evtx_events.jsonl"
        with open(out_path, "w") as out:
            for evtx_file in evtx_files:
                n = process_evtx_file(evtx_file, out)
                if n:
                    print(f"  {evtx_file.relative_to(RAW_DIR)}: {n} events")
                    total += n
        print(f"EVTX: {total} events -> {out_path}")
    else:
        print(f"No EVTX data at {evtx_dir} — run download_data.py first")

    # Process Splunk Attack Data JSON
    splunk_dir = RAW_DIR / "splunk-attack-data"
    if splunk_dir.exists():
        json_files = list(splunk_dir.rglob("*.json"))
        print(f"\nFound {len(json_files)} Splunk JSON files")
        splunk_count = 0
        out_path = PROCESSED_DIR / "splunk_events.jsonl"
        with open(out_path, "w") as out:
            for json_file in json_files:
                n = process_splunk_json(json_file, out)
                if n:
                    splunk_count += n
        print(f"Splunk: {splunk_count} events -> {out_path}")
        total += splunk_count

    print(f"\nTotal events normalized: {total}")


if __name__ == "__main__":
    main()
