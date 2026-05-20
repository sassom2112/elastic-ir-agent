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

# Sysmon Event ID → ECS action + category + ATT&CK hints
# Sysmon events cover most of the EVTX-ATTACK-SAMPLES corpus
SYSMON_EVENT_MAP = {
    1: {
        "action": "process-created",
        "category": "process",
        "type": "start",
    },
    2: {
        "action": "file-time-changed",
        "category": "file",
        "type": "change",
        "technique_id": "T1070.006",
        "technique_name": "Timestomp",
        "tactic_name": "Defense Evasion",
    },
    3: {
        "action": "network-connection",
        "category": "network",
        "type": "start",
    },
    5: {
        "action": "process-terminated",
        "category": "process",
        "type": "end",
    },
    6: {
        "action": "driver-loaded",
        "category": "driver",
        "type": "start",
    },
    7: {
        "action": "image-loaded",
        "category": "library",
        "type": "start",
    },
    8: {
        "action": "create-remote-thread",
        "category": "process",
        "type": "change",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic_name": "Defense Evasion",
    },
    10: {
        "action": "process-accessed",
        "category": "process",
        "type": "info",
        "technique_id": "T1003.001",
        "technique_name": "LSASS Memory",
        "tactic_name": "Credential Access",
    },
    11: {
        "action": "file-created",
        "category": "file",
        "type": "creation",
    },
    12: {
        "action": "registry-object-created",
        "category": "registry",
        "type": "creation",
    },
    13: {
        "action": "registry-value-set",
        "category": "registry",
        "type": "change",
    },
    14: {
        "action": "registry-key-renamed",
        "category": "registry",
        "type": "change",
    },
    15: {
        "action": "file-stream-created",
        "category": "file",
        "type": "creation",
        "technique_id": "T1564.004",
        "technique_name": "NTFS File Attributes",
        "tactic_name": "Defense Evasion",
    },
    17: {
        "action": "pipe-created",
        "category": "ipc",
        "type": "start",
        "technique_id": "T1559",
        "technique_name": "Inter-Process Communication",
        "tactic_name": "Execution",
    },
    18: {
        "action": "pipe-connected",
        "category": "ipc",
        "type": "info",
    },
    20: {
        "action": "wmi-filter-created",
        "category": "iam",
        "type": "creation",
        "technique_id": "T1546.003",
        "technique_name": "Windows Management Instrumentation Event Subscription",
        "tactic_name": "Persistence",
    },
    21: {
        "action": "wmi-consumer-created",
        "category": "iam",
        "type": "creation",
        "technique_id": "T1546.003",
        "technique_name": "Windows Management Instrumentation Event Subscription",
        "tactic_name": "Persistence",
    },
    22: {
        "action": "dns-query",
        "category": "network",
        "type": "info",
    },
    23: {
        "action": "file-deleted",
        "category": "file",
        "type": "deletion",
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactic_name": "Defense Evasion",
    },
    25: {
        "action": "process-tampered",
        "category": "process",
        "type": "change",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic_name": "Defense Evasion",
    },
}

# Windows Security Event ID → ECS action + category + ATT&CK hints
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

        channel = safe_get(system, "Channel") or ""
        # Treat as Sysmon if channel says so, OR if event ID is in Sysmon range (1-25)
        # and not a known Security/System log ID
        SECURITY_IDS = {4624, 4625, 4648, 4656, 4663, 4688, 4698, 4720, 5140, 7045, 5145, 5156}
        is_sysmon = "sysmon" in channel.lower() or (
            event_id in SYSMON_EVENT_MAP and event_id not in SECURITY_IDS
        )
        mapping = (SYSMON_EVENT_MAP if is_sysmon else EVENT_MAP).get(event_id, {})
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
            subject_user = event_data_fields.get("SubjectUserName") or event_data_fields.get("TargetUserName") or event_data_fields.get("User")
            subject_domain = event_data_fields.get("SubjectDomainName") or event_data_fields.get("TargetDomainName")
            if subject_user:
                event_doc["user"] = {
                    "name": subject_user,
                    "domain": subject_domain,
                }

            # Sysmon process events (ID 1)
            if is_sysmon and event_id == 1:
                image = event_data_fields.get("Image", "")
                proc_name = Path(image).name if image else None
                parent_image = event_data_fields.get("ParentImage", "")
                event_doc["process"] = {
                    "name": proc_name,
                    "command_line": event_data_fields.get("CommandLine"),
                    "pid": event_data_fields.get("ProcessId"),
                    "parent": {
                        "name": Path(parent_image).name if parent_image else None,
                        "command_line": event_data_fields.get("ParentCommandLine"),
                    },
                }
                if proc_name and proc_name.lower() in SUSPICIOUS_PROCESSES:
                    event_doc.setdefault("threat", {})
                    event_doc["threat"]["technique"] = {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                    }
                    event_doc["tags"] = ["suspicious-process"]
                cmdline = event_data_fields.get("CommandLine", "")
                if cmdline and ("-enc" in cmdline.lower() or "-encodedcommand" in cmdline.lower()):
                    event_doc.setdefault("tags", [])
                    if isinstance(event_doc["tags"], list):
                        event_doc["tags"].append("encoded-powershell")
                    else:
                        event_doc["tags"] = ["encoded-powershell"]

            # Sysmon network events (ID 3)
            elif is_sysmon and event_id == 3:
                event_doc["network"] = {
                    "destination": {
                        "ip": event_data_fields.get("DestinationIp"),
                        "port": event_data_fields.get("DestinationPort"),
                        "hostname": event_data_fields.get("DestinationHostname"),
                    },
                    "source": {
                        "ip": event_data_fields.get("SourceIp"),
                        "port": event_data_fields.get("SourcePort"),
                    },
                    "protocol": event_data_fields.get("Protocol"),
                }
                image = event_data_fields.get("Image", "")
                if image:
                    event_doc["process"] = {"name": Path(image).name}

            # Sysmon process access (ID 10) — lsass memory dumping
            elif is_sysmon and event_id == 10:
                target = event_data_fields.get("TargetImage", "")
                src = event_data_fields.get("SourceImage", "")
                if target:
                    event_doc["process"] = {"name": Path(target).name}
                    if "lsass" in target.lower():
                        event_doc.setdefault("threat", {})
                        event_doc["threat"]["technique"] = {
                            "id": "T1003.001",
                            "name": "LSASS Memory",
                        }
                        event_doc["threat"]["tactic"] = {"name": "Credential Access"}
                        event_doc.setdefault("tags", [])
                        if isinstance(event_doc["tags"], list):
                            event_doc["tags"].append("lsass-access")
                if src:
                    event_doc.setdefault("process", {})
                    event_doc["process"]["parent"] = {"name": Path(src).name}

            # Security log process events (4688)
            elif not is_sysmon and event_id == 4688:
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
