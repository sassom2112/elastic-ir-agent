"""
Memory read/write tools for the IR agent.

These back the write_memory and search_memory MCP tools in Elastic Agent Builder.
They can also be called directly for testing.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import List, Literal, Optional

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from agent.audit_log import log_tool_call
from agent.elastic_client import get_es as get_client

MemoryType = Literal["finding", "summary", "hypothesis", "ioc", "timeline_entry"]

_ALLOWED_WRITE_INDEXES = frozenset({"ir-agent-memory"})


def write_memory(
    content: str,
    memory_type: MemoryType,
    session_id: str,
    mitre_techniques: Optional[List[str]] = None,
    affected_hosts: Optional[List[str]] = None,
    affected_users: Optional[List[str]] = None,
    related_events: Optional[List[str]] = None,
    confidence: float = 1.0,
    severity: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> dict:
    """Write a memory entry to the agent memory index."""
    client = get_client(write=True)
    index = os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory")
    if index not in _ALLOWED_WRITE_INDEXES:
        return {"status": "error", "error": f"Write target {index!r} is not in the approved index allowlist"}

    doc = {
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
    if affected_users:
        doc["affected_users"] = affected_users
    if related_events:
        doc["related_events"] = related_events
    if severity:
        doc["severity"] = severity
    if tags:
        doc["tags"] = tags

    doc_id = str(uuid.uuid4())
    client.index(index=index, id=doc_id, document=doc)

    result = {"id": doc_id, "status": "written", "memory_type": memory_type}
    log_tool_call(session_id, "write_memory",
                  {"memory_type": memory_type, "content_len": len(content)}, result)
    return result


def search_memory(
    query: str,
    session_id: str,
    memory_type: Optional[MemoryType] = None,
    top_k: int = 5,
) -> List[dict]:
    """
    Search agent memory scoped strictly to session_id.
    Cross-session queries are forbidden — each investigation is forensically isolated
    to prevent IOC contamination and false attribution between unrelated cases.
    """
    client = get_client()
    index = os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory")

    # session_id is always required and always applied as a hard filter
    must_filters: list = [{"term": {"session_id": session_id}}]
    if memory_type:
        must_filters.append({"term": {"memory_type": memory_type}})

    search_body = {
        "size": top_k,
        "query": {
            "bool": {
                "must": [
                    {
                        "multi_match": {
                            "query": query,
                            "fields": ["content", "content^2"],
                        }
                    }
                ],
                "filter": must_filters,
            }
        },
        "_source": ["content", "memory_type", "session_id", "@timestamp",
                    "mitre_techniques", "affected_hosts", "confidence", "severity"],
    }

    try:
        resp = client.search(index=index, body=search_body)
        return [
            {
                "score": hit["_score"],
                "id": hit["_id"],
                **hit["_source"],
            }
            for hit in resp["hits"]["hits"]
        ]
    except Exception:
        return []


if __name__ == "__main__":
    # Quick test
    import sys

    session = "test-session-001"
    print("Writing test memory entry...")
    result = write_memory(
        content="Detected brute force attack on WORKSTATION-04 — 47 failed logins in 10 minutes from 192.168.1.100",
        memory_type="finding",
        session_id=session,
        mitre_techniques=["T1110"],
        affected_hosts=["WORKSTATION-04"],
        confidence=0.95,
        severity="HIGH",
    )
    print(f"Written: {result}")

    print("\nSearching memory...")
    results = search_memory("brute force login failures", session_id=session)
    for r in results:
        print(f"  [{r['memory_type']}] {r['content'][:100]}...")
