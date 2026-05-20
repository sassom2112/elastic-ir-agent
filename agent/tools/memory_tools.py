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

MemoryType = Literal["finding", "summary", "hypothesis", "ioc", "timeline_entry"]


def get_client() -> Elasticsearch:
    return Elasticsearch(
        cloud_id=os.environ["ELASTIC_CLOUD_ID"],
        api_key=os.environ["ELASTIC_API_KEY"],
    )


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
    client = get_client()
    index = os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory")

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

    return {"id": doc_id, "status": "written", "memory_type": memory_type}


def search_memory(
    query: str,
    session_id: Optional[str] = None,
    memory_type: Optional[MemoryType] = None,
    top_k: int = 5,
) -> List[dict]:
    """
    Search agent memory using hybrid text + semantic search.
    Returns the top_k most relevant memory entries.
    """
    client = get_client()
    index = os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory")

    must_filters = []
    if session_id:
        must_filters.append({"term": {"session_id": session_id}})
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
