"""
Smoke test: verify Elastic connection, index counts, and run a sample ES|QL query.

Run after indexing to confirm data is in Elastic before connecting the agent.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent.parent))
from agent.elastic_client import get_es as get_client

SAMPLE_QUERIES = [
    (
        "Failed logins in last 30 days",
        """
        FROM ir-events
        | WHERE event.code == "4625"
        | STATS count = COUNT(*) BY host.name
        | SORT count DESC
        | LIMIT 10
        """,
    ),
    (
        "MITRE technique distribution",
        """
        FROM ir-events
        | WHERE threat.technique.id IS NOT NULL
        | STATS events = COUNT(*) BY threat.technique.id, threat.technique.name
        | SORT events DESC
        """,
    ),
    (
        "Suspicious process executions",
        """
        FROM ir-events
        | WHERE event.category == "process"
        | WHERE process.name IS NOT NULL
        | STATS count = COUNT(*) BY process.name
        | SORT count DESC
        | LIMIT 20
        """,
    ),
]


def main() -> None:
    client = get_client()

    print("=== Elastic IR Agent — Smoke Test ===\n")

    # Connection check
    info = client.info()
    print(f"Connected: {info['name']} v{info['version']['number']}")

    # Index counts
    events_index = os.getenv("ELASTIC_INDEX_EVENTS", "ir-events")
    memory_index = os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory")

    for idx in [events_index, memory_index]:
        try:
            count = client.count(index=idx)["count"]
            print(f"  {idx}: {count:,} documents")
        except Exception as e:
            print(f"  {idx}: not found ({e})")

    if client.count(index=events_index).get("count", 0) == 0:
        print("\nNo events indexed yet. Run:")
        print("  python scripts/download_data.py")
        print("  python scripts/normalize_evtx.py")
        print("  python scripts/index_data.py")
        return

    # Sample ES|QL queries
    print("\n--- Sample Queries ---")
    for label, query in SAMPLE_QUERIES:
        print(f"\n{label}:")
        try:
            resp = client.esql.query(body={"query": query.strip()})
            columns = [c["name"] for c in resp.get("columns", [])]
            rows = resp.get("values", [])
            if rows:
                col_str = " | ".join(f"{c:<30}" for c in columns)
                print("  " + col_str)
                print("  " + "-" * len(col_str))
                for row in rows[:5]:
                    print("  " + " | ".join(f"{str(v):<30}" for v in row))
                if len(rows) > 5:
                    print(f"  ... ({len(rows)} total rows)")
            else:
                print("  (no results)")
        except Exception as e:
            print(f"  Error: {e}")

    print("\n=== Smoke test complete ===")


if __name__ == "__main__":
    main()
