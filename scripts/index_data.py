"""
Index processed attack data into Elastic Cloud Serverless.

Expects ECS-formatted JSON files in data/processed/.
Run normalize_evtx.py first to convert raw EVTX files.
"""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from elasticsearch import Elasticsearch, helpers

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent.parent))
from agent.elastic_client import get_es as get_client

PROCESSED_DIR = Path(__file__).parent.parent / "data" / "processed"
INDEX_NAME = os.getenv("ELASTIC_INDEX_EVENTS", "ir-events")
BATCH_SIZE = 500


def create_index(client: Elasticsearch) -> None:
    mappings_path = Path(__file__).parent.parent / "elastic" / "mappings" / "ir_events.json"
    with open(mappings_path) as f:
        config = json.load(f)

    if not client.indices.exists(index=INDEX_NAME):
        client.indices.create(index=INDEX_NAME, body=config)
        print(f"Created index: {INDEX_NAME}")
    else:
        print(f"Index already exists: {INDEX_NAME}")


def load_events(file_path: Path) -> list[dict]:
    events = []
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def bulk_index(client: Elasticsearch, events: list[dict]) -> tuple[int, int]:
    actions = [
        {"_index": INDEX_NAME, "_source": event}
        for event in events
    ]
    success, errors = helpers.bulk(client, actions, chunk_size=BATCH_SIZE, raise_on_error=False)
    return success, len(errors)


def main() -> None:
    client = get_client()

    print("Checking connection...")
    info = client.info()
    print(f"Connected to: {info['name']} ({info['version']['number']})")

    create_index(client)

    json_files = list(PROCESSED_DIR.glob("*.jsonl")) + list(PROCESSED_DIR.glob("*.json"))
    if not json_files:
        print(f"No processed files found in {PROCESSED_DIR}")
        print("Run: python scripts/normalize_evtx.py")
        sys.exit(1)

    total_indexed = 0
    total_errors = 0

    for file_path in sorted(json_files):
        print(f"Indexing {file_path.name} ...")
        events = load_events(file_path)
        if events:
            ok, errs = bulk_index(client, events)
            total_indexed += ok
            total_errors += errs
            print(f"  -> {ok} indexed, {errs} errors")

    print(f"\nDone: {total_indexed} total events indexed, {total_errors} errors")


if __name__ == "__main__":
    main()
