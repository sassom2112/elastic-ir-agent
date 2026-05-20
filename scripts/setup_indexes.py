"""
Create Elasticsearch indexes with mappings and ingest pipelines.

Run once after connecting to Elastic Cloud Serverless:
  python scripts/setup_indexes.py
"""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

MAPPINGS_DIR = Path(__file__).parent.parent / "elastic" / "mappings"


def get_client() -> Elasticsearch:
    cloud_id = os.getenv("ELASTIC_CLOUD_ID")
    api_key = os.getenv("ELASTIC_API_KEY")
    if not cloud_id or not api_key:
        print("ERROR: Set ELASTIC_CLOUD_ID and ELASTIC_API_KEY in .env")
        sys.exit(1)
    return Elasticsearch(cloud_id=cloud_id, api_key=api_key)


def create_elser_pipeline(client: Elasticsearch) -> None:
    """Create ingest pipeline that auto-embeds content with ELSER for semantic search."""
    pipeline_id = "elser-embed-memory"

    # Check if ELSER model is available
    try:
        client.ml.get_trained_models(model_id=".elser_model_2_linux-x86_64")
        model_id = ".elser_model_2_linux-x86_64"
    except Exception:
        try:
            client.ml.get_trained_models(model_id=".elser_model_2")
            model_id = ".elser_model_2"
        except Exception:
            print("  Warning: ELSER model not found — semantic search will be limited")
            print("  To enable: Kibana → Machine Learning → Trained Models → Download ELSER")
            return

    pipeline = {
        "description": "Embed agent memory content with ELSER for semantic search",
        "processors": [
            {
                "inference": {
                    "model_id": model_id,
                    "input_output": [
                        {
                            "input_field": "content",
                            "output_field": "content_vector",
                        }
                    ],
                    "on_failure": [
                        {
                            "set": {
                                "field": "_source._ingest.inference_failure",
                                "value": True,
                            }
                        }
                    ],
                }
            }
        ],
    }

    client.ingest.put_pipeline(id=pipeline_id, body=pipeline)
    print(f"  Created ingest pipeline: {pipeline_id}")


def create_index(client: Elasticsearch, index_name: str, mapping_file: str) -> None:
    mapping_path = MAPPINGS_DIR / mapping_file
    with open(mapping_path) as f:
        config = json.load(f)

    if client.indices.exists(index=index_name):
        print(f"  Index already exists: {index_name} (skipping)")
        return

    client.indices.create(index=index_name, body=config)
    print(f"  Created index: {index_name}")


def main() -> None:
    client = get_client()

    print("Connecting to Elastic Cloud...")
    info = client.info()
    print(f"Connected: {info['name']} v{info['version']['number']}\n")

    print("Setting up ELSER ingest pipeline...")
    create_elser_pipeline(client)

    print("\nCreating indexes...")
    indexes = [
        (os.getenv("ELASTIC_INDEX_EVENTS", "ir-events"), "ir_events.json"),
        (os.getenv("ELASTIC_INDEX_MEMORY", "ir-agent-memory"), "ir_agent_memory.json"),
    ]
    for index_name, mapping_file in indexes:
        create_index(client, index_name, mapping_file)

    print("\nSetup complete.")
    print("Next: python scripts/download_data.py && python scripts/normalize_evtx.py && python scripts/index_data.py")


if __name__ == "__main__":
    main()
