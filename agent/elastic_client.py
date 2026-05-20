"""
Shared Elasticsearch client factory.

Supports both Elastic Cloud Serverless (ELASTIC_URL) and legacy hosted (ELASTIC_CLOUD_ID).
Serverless projects expose a plain HTTPS endpoint; hosted projects use a Cloud ID.

Use get_es(write=True) for any operation that writes to Elasticsearch (index, delete, update).
Read operations use ELASTIC_API_KEY_READ; write operations use ELASTIC_API_KEY_WRITE.
Both fall back to ELASTIC_API_KEY if the scoped keys are not set.
"""

import os
import sys
from elasticsearch import Elasticsearch


def get_es(write: bool = False) -> Elasticsearch:
    if write:
        api_key = os.getenv("ELASTIC_API_KEY_WRITE") or os.getenv("ELASTIC_API_KEY")
    else:
        api_key = os.getenv("ELASTIC_API_KEY_READ") or os.getenv("ELASTIC_API_KEY")

    url = os.getenv("ELASTIC_URL")
    cloud_id = os.getenv("ELASTIC_CLOUD_ID")

    if not api_key:
        key_var = "ELASTIC_API_KEY_WRITE" if write else "ELASTIC_API_KEY_READ"
        print(f"ERROR: Set {key_var} (or ELASTIC_API_KEY) in .env")
        sys.exit(1)

    if url:
        return Elasticsearch(url, api_key=api_key)
    elif cloud_id:
        return Elasticsearch(cloud_id=cloud_id, api_key=api_key)
    else:
        print("ERROR: Set ELASTIC_URL (Serverless) or ELASTIC_CLOUD_ID (Hosted) in .env")
        sys.exit(1)
