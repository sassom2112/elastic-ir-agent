"""
Shared Elasticsearch client factory.

Supports both Elastic Cloud Serverless (ELASTIC_URL) and legacy hosted (ELASTIC_CLOUD_ID).
Serverless projects expose a plain HTTPS endpoint; hosted projects use a Cloud ID.
"""

import os
import sys
from elasticsearch import Elasticsearch


def get_es() -> Elasticsearch:
    api_key = os.getenv("ELASTIC_API_KEY")
    url = os.getenv("ELASTIC_URL")
    cloud_id = os.getenv("ELASTIC_CLOUD_ID")

    if not api_key:
        print("ERROR: ELASTIC_API_KEY is not set in .env")
        sys.exit(1)

    if url:
        return Elasticsearch(url, api_key=api_key)
    elif cloud_id:
        return Elasticsearch(cloud_id=cloud_id, api_key=api_key)
    else:
        print("ERROR: Set ELASTIC_URL (Serverless) or ELASTIC_CLOUD_ID (Hosted) in .env")
        sys.exit(1)
