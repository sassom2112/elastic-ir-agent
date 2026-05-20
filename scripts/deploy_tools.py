"""
Deploy ES|QL tool definitions to Elastic Agent Builder via the Kibana API.

Reads elastic/esql_tools/queries.yaml and creates/updates each tool in Agent Builder.
Requires KIBANA_URL and ELASTIC_API_KEY in .env.
"""

import json
import os
import sys
from pathlib import Path

import requests
import yaml
from dotenv import load_dotenv

load_dotenv()

TOOLS_FILE = Path(__file__).parent.parent / "elastic" / "esql_tools" / "queries.yaml"


def get_headers() -> dict:
    api_key = os.getenv("ELASTIC_API_KEY")
    if not api_key:
        print("ERROR: Set ELASTIC_API_KEY in .env")
        sys.exit(1)
    return {
        "Authorization": f"ApiKey {api_key}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }


def get_kibana_url() -> str:
    url = os.getenv("KIBANA_URL") or os.getenv("ELASTIC_MCP_ENDPOINT")
    if not url:
        print("ERROR: Set KIBANA_URL in .env (your Kibana endpoint, e.g. https://xxx.kb.us-central1.gcp.elastic-cloud.com)")
        sys.exit(1)
    return url.rstrip("/")


def load_tools() -> list[dict]:
    with open(TOOLS_FILE) as f:
        data = yaml.safe_load(f)
    return data.get("tools", [])


def build_tool_payload(tool: dict) -> dict:
    """Convert our YAML tool definition to the Agent Builder API format."""
    params_schema = {
        "type": "object",
        "properties": {},
        "required": [],
    }
    for param in tool.get("parameters", []):
        params_schema["properties"][param["name"]] = {
            "type": param["type"],
            "description": param.get("description", ""),
        }
        if "default" not in param:
            params_schema["required"].append(param["name"])

    return {
        "name": tool["name"],
        "description": tool["description"].strip(),
        "type": "esql",
        "esql": {
            "query": tool["esql"].strip(),
        },
        "parameters": params_schema,
    }


def deploy_tool(kibana_url: str, headers: dict, tool: dict) -> bool:
    payload = build_tool_payload(tool)
    name = tool["name"]

    # Try PUT (update) first, fall back to POST (create)
    url = f"{kibana_url}/api/agent_builder/tools/{name}"
    resp = requests.put(url, headers=headers, json=payload, timeout=30)

    if resp.status_code == 404:
        url = f"{kibana_url}/api/agent_builder/tools"
        resp = requests.post(url, headers=headers, json=payload, timeout=30)

    if resp.status_code in (200, 201):
        print(f"  [OK] {name}")
        return True
    else:
        print(f"  [FAIL] {name}: {resp.status_code} {resp.text[:200]}")
        return False


def main() -> None:
    kibana_url = get_kibana_url()
    headers = get_headers()
    tools = load_tools()

    print(f"Deploying {len(tools)} tools to {kibana_url}...\n")

    ok = sum(deploy_tool(kibana_url, headers, t) for t in tools)
    print(f"\n{ok}/{len(tools)} tools deployed successfully.")

    if ok < len(tools):
        print("\nNote: If the Agent Builder API path is different in your Kibana version,")
        print("you can create tools manually via Kibana → Search → Agent Builder → Tools")
        print("using the ES|QL from elastic/esql_tools/queries.yaml")


if __name__ == "__main__":
    main()
