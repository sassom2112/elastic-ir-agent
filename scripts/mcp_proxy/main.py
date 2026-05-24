import os
import json
import requests
from flask import Flask, request, Response

app = Flask(__name__)

KIBANA_URL = os.environ["KIBANA_URL"].rstrip("/")
ELASTIC_API_KEY = os.environ["ELASTIC_API_KEY"]
MCP_TARGET = f"{KIBANA_URL}/api/agent_builder/mcp"

TOOLS = frozenset({
    "unique_hosts_by_technique",
    "credential_access_events",
    "suspicious_process_execution",
    "attack_timeline",
    "failed_logins_by_host",
    "lateral_movement_detection",
})

_ELASTIC_HEADERS = {
    "Authorization": f"ApiKey {os.environ.get('ELASTIC_API_KEY', '')}",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "kbn-xsrf": "true",
}


def _mcp_call(tool_name: str, arguments: dict) -> Response:
    _ELASTIC_HEADERS["Authorization"] = f"ApiKey {ELASTIC_API_KEY}"
    payload = {
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    resp = requests.post(MCP_TARGET, json=payload, headers=_ELASTIC_HEADERS, timeout=30)
    data = resp.json()
    content = data.get("result", {}).get("content", [])
    text = "".join(c["text"] for c in content if c.get("type") == "text")
    try:
        result = json.loads(text)
    except Exception:
        result = {"text": text}
    return Response(json.dumps(result), status=200, content_type="application/json")


@app.route("/tools/<tool_name>", methods=["POST"])
def tool_call(tool_name: str):
    if tool_name not in TOOLS:
        return Response(
            json.dumps({"error": f"Unknown tool: {tool_name}"}),
            status=404, content_type="application/json",
        )
    args = request.get_json(silent=True) or {}
    return _mcp_call(tool_name, args)


@app.route("/", methods=["GET"])
def status():
    return Response(
        json.dumps({"status": "Elastic IR MCP Proxy", "tools": sorted(TOOLS)}),
        content_type="application/json",
    )


@app.route("/mcp", methods=["GET", "POST"])
def mcp_proxy():
    _ELASTIC_HEADERS["Authorization"] = f"ApiKey {ELASTIC_API_KEY}"
    resp = requests.request(
        method=request.method,
        url=MCP_TARGET,
        headers=_ELASTIC_HEADERS,
        data=request.get_data(),
        timeout=30,
    )
    return Response(
        resp.content, status=resp.status_code,
        content_type=resp.headers.get("Content-Type", "application/json"),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
