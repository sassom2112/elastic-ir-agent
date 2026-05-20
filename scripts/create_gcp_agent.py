"""
Create or update the IR Agent in Google Cloud Agent Builder via the Vertex AI API.

Prerequisites:
  pip install google-cloud-aiplatform
  gcloud auth application-default login
  gcloud config set project YOUR_PROJECT_ID

Run:
  python scripts/create_gcp_agent.py
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

try:
    import vertexai
    from vertexai.preview import reasoning_engines
except ImportError:
    print("ERROR: Install Vertex AI SDK: pip install google-cloud-aiplatform")
    sys.exit(1)

PROJECT_ID = os.getenv("GOOGLE_PROJECT_ID")
REGION = os.getenv("GOOGLE_REGION", "us-central1")
ELASTIC_MCP = os.getenv("ELASTIC_MCP_ENDPOINT")
ELASTIC_KEY = os.getenv("ELASTIC_API_KEY")

SYSTEM_PROMPT_PATH = Path(__file__).parent.parent / "agent" / "prompts" / "system_prompt.md"


def validate_env() -> None:
    missing = [k for k in ["GOOGLE_PROJECT_ID", "ELASTIC_MCP_ENDPOINT", "ELASTIC_API_KEY"] if not os.getenv(k)]
    if missing:
        print(f"ERROR: Missing env vars: {', '.join(missing)}")
        print("Fill in .env and re-run.")
        sys.exit(1)


def get_system_prompt() -> str:
    with open(SYSTEM_PROMPT_PATH) as f:
        return f.read()


def create_agent() -> None:
    validate_env()
    vertexai.init(project=PROJECT_ID, location=REGION)

    system_prompt = get_system_prompt()

    print(f"Creating IR Agent in project {PROJECT_ID} / {REGION} ...")

    # Define MCP tool source pointing to Elastic Agent Builder
    mcp_tool_source = {
        "type": "mcp",
        "server_url": ELASTIC_MCP,
        "auth": {
            "type": "api_key",
            "header": "Authorization",
            "value": f"ApiKey {ELASTIC_KEY}",
        },
    }

    agent = reasoning_engines.ReasoningEngine.create(
        display_name="IR Agent — Elastic Incident Responder",
        description=(
            "Autonomous IR agent. Investigates security alerts using Elastic MCP tools, "
            "maps findings to MITRE ATT&CK, and produces structured IR reports."
        ),
        spec=reasoning_engines.ReasoningEngineSpec(
            agent_framework=reasoning_engines.LangchainAgent(
                model="gemini-2.0-flash-001",
                system_instruction=system_prompt,
                tools=[mcp_tool_source],
                model_kwargs={
                    "temperature": 0.2,
                    "max_output_tokens": 8192,
                },
            )
        ),
    )

    print(f"\nAgent created successfully!")
    print(f"Resource name: {agent.resource_name}")
    print(f"\nTest it:")
    print(f"  python scripts/run_investigation.py --agent-id {agent.name.split('/')[-1]}")


if __name__ == "__main__":
    create_agent()
