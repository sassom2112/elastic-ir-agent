"""
Run an investigation against the deployed Google Cloud Agent Builder agent.

Usage:
  python scripts/run_investigation.py --prompt "investigate failed logins on WS-04"
  python scripts/run_investigation.py --agent-id <id> --prompt "..."

Falls back to local agent if GCP agent ID is not configured.
"""

import argparse
import os
import sys
from dotenv import load_dotenv

load_dotenv()


def run_via_gcp(agent_id: str, prompt: str, project: str, region: str) -> str:
    try:
        import vertexai
        from vertexai.preview import reasoning_engines
    except ImportError:
        print("ERROR: pip install google-cloud-aiplatform")
        sys.exit(1)

    vertexai.init(project=project, location=region)
    agent = reasoning_engines.ReasoningEngine(agent_id)
    response = agent.query(input=prompt)
    return response.get("output", str(response))


def run_via_local(prompt: str, session_id: str) -> str:
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))
    from agent.local_agent import run_investigation
    return run_investigation(prompt, session_id=session_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run IR Agent investigation")
    parser.add_argument("--prompt", "-p", required=True, help="Investigation prompt")
    parser.add_argument("--agent-id", help="GCP Agent Builder agent resource ID (uses local agent if omitted)")
    parser.add_argument("--session", "-s", default="run-001", help="Session ID for memory continuity")
    args = parser.parse_args()

    agent_id = args.agent_id or os.getenv("GCP_AGENT_ID")
    project = os.getenv("GOOGLE_PROJECT_ID")
    region = os.getenv("GOOGLE_REGION", "us-central1")

    if agent_id and project:
        print(f"Running via GCP Agent Builder (agent: {agent_id})")
        result = run_via_gcp(agent_id, args.prompt, project, region)
    else:
        print("Running via local agent (GCP_AGENT_ID not set)")
        result = run_via_local(args.prompt, args.session)

    print(result)


if __name__ == "__main__":
    main()
