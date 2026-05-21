"""
Gemini REST client — shared by the Triage Agent and Forensic Auditor.

Uses the REST API directly (no Gemini SDK required, Python 3.8+).
"""

import os
import time
from typing import Any, Dict, List, Optional

import requests

GEMINI_REST_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
DEFAULT_MODEL = "gemini-2.5-flash"


def gemini_call(
    contents: List[Dict],
    model: str = DEFAULT_MODEL,
    system_prompt: Optional[str] = None,
    tool_declarations: Optional[Dict] = None,
    api_key: Optional[str] = None,
) -> Dict:
    key = api_key or os.getenv("GOOGLE_API_KEY")
    url = GEMINI_REST_URL.format(model=model, key=key)
    payload: Dict[str, Any] = {
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 8192},
        "contents": contents,
    }
    if system_prompt:
        payload["system_instruction"] = {"parts": [{"text": system_prompt}]}
    if tool_declarations:
        payload["tools"] = [tool_declarations]

    for attempt in range(5):
        resp = requests.post(url, json=payload, timeout=120)
        if resp.status_code == 429:
            wait = 15 * (attempt + 1)
            print(f"  [rate limit] waiting {wait}s before retry {attempt + 1}/5 ...")
            time.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.json()

    resp.raise_for_status()
    return {}


def extract_parts(response: Dict) -> List[Dict]:
    return response.get("candidates", [{}])[0].get("content", {}).get("parts", [])
