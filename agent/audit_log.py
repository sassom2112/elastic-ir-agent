"""
Chain-of-custody audit log for the IR agent.

Every tool call — allowed or blocked — is atomically appended to a JSONL file
using os.open + os.write (not Python's buffered IO) so there are no partial
writes even under concurrent sessions or crashes.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_DEFAULT_LOG = Path(__file__).parent.parent / "reports" / "audit_log.jsonl"


def log_tool_call(
    session_id: str,
    tool_name: str,
    args: Dict,
    result: Any,
    *,
    blocked_reason: Optional[str] = None,
    duration_ms: Optional[int] = None,
    log_path: Path = _DEFAULT_LOG,
) -> None:
    entry = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "tool": tool_name,
        "args": args,
        "blocked": blocked_reason is not None,
        "blocked_reason": blocked_reason,
        "duration_ms": duration_ms,
        "result_preview": str(result)[:300] if result is not None else None,
    }
    line = (json.dumps(entry) + "\n").encode()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)
