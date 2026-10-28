import os
import json
import time
import glob
import threading
from typing import Optional, Any, Dict
from datetime import datetime, timezone


class AuditLogger:
    """
    Structured, Thread-Safe JSONL Audit Logger.
    - Security First: Sanitizes/truncates args and prevents logging raw sensitive payloads.
    - Daily file rotation: mcp_audit-YYYYMMDD.jsonl
    - Auto-pruning retention policy.
    - Logs caller_id, request_id, tool_name, status, duration_ms, and errors.
    """

    def __init__(
        self,
        log_dir: str = "./logs",
        retention_days: int = 30,
        max_arg_length: int = 256,
    ):
        self.log_dir = log_dir
        self.retention_days = retention_days
        self.max_arg_length = max_arg_length
        self._lock = threading.Lock()
        os.makedirs(self.log_dir, exist_ok=True)

    def _get_current_log_path(self) -> str:
        today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        return os.path.join(self.log_dir, f"mcp_audit-{today_str}.jsonl")

    def _sanitize_args(self, args: Any) -> Any:
        """Sanitize arguments: record keys and truncated values, never massive blobs."""
        if not isinstance(args, dict):
            return str(args)[:self.max_arg_length]

        sanitized = {}
        for k, v in args.items():
            if isinstance(v, (int, float, bool)):
                sanitized[k] = v
            elif isinstance(v, str):
                sanitized[k] = v[:self.max_arg_length] + ("..." if len(v) > self.max_arg_length else "")
            elif isinstance(v, (list, dict)):
                sanitized[k] = f"<{type(v).__name__} len={len(v)}>"
            else:
                sanitized[k] = str(type(v).__name__)
        return sanitized

    def log(
        self,
        caller_id: str,
        tool_name: str,
        status: str,  # "ok", "denied", "rate_limited", "error"
        request_id: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[float] = None,
        result_count: Optional[int] = None,
        redaction_hits: int = 0,
        error: Optional[str] = None,
    ) -> None:
        """Write structured audit event."""
        now_utc = datetime.now(timezone.utc).isoformat()
        event = {
            "ts": now_utc,
            "request_id": request_id or "",
            "caller_id": caller_id,
            "tool": tool_name,
            "status": status,
            "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
            "result_count": result_count,
            "redaction_hits": redaction_hits,
            "args": self._sanitize_args(args) if args else {},
            "error": str(error)[:256] if error else None,
        }

        line = json.dumps(event, ensure_ascii=False) + "\n"
        log_path = self._get_current_log_path()

        with self._lock:
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except OSError:
                pass  # Fail-safe: prevent crashing request cycle on file IO issues

    def prune_old_logs(self) -> int:
        """Delete audit logs older than retention_days."""
        now = time.time()
        cutoff = now - (self.retention_days * 86400)
        pattern = os.path.join(self.log_dir, "mcp_audit-*.jsonl")
        deleted = 0

        with self._lock:
            for path in glob.glob(pattern):
                try:
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                        deleted += 1
                except OSError:
                    pass
        return deleted
