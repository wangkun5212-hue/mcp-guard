"""
mcp-guard: Production guardrails for MCP (Model Context Protocol) servers.
"""

from mcp_guard.auth import KeyManager, ClientIdentity
from mcp_guard.limiter import TokenBucket, PerToolRateLimiter
from mcp_guard.redactor import RedactionPipeline, RegexMaskRule
from mcp_guard.audit import AuditLogger
from mcp_guard.gateway import MCPGuardGateway

__version__ = "0.1.0"
__all__ = [
    "KeyManager",
    "ClientIdentity",
    "TokenBucket",
    "PerToolRateLimiter",
    "RedactionPipeline",
    "RegexMaskRule",
    "AuditLogger",
    "MCPGuardGateway",
]
