# 🛡️ MCP Guard

> **Production guardrails for MCP (Model Context Protocol) servers.** Lightweight, framework-agnostic ASGI gateway with multi-tenant auth, per-tool rate limiting, sensitive data redaction, and audit logging.

> **English | [中文文档](README_zh.md)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Starlette](https://img.shields.io/badge/Starlette-compatible-009688.svg)](https://www.starlette.io/)

---

## 🎯 The Problem

The Model Context Protocol (MCP) standardizes how LLMs invoke local and remote tools. However, almost all open-source MCP servers assume **single-user, local `stdio` usage**.

When organizations expose MCP servers over HTTP/SSE across teams or to external partners, they face immediate production roadblocks:

- ❌ **No Multi-Tenant Auth**: No standard mechanism for issuing, validating, or revoking API keys per client.
- ❌ **Lack of Tool-Aware Rate Limiting**: Generic API gateways treat all HTTP calls the same. They cannot differentiate between cheap retrieval tools (`search_docs`) and expensive reasoning tools (`ask_llm`) nested inside JSON-RPC payloads.
- ❌ **Data Leakage Risks**: Output text easily leaks internal pricing, PII, API tokens, or internal database exceptions.
- ❌ **Audit Blindspots**: Missing structured records of who called which tool, with what arguments, execution latency, and error states.

---

## 💡 The Solution: MCP Guard

**MCP Guard** is a lightweight, zero-bloat security layer for MCP servers. It sits directly in front of your tools and provides enterprise-ready guardrails out-of-the-box.

- 🔑 **Multi-Tenant Key Manager**: Bearer token authentication with constant-time comparison (`hmac.compare_digest`), SHA-256 hash storage, and dynamic hot-reloading.
- ⏱️ **Per-Tool TokenBucket Rate Limiting**: Independent QPS and burst capacity policies per tool, tenant-tier multipliers, and bounded memory with LRU idle client eviction.
- 🛡️ **Dynamic Sensitive Data Redaction**: Over-masking defense pipeline that strips sensitive patterns (prices, tokens, custom regex) across MCP `content` blocks.
- 📜 **Structured Daily JSONL Audit Logs**: High-performance, injection-safe audit trail recording `caller_id`, `tool`, `duration_ms`, `redaction_hits`, and sanitized arguments.
- 🔌 **Universal ASGI / Starlette Bridge**: Seamlessly works with Uvicorn, FastAPI, or any ASGI server.

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/wangkun5212-hue/mcp-guard.git
cd mcp-guard
pip install -e .
```

### 2. Create a Protected MCP Server

```python
import uvicorn
from mcp_guard.gateway import MCPGuardGateway
from mcp_guard.auth import KeyManager
from mcp_guard.limiter import PerToolRateLimiter, ToolRatePolicy
from mcp_guard.redactor import RedactionPipeline
from mcp_guard.audit import AuditLogger

# 1. Multi-Tenant Auth
key_mgr = KeyManager()
key_mgr.add_key(
    raw_key="sk-client-key-123",
    caller_id="partner_client",
    allowed_tools=["search_catalog"], # Whitelist access
    rate_multiplier=1.0,
)

# 2. Per-Tool Rate Limiter
limiter = PerToolRateLimiter(
    default_policy=ToolRatePolicy(rate_per_minute=60, burst_capacity=10),
    tool_policies={
        "heavy_reasoning_tool": ToolRatePolicy(rate_per_minute=5, burst_capacity=1),
    }
)

# 3. Create Guard Gateway
gateway = MCPGuardGateway(
    key_manager=key_mgr,
    rate_limiter=limiter,
    redactor=RedactionPipeline(),
    audit_logger=AuditLogger(log_dir="./logs"),
)

# 4. Register Tools
def search_catalog(query: str):
    return f"Result for '{query}'. Catalog license quote: $8,000 USD."

gateway.register_tool(
    schema={
        "name": "search_catalog",
        "description": "Search items in catalog",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    handler=search_catalog,
)

app = gateway.as_asgi_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
```

Run server:
```bash
python main.py
```

---

## 🔌 Connect Any MCP Client

Clients can connect using standard HTTP POST JSON-RPC 2.0 requests to `/mcp` with `Authorization: Bearer <token>`:

```bash
curl -X POST http://127.0.0.1:8000/mcp \
  -H "Authorization: Bearer sk-client-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "search_catalog",
      "arguments": {"query": "server"}
    },
    "id": 1
  }'
```

Response with automatic data redaction:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Result for 'server'. Catalog license quote: ***."
      },
      {
        "type": "text",
        "text": "[Note: Sensitive info redacted by guardrails]"
      }
    ],
    "isError": false
  },
  "id": 1
}
```

---

## 🧪 Testing

Run test suite:
```bash
PYTHONPATH=. pytest tests/ -v
```

---

## 📄 License

MIT License. Free for commercial and research use.
