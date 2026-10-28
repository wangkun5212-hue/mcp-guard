# 🛡️ MCP Guard

> **生产级 MCP (Model Context Protocol) 安全网关守门层。** 轻量、无厚重依赖的 ASGI 守门组件，内置多租户鉴权、工具级令牌桶限流、动态敏感数据脱敏与合规审计日志。

> **[English](README.md) | 中文文档**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Starlette](https://img.shields.io/badge/Starlette-compatible-009688.svg)](https://www.starlette.io/)

---

## 🎯 解决的核心痛点

MCP（Model Context Protocol）标准化了大模型与工具的交互。然而，当前开源社区的大多数 MCP 服务都停留在**本地单机、单用户的 `stdio` 模式**。

一旦需要将 MCP 部署到网络端（HTTP/SSE）供外部团队、渠道或生产系统调用，立刻会面临严重的生产级阻碍：

- ❌ **缺少多租户身份体系**：无法便捷地为不同客户端签发独立 Key，无法即时停用或针对租户配置白名单。
- ❌ **通用网关无法感知 Tool 语义**：传统的 Nginx、Kong、Envoy 无法解析 JSON-RPC 的 Body 内容，因此无法对轻量检索工具（如 `search_docs`）和高成本推理工具（如 `ask_llm`）做分级流控。
- ❌ **数据外泄风险**：工具输出经常包含敏感的价格、Token、内部异常堆栈或个人隐私数据。
- ❌ **审计盲区**：缺乏高可靠的结构化记录，难以事后追溯谁在何时调用了哪个工具、参数是什么、耗时多久。

---

## 💡 解决方案：MCP Guard

**MCP Guard** 是一个超轻量级的 MCP 安全防护层。直接挂载在你的 MCP 工具前面，为 HTTP 场景提供开箱即用的企业级防护：

- 🔑 **多租户密钥管理 (Auth)**：支持 Bearer Token 认证，内存采用 SHA-256 摘要隔离，常量时间比对（`hmac.compare_digest`），支持文件持久化与动态热重载（无需重启服务）。
- ⏱️ **工具级令牌桶限流 (Per-Tool Rate Limiter)**：基于 `time.monotonic()` 消除时钟漂移。不同工具独立配置 QPS 与 Burst 容量，支持租户倍率乘数，内置 LRU 闲置清理机制防爆内存。
- 🛡️ **动态敏感数据脱敏 (Redaction)**：宁可过度打码（Over-masking）的安全防御策略。自动扫描 MCP `content` 块并对敏感价格、Token、密钥等执行动态拦截掩码。
- 📜 **结构化每日审计日志 (JSONL Audit Log)**：防注入转义，按天滚动。安全记录 `caller_id`、`tool`、`duration_ms`、`redaction_hits`，参数自动做安全截断脱敏。
- 🔌 **原生 ASGI / Starlette 底座**：无厚重框架绑定，完美兼容 Uvicorn、FastAPI 及任何 ASGI 容器。

---

## 🚀 快速上手

### 1. 安装

```bash
git clone https://github.com/wangkun5212-hue/mcp-guard.git
cd mcp-guard
pip install -e .
```

### 2. 构建受保护的 MCP 服务

```python
import uvicorn
from mcp_guard.gateway import MCPGuardGateway
from mcp_guard.auth import KeyManager
from mcp_guard.limiter import PerToolRateLimiter, ToolRatePolicy
from mcp_guard.redactor import RedactionPipeline
from mcp_guard.audit import AuditLogger

# 1. 多租户密钥管理
key_mgr = KeyManager()
key_mgr.add_key(
    raw_key="sk-client-key-123",
    caller_id="partner_client",
    allowed_tools=["search_catalog"], # 限制工具调用白名单
    rate_multiplier=1.0,
)

# 2. 工具级分级限流器
limiter = PerToolRateLimiter(
    default_policy=ToolRatePolicy(rate_per_minute=60, burst_capacity=10),
    tool_policies={
        "heavy_reasoning_tool": ToolRatePolicy(rate_per_minute=5, burst_capacity=1),
    }
)

# 3. 创建网关
gateway = MCPGuardGateway(
    key_manager=key_mgr,
    rate_limiter=limiter,
    redactor=RedactionPipeline(),
    audit_logger=AuditLogger(log_dir="./logs"),
)

# 4. 注册业务工具
def search_catalog(query: str):
    return f"查询 '{query}' 的结果: 内部授权许可底价为 $8,000 USD。"

gateway.register_tool(
    schema={
        "name": "search_catalog",
        "description": "搜索产品目录",
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

启动服务：
```bash
python main.py
```

---

## 🔌 连接 MCP 客户端

客户端使用标准 HTTP POST JSON-RPC 2.0 协议连接 `/mcp`，Header 中携带 `Authorization: Bearer <token>`：

```bash
curl -X POST http://127.0.0.1:8000/mcp \
  -H "Authorization: Bearer sk-client-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "search_catalog",
      "arguments": {"query": "license"}
    },
    "id": 1
  }'
```

输出自动完成数据脱敏拦截：
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "查询 'license' 的结果: 内部授权许可底价为 ***。"
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

## 🧪 自动化测试

运行单元测试套件：
```bash
PYTHONPATH=. pytest tests/ -v
```

---

## 📄 开源许可证

MIT License.
