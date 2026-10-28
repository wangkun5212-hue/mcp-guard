import uvicorn
from mcp_guard.gateway import MCPGuardGateway
from mcp_guard.auth import KeyManager
from mcp_guard.limiter import PerToolRateLimiter, ToolRatePolicy
from mcp_guard.redactor import RedactionPipeline
from mcp_guard.audit import AuditLogger

# 1. Initialize Key Manager with Multi-Tenant Keys
key_manager = KeyManager()
# Key 1: External partner with limited tool access and normal rate
key_manager.add_key(
    raw_key="sk-partner-secret-token",
    caller_id="external_partner_corp",
    allowed_tools=["search_public_catalog"],
    rate_multiplier=1.0,
)
# Key 2: Internal developer with full access and elevated rate
key_manager.add_key(
    raw_key="sk-internal-admin-token",
    caller_id="internal_platform_admin",
    allowed_tools=None,  # Wildcard access to all tools
    rate_multiplier=5.0,
)

# 2. Configure Per-Tool Rate Limiter
rate_limiter = PerToolRateLimiter(
    default_policy=ToolRatePolicy(rate_per_minute=60, burst_capacity=10),
    tool_policies={
        # Heavy reasoning tool gets tighter constraints
        "generate_ai_summary": ToolRatePolicy(rate_per_minute=10, burst_capacity=2),
    },
)

# 3. Setup Redaction Pipeline & Audit Logger
redactor = RedactionPipeline()
audit_logger = AuditLogger(log_dir="./logs")

# 4. Create Gateway
gateway = MCPGuardGateway(
    key_manager=key_manager,
    rate_limiter=rate_limiter,
    redactor=redactor,
    audit_logger=audit_logger,
    server_name="secure-mcp-service",
)

# 5. Register Business Tools
def search_public_catalog(query: str):
    # Simulated search output containing sensitive internal prices
    return f"Product catalog for '{query}': Premium license base fee is $12,000 USD, discounted price is 8000 CNY."

def generate_ai_summary(topic: str):
    return f"Synthesized executive briefing regarding {topic}."

gateway.register_tool(
    schema={
        "name": "search_public_catalog",
        "description": "Search public product catalogs and specifications",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    handler=search_public_catalog,
)

gateway.register_tool(
    schema={
        "name": "generate_ai_summary",
        "description": "Generate in-depth analysis on a specific topic",
        "inputSchema": {
            "type": "object",
            "properties": {"topic": {"type": "string"}},
            "required": ["topic"],
        },
    },
    handler=generate_ai_summary,
)

app = gateway.as_asgi_app()

if __name__ == "__main__":
    print("Starting MCP Guard Gateway on http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
