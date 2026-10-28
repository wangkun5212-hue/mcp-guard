import pytest
import os
import shutil
import tempfile
from starlette.testclient import TestClient

from mcp_guard.auth import KeyManager
from mcp_guard.limiter import PerToolRateLimiter, ToolRatePolicy
from mcp_guard.redactor import RedactionPipeline
from mcp_guard.audit import AuditLogger
from mcp_guard.gateway import MCPGuardGateway


@pytest.fixture
def temp_env():
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_setup(temp_env):
    key_mgr = KeyManager()
    key_mgr.add_key(
        raw_key="test-key-partner",
        caller_id="partner_corp",
        allowed_tools=["search_docs", "get_weather"],
        rate_multiplier=1.0,
    )
    key_mgr.add_key(
        raw_key="test-key-admin",
        caller_id="admin_user",
        allowed_tools=None,  # All tools
        rate_multiplier=5.0,
    )

    limiter = PerToolRateLimiter(
        default_policy=ToolRatePolicy(rate_per_minute=60, burst_capacity=2),
        tool_policies={
            "ask_ai": ToolRatePolicy(rate_per_minute=10, burst_capacity=1),
        },
    )

    redactor = RedactionPipeline()
    audit = AuditLogger(log_dir=os.path.join(temp_env, "logs"))

    gateway = MCPGuardGateway(
        key_manager=key_mgr,
        rate_limiter=limiter,
        redactor=redactor,
        audit_logger=audit,
    )

    # Register sample tools
    gateway.register_tool(
        schema={"name": "search_docs", "description": "Search internal docs"},
        handler=lambda query: f"Found doc for '{query}'. Total quote: $5,000 USD and CNY 1200.",
    )
    gateway.register_tool(
        schema={"name": "ask_ai", "description": "Heavy LLM reasoning"},
        handler=lambda prompt: f"AI Answer for {prompt}",
    )

    client = TestClient(gateway.as_asgi_app())
    return client, audit, temp_env


def test_auth_unauthorized(test_setup):
    client, _, _ = test_setup
    res = client.post("/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": 1})
    assert res.status_code == 401
    assert res.json()["error"]["code"] == -32001


def test_auth_and_initialize(test_setup):
    client, _, _ = test_setup
    headers = {"Authorization": "Bearer test-key-partner"}
    res = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "initialize", "id": 1})
    assert res.status_code == 200
    data = res.json()
    assert data["result"]["serverInfo"]["name"] == "mcp-guard"


def test_tools_list_filtering(test_setup):
    client, _, _ = test_setup

    # partner only has ["search_docs", "get_weather"]
    headers = {"Authorization": "Bearer test-key-partner"}
    res = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "tools/list", "id": 2})
    assert res.status_code == 200
    tools = [t["name"] for t in res.json()["result"]["tools"]]
    assert "search_docs" in tools
    assert "ask_ai" not in tools

    # admin sees all tools
    admin_headers = {"Authorization": "Bearer test-key-admin"}
    res_admin = client.post("/mcp", headers=admin_headers, json={"jsonrpc": "2.0", "method": "tools/list", "id": 3})
    admin_tools = [t["name"] for t in res_admin.json()["result"]["tools"]]
    assert "search_docs" in admin_tools
    assert "ask_ai" in admin_tools


def test_tool_call_permission_denied(test_setup):
    client, _, _ = test_setup
    headers = {"Authorization": "Bearer test-key-partner"}
    res = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "ask_ai", "arguments": {"prompt": "hi"}},
            "id": 4,
        },
    )
    assert res.status_code == 403
    assert res.json()["error"]["code"] == -32003


def test_data_redaction_and_audit(test_setup):
    client, audit, temp_env = test_setup
    headers = {"Authorization": "Bearer test-key-partner"}

    res = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "search_docs", "arguments": {"query": "pricing"}},
            "id": 5,
        },
    )
    assert res.status_code == 200
    result_content = res.json()["result"]["content"]
    combined_text = " ".join([c["text"] for c in result_content])

    # Price numbers should be scrubbed
    assert "$5,000" not in combined_text
    assert "***" in combined_text
    assert "[Note: Sensitive info redacted by guardrails]" in combined_text


def test_rate_limiting_burst(test_setup):
    client, _, _ = test_setup
    headers = {"Authorization": "Bearer test-key-admin"}

    # ask_ai burst is 1 * 5.0 (multiplier) = 5
    # Let's hit it rapidly
    allowed_count = 0
    blocked = False
    for i in range(10):
        res = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "ask_ai", "arguments": {"prompt": f"test {i}"}},
                "id": 100 + i,
            },
        )
        if res.status_code == 200:
            allowed_count += 1
        elif res.status_code == 429:
            blocked = True
            assert "Retry-After" in res.headers
            break

    assert blocked is True
    assert allowed_count > 0
