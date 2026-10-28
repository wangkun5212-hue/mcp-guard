import time
import uuid
from typing import Callable, Dict, Any, List, Optional
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_guard.auth import KeyManager, ClientIdentity
from mcp_guard.limiter import PerToolRateLimiter
from mcp_guard.redactor import RedactionPipeline
from mcp_guard.audit import AuditLogger


class MCPGuardGateway:
    """
    Lightweight, Production-Grade MCP Guard Gateway.
    - Bridges MCP JSON-RPC 2.0 requests over HTTP.
    - Enforces Bearer token multi-tenant authentication.
    - Hierarchical per-tool token-bucket rate limiting.
    - Dynamic data redaction across outputs and error messages.
    - Structured daily JSONL audit logging.
    """

    def __init__(
        self,
        key_manager: KeyManager,
        rate_limiter: PerToolRateLimiter,
        redactor: Optional[RedactionPipeline] = None,
        audit_logger: Optional[AuditLogger] = None,
        server_name: str = "mcp-guard",
        server_version: str = "0.1.0",
    ):
        self.key_manager = key_manager
        self.rate_limiter = rate_limiter
        self.redactor = redactor or RedactionPipeline()
        self.audit_logger = audit_logger or AuditLogger()
        self.server_name = server_name
        self.server_version = server_version

        self._tools: Dict[str, Dict[str, Any]] = {}
        self._handlers: Dict[str, Callable] = {}

    def register_tool(self, schema: Dict[str, Any], handler: Callable) -> None:
        """Register tool definition and its execution handler."""
        name = schema.get("name")
        if not name:
            raise ValueError("Tool schema must contain 'name'")
        self._tools[name] = schema
        self._handlers[name] = handler

    async def handle_mcp_post(self, request: Request) -> Response:
        """Core MCP JSON-RPC 2.0 request handler."""
        start_time = time.monotonic()
        req_id = request.headers.get("x-request-id") or str(uuid.uuid4())

        # 1. Authenticate
        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer "):].strip()

        identity: Optional[ClientIdentity] = self.key_manager.authenticate(token)
        if not identity:
            self.audit_logger.log(
                caller_id="unauthorized",
                tool_name="auth",
                status="denied",
                request_id=req_id,
                error="Invalid or missing bearer token",
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32001, "message": "Unauthorized: Invalid or missing token"},
                    "id": None,
                },
                status_code=401,
            )

        # 2. Parse JSON-RPC Payload
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error: Invalid JSON"},
                    "id": None,
                },
                status_code=400,
            )

        rpc_id = body.get("id")
        method = body.get("method")
        params = body.get("params", {})

        # 3. Route MCP Methods
        if method == "initialize":
            return self._handle_initialize(rpc_id)

        if method == "tools/list":
            return self._handle_tools_list(rpc_id, identity)

        if method == "tools/call":
            return await self._handle_tool_call(rpc_id, params, identity, req_id, start_time)

        # Unknown Method
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Method not found: {method}"},
                "id": rpc_id,
            },
            status_code=404,
        )

    def _handle_initialize(self, rpc_id: Any) -> JSONResponse:
        return JSONResponse({
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": self.server_name, "version": self.server_version},
                "capabilities": {"tools": {}},
            },
            "id": rpc_id,
        })

    def _handle_tools_list(self, rpc_id: Any, identity: ClientIdentity) -> JSONResponse:
        """Return available tools filtered by client tool whitelist."""
        available = []
        for name, schema in self._tools.items():
            if identity.allowed_tools is None or name in identity.allowed_tools:
                available.append(schema)
        return JSONResponse({
            "jsonrpc": "2.0",
            "result": {"tools": available},
            "id": rpc_id,
        })

    async def _handle_tool_call(
        self,
        rpc_id: Any,
        params: dict,
        identity: ClientIdentity,
        req_id: str,
        start_time: float,
    ) -> JSONResponse:
        tool_name = params.get("name")
        args = params.get("arguments", {})

        if not tool_name or tool_name not in self._tools:
            return JSONResponse({
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": f"Tool '{tool_name}' not found"},
                "id": rpc_id,
            }, status_code=404)

        # Permission check
        if identity.allowed_tools is not None and tool_name not in identity.allowed_tools:
            self.audit_logger.log(
                caller_id=identity.caller_id,
                tool_name=tool_name,
                status="denied",
                request_id=req_id,
                args=args,
                error="Tool not in client allowed_tools whitelist",
            )
            return JSONResponse({
                "jsonrpc": "2.0",
                "error": {"code": -32003, "message": f"Forbidden: Tool '{tool_name}' not permitted"},
                "id": rpc_id,
            }, status_code=403)

        # Rate Limit check
        allowed, retry_after = self.rate_limiter.check(
            caller_id=identity.caller_id,
            tool_name=tool_name,
            rate_multiplier=identity.rate_multiplier,
        )
        if not allowed:
            self.audit_logger.log(
                caller_id=identity.caller_id,
                tool_name=tool_name,
                status="rate_limited",
                request_id=req_id,
                args=args,
                error=f"Rate limit exceeded. Retry after {retry_after:.1f}s",
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": f"Rate limit exceeded for tool '{tool_name}'. Retry after {retry_after:.1f}s",
                    },
                    "id": rpc_id,
                },
                status_code=429,
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

        # Execute Tool Handler
        handler = self._handlers[tool_name]
        try:
            import inspect
            if inspect.iscoroutinefunction(handler):
                raw_result = await handler(**args)
            else:
                raw_result = handler(**args)

            # Format raw result to MCP content array
            if isinstance(raw_result, list) and all(isinstance(x, dict) and "type" in x for x in raw_result):
                mcp_content = raw_result
            else:
                text_content = str(raw_result) if not isinstance(raw_result, str) else raw_result
                mcp_content = [{"type": "text", "text": text_content}]

            # Apply Data Redaction
            redacted_content, hits = self.redactor.redact_mcp_content(mcp_content)

            duration_ms = (time.monotonic() - start_time) * 1000.0
            self.audit_logger.log(
                caller_id=identity.caller_id,
                tool_name=tool_name,
                status="ok",
                request_id=req_id,
                args=args,
                duration_ms=duration_ms,
                result_count=len(redacted_content),
                redaction_hits=hits,
            )

            return JSONResponse({
                "jsonrpc": "2.0",
                "result": {"content": redacted_content, "isError": False},
                "id": rpc_id,
            })

        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000.0
            masked_err, _ = self.redactor.mask_text(str(e))
            self.audit_logger.log(
                caller_id=identity.caller_id,
                tool_name=tool_name,
                status="error",
                request_id=req_id,
                args=args,
                duration_ms=duration_ms,
                error=masked_err,
            )
            return JSONResponse({
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": f"Error executing tool: {masked_err}"}],
                    "isError": True,
                },
                "id": rpc_id,
            })

    async def health_check(self, request: Request) -> JSONResponse:
        return JSONResponse({"status": "healthy", "service": self.server_name, "version": self.server_version})

    def as_asgi_app(self) -> Starlette:
        """Create standard Starlette ASGI application."""
        routes = [
            Route("/mcp", self.handle_mcp_post, methods=["POST"]),
            Route("/health", self.health_check, methods=["GET"]),
        ]
        return Starlette(debug=False, routes=routes)
