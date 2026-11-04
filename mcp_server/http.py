"""The MCP server over HTTP (MCP's streamable HTTP transport), for clients that connect to the hosted
app instead of running it locally:

  claude mcp add --transport http recon https://<host>/mcp --header "Authorization: Bearer <token>"

Same ten tools and the same data as the stdio server. The tools act for RECON_USER, so a list Claude
builds is the list that user opens in the app. Every request needs RECON_MCP_TOKEN as a bearer token;
without one configured, the endpoint refuses everything.

  RECON_MCP_TOKEN  the bearer token clients send (generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`)
  RECON_MCP_HOSTS  host names the endpoint answers to, comma-separated (DNS-rebinding protection)
"""
import hmac
import json
import os

from mcp.server.transport_security import TransportSecuritySettings

from mcp_server.server import mcp

TOKEN = os.environ.get("RECON_MCP_TOKEN", "")
HOSTS = [h.strip() for h in os.environ.get("RECON_MCP_HOSTS", "localhost:8787,127.0.0.1:8787").split(",") if h.strip()]

# stateless with JSON responses: every call is one POST, which passes cleanly through nginx and Funnel
mcp_app = mcp.streamable_http_app(
    stateless_http=True, json_response=True, streamable_http_path="/mcp",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=HOSTS),
)


async def _deny(send, status, message):
    body = json.dumps({"error": message}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]})
    await send({"type": "http.response.body", "body": body})


async def app(scope, receive, send):
    """The MCP endpoint behind a bearer token (checked in constant time)."""
    if scope["type"] == "http":
        auth = dict(scope.get("headers") or []).get(b"authorization", b"").decode()
        if not TOKEN or not hmac.compare_digest(auth, f"Bearer {TOKEN}"):
            return await _deny(send, 401, "a valid bearer token is required")
    return await mcp_app(scope, receive, send)
