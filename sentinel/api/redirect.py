"""Minimal ASGI app that redirects all HTTP requests to HTTPS.

Runs as a second uvicorn server on the HTTP port during lifespan startup.
Only started when TLS is enabled (tls_cert_file is set) and redirect_enabled is True.
"""

from sentinel.core.config import settings


class HTTPSRedirectApp:
    """ASGI app that returns 301 redirects to the HTTPS equivalent URL."""

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return

        # Build redirect URL from the request
        headers = dict(scope.get("headers", []))
        host_header = headers.get(b"host", b"localhost").decode()
        # Strip any existing port from the host
        host = host_header.split(":")[0]
        path = scope.get("path", "/")
        query = scope.get("query_string", b"")

        location = f"https://{host}:{settings.external_https_port}{path}"
        if query:
            location += f"?{query.decode()}"

        await send({
            "type": "http.response.start",
            "status": 301,
            "headers": [
                [b"location", location.encode()],
                [b"content-type", b"text/plain"],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": b"Redirecting to HTTPS...\n",
        })
