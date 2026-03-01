"""Gmail API v1 client — search, read, send, draft.

All functions take an OAuth2 access token and call the Gmail REST API
directly via httpx. Token is only used in the Authorization header and
never appears in content, logs, or error messages.

Results are UNTRUSTED external data — the executor tags them as
DataSource.WEB / TrustLevel.UNTRUSTED before returning to the planner.
"""

import base64
import html
import logging
import re
from dataclasses import dataclass
from email.mime.text import MIMEText
from urllib.parse import quote

import httpx

logger = logging.getLogger("sentinel.audit")

_GMAIL_BASE = "https://www.googleapis.com/gmail/v1/users/me"
_HTML_TAG_RE = re.compile(r"<[^>]+>")


class GmailError(Exception):
    """Error from Gmail API operations."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EmailSearchResult:
    """Summary of an email from a search result."""
    message_id: str
    thread_id: str
    subject: str
    sender: str
    date: str
    snippet: str


@dataclass
class EmailMessage:
    """Full email message with decoded body."""
    message_id: str
    thread_id: str
    subject: str
    sender: str
    to: str
    date: str
    body_text: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _gmail_request(
    method: str,
    url: str,
    token: str,
    timeout: int = 15,
    json_body: dict | None = None,
) -> httpx.Response:
    """Shared HTTP helper — injects Bearer token, classifies errors.

    Token only enters the Authorization header here — never in content,
    logs, or error messages.
    """
    headers = {"Authorization": f"Bearer {token}"}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await getattr(client, method.lower())(
                url,
                headers=headers,
                json=json_body,
            )
    except httpx.TimeoutException as exc:
        raise GmailError(f"Gmail API request timed out: {exc}") from exc
    except httpx.ConnectError as exc:
        raise GmailError(f"Cannot connect to Gmail API: {exc}") from exc

    if resp.status_code == 429:
        raise GmailError("Gmail API rate limited")
    if resp.status_code == 401:
        raise GmailError("Gmail API auth failed — token may be expired")
    if resp.status_code >= 500:
        raise GmailError(f"Gmail API error {resp.status_code}")
    if resp.status_code >= 400:
        raise GmailError(f"Gmail API client error {resp.status_code}")

    return resp


def _parse_headers(headers_list: list[dict]) -> dict[str, str]:
    """Extract Subject/From/To/Date from payload.headers list."""
    result = {}
    for h in headers_list:
        name_lower = h.get("name", "").lower()
        if name_lower in ("subject", "from", "to", "date"):
            result[name_lower] = h.get("value", "")
    return result


def _decode_body(payload: dict) -> str:
    """Recursive multipart traversal — prefers text/plain, falls back to text/html."""
    mime_type = payload.get("mimeType", "")

    # Direct body (non-multipart)
    body = payload.get("body", {})
    if body.get("data"):
        decoded = _base64url_decode(body["data"])
        if "html" in mime_type:
            return _sanitize_body(decoded)
        return decoded

    # Multipart — recurse through parts
    parts = payload.get("parts", [])
    plain_text = ""
    html_text = ""

    for part in parts:
        part_mime = part.get("mimeType", "")
        if part_mime == "text/plain":
            part_body = part.get("body", {})
            if part_body.get("data"):
                plain_text = _base64url_decode(part_body["data"])
        elif part_mime == "text/html":
            part_body = part.get("body", {})
            if part_body.get("data"):
                html_text = _base64url_decode(part_body["data"])
        elif part_mime.startswith("multipart/"):
            # Nested multipart — recurse
            nested = _decode_body(part)
            if nested:
                if not plain_text:
                    plain_text = nested

    if plain_text:
        return plain_text
    if html_text:
        return _sanitize_body(html_text)
    return ""


def _base64url_decode(data: str) -> str:
    """Decode base64url-encoded data (Gmail uses URL-safe base64 without padding)."""
    # Add padding if needed
    padded = data + "=" * (4 - len(data) % 4) if len(data) % 4 else data
    try:
        return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _sanitize_body(html_text: str) -> str:
    """Strip HTML tags, decode entities — for HTML-only emails."""
    text = _HTML_TAG_RE.sub("", html_text)
    text = html.unescape(text)
    # Collapse excessive whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" {2,}", " ", text)
    return text.strip()


def _truncate_body(body: str, max_length: int) -> str:
    """Truncate body to max_length with indicator."""
    if len(body) <= max_length:
        return body
    return body[:max_length] + "\n\n[... truncated]"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def search_emails(
    token: str,
    query: str,
    max_results: int = 20,
    timeout: int = 15,
) -> list[EmailSearchResult]:
    """Search Gmail messages by query string.

    Two-step: list message IDs, then fetch metadata headers per result.
    """
    # Step 1: Get message IDs matching query
    # N-002: URL-encode query to prevent parameter injection via & or = in search terms
    list_url = f"{_GMAIL_BASE}/messages"
    resp = await _gmail_request(
        "get",
        f"{list_url}?q={quote(query, safe='')}&maxResults={max_results}",
        token,
        timeout,
    )
    data = resp.json()
    messages = data.get("messages", [])

    if not messages:
        return []

    # Step 2: Fetch metadata for each message
    results = []
    for msg_ref in messages:
        msg_id = msg_ref["id"]
        detail_url = (
            f"{_GMAIL_BASE}/messages/{msg_id}"
            "?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date"
        )
        detail_resp = await _gmail_request("get", detail_url, token, timeout)
        detail = detail_resp.json()

        headers = _parse_headers(detail.get("payload", {}).get("headers", []))
        results.append(EmailSearchResult(
            message_id=msg_id,
            thread_id=detail.get("threadId", ""),
            subject=headers.get("subject", "(no subject)"),
            sender=headers.get("from", ""),
            date=headers.get("date", ""),
            snippet=detail.get("snippet", ""),
        ))

    return results


async def read_email(
    token: str,
    message_id: str,
    max_body_length: int = 50000,
    timeout: int = 15,
) -> EmailMessage:
    """Read a full email message by ID, decoding the body."""
    url = f"{_GMAIL_BASE}/messages/{message_id}?format=full"
    resp = await _gmail_request("get", url, token, timeout)
    data = resp.json()

    payload = data.get("payload", {})
    headers = _parse_headers(payload.get("headers", []))
    body = _decode_body(payload)
    body = _truncate_body(body, max_body_length)

    return EmailMessage(
        message_id=data.get("id", message_id),
        thread_id=data.get("threadId", ""),
        subject=headers.get("subject", "(no subject)"),
        sender=headers.get("from", ""),
        to=headers.get("to", ""),
        date=headers.get("date", ""),
        body_text=body,
    )


async def send_email(
    token: str,
    to: str,
    subject: str,
    body: str,
    thread_id: str | None = None,
    timeout: int = 15,
) -> str:
    """Send an email (or reply if thread_id is set). Returns message_id."""
    # Build RFC 2822 MIME message
    msg = MIMEText(body, "plain", "utf-8")
    msg["To"] = to
    msg["Subject"] = subject

    # Base64url encode the MIME message
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")

    payload: dict = {"raw": raw}
    if thread_id:
        payload["threadId"] = thread_id

    url = f"{_GMAIL_BASE}/messages/send"
    resp = await _gmail_request("post", url, token, timeout, json_body=payload)
    data = resp.json()
    return data.get("id", "")


async def create_draft(
    token: str,
    to: str,
    subject: str,
    body: str,
    timeout: int = 15,
) -> str:
    """Create a draft email. Returns draft_id."""
    msg = MIMEText(body, "plain", "utf-8")
    msg["To"] = to
    msg["Subject"] = subject

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")

    url = f"{_GMAIL_BASE}/drafts"
    resp = await _gmail_request(
        "post", url, token, timeout,
        json_body={"message": {"raw": raw}},
    )
    data = resp.json()
    return data.get("id", "")


# ---------------------------------------------------------------------------
# Formatters — produce LLM-friendly text
# ---------------------------------------------------------------------------

def format_search_results(results: list[EmailSearchResult]) -> str:
    """Format search results as numbered text for LLM consumption."""
    if not results:
        return "No emails found."

    lines = []
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r.subject}")
        lines.append(f"   From: {r.sender}")
        lines.append(f"   Date: {r.date}")
        lines.append(f"   ID: {r.message_id}")
        if r.snippet:
            lines.append(f"   Preview: {r.snippet}")
        lines.append("")
    return "\n".join(lines).rstrip()


def format_email(msg: EmailMessage) -> str:
    """Format a full email as structured text."""
    lines = [
        f"Subject: {msg.subject}",
        f"From: {msg.sender}",
        f"To: {msg.to}",
        f"Date: {msg.date}",
        f"Message ID: {msg.message_id}",
        f"Thread ID: {msg.thread_id}",
        "",
        msg.body_text,
    ]
    return "\n".join(lines)
