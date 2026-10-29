#!/usr/bin/env python3
"""
Passive HTTP Header, TLS, Caching & CORS Configuration Auditor.

Performs strictly ONE non-intrusive HTTP GET or HEAD request against an authorized
target URL (e.g., local staging server or owned public endpoint) and emits a
structured Markdown security & performance checklist.

Safety Guarantees:
- Zero fuzzing, directory enumeration, port scanning, or payload injection.
- Exactly one HTTP request per invocation (redirects are reported, not chased).
- Cookie values in `Set-Cookie` headers are automatically redacted before display.
- Pure Python 3.10+ standard library implementation (no third-party dependencies).
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import ssl
import sys
import time
import urllib.parse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Literal

StatusLevel = Literal["PASS", "WARN", "FAIL", "INFO"]

STATUS_BADGE: dict[StatusLevel, str] = {
    "PASS": "[x] **PASS**",
    "WARN": "[ ] **WARN**",
    "FAIL": "[ ] **FAIL**",
    "INFO": "[-] **INFO**",
}


@dataclass(frozen=True)
class CheckResult:
    category: str
    control: str
    status: StatusLevel
    observed: str
    recommendation: str


@dataclass(frozen=True)
class AuditReport:
    target_url: str
    method: str
    timestamp_utc: str
    http_status: int
    http_reason: str
    http_version: str
    tls_version: str | None
    tls_cipher: str | None
    total_ttfb_ms: float
    request_ttfb_ms: float
    checks: list[CheckResult]


def redact_set_cookie(raw_cookie: str) -> str:
    """Redacts the cookie value while preserving the cookie name and security flags."""
    parts = [segment.strip() for segment in raw_cookie.split(";")]
    if not parts:
        return "<empty>"
    name_val = parts[0]
    cookie_name = name_val.split("=", 1)[0].strip() if "=" in name_val else name_val
    flags = "; ".join(parts[1:])
    return f"{cookie_name}=<redacted>" + (f"; {flags}" if flags else "")


def evaluate_hsts(value: str | None, is_https: bool) -> CheckResult:
    if not value:
        return CheckResult(
            category="Security Headers",
            control="Strict-Transport-Security (HSTS)",
            status="FAIL" if is_https else "WARN",
            observed="Missing",
            recommendation=(
                "Set `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` "
                "on HTTPS responses."
            ),
        )

    lower = value.lower()
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", lower)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    has_subdomains = "includesubdomains" in lower

    if max_age >= 31_536_000 and has_subdomains:
        return CheckResult(
            category="Security Headers",
            control="Strict-Transport-Security (HSTS)",
            status="PASS",
            observed=f"`{value}`",
            recommendation="Meets >= 1-year `max-age` with `includeSubDomains`.",
        )

    return CheckResult(
        category="Security Headers",
        control="Strict-Transport-Security (HSTS)",
        status="WARN",
        observed=f"`{value}`",
        recommendation="Increase `max-age` to >= `31536000` (ideally `63072000`) and include `includeSubDomains`.",
    )


def evaluate_csp(value: str | None) -> CheckResult:
    if not value:
        return CheckResult(
            category="Security Headers",
            control="Content-Security-Policy (CSP)",
            status="FAIL",
            observed="Missing",
            recommendation=(
                "Define a strict CSP (`default-src 'none'; frame-ancestors 'none'` for JSON APIs, "
                "or nonce-based `script-src` for HTML applications)."
            ),
        )

    lower = value.lower()
    weak_tokens = [tok for tok in ("'unsafe-inline'", "'unsafe-eval'") if tok in lower]
    has_frame_ancestors = "frame-ancestors" in lower

    if weak_tokens:
        return CheckResult(
            category="Security Headers",
            control="Content-Security-Policy (CSP)",
            status="WARN",
            observed=f"`{value}`",
            recommendation=(
                f"Replace permissive directive(s) {', '.join(weak_tokens)} with cryptographic nonces or hashes."
            ),
        )

    if not has_frame_ancestors:
        return CheckResult(
            category="Security Headers",
            control="Content-Security-Policy (CSP)",
            status="WARN",
            observed=f"`{value}`",
            recommendation="Add explicit `frame-ancestors 'none'` (or `'self'`) directive for clickjacking protection.",
        )

    return CheckResult(
        category="Security Headers",
        control="Content-Security-Policy (CSP)",
        status="PASS",
        observed=f"`{value}`",
        recommendation="Strict CSP present without `'unsafe-inline'`/`'unsafe-eval'` and includes `frame-ancestors`.",
    )


def evaluate_headers(
    headers_lower: dict[str, str],
    set_cookies: list[str],
    is_https: bool,
    tls_version: str | None,
    tls_cipher: str | None,
    request_ttfb_ms: float,
) -> list[CheckResult]:
    checks: list[CheckResult] = []

    # 1. Transport & TLS
    if is_https:
        tls_ok = tls_version in {"TLSv1.3", "TLSv1.2"}
        checks.append(
            CheckResult(
                category="Transport & TLS",
                control="TLS Protocol & Cipher Negotiation",
                status="PASS" if tls_ok else "FAIL",
                observed=f"Protocol: `{tls_version or 'unknown'}`, Cipher: `{tls_cipher or 'unknown'}`",
                recommendation=(
                    "Prefer TLS 1.3 with AEAD cipher suites; disable TLS 1.0/1.1."
                    if not tls_ok
                    else "Modern TLS protocol negotiated."
                ),
            )
        )
    else:
        checks.append(
            CheckResult(
                category="Transport & TLS",
                control="HTTPS Transport Encryption",
                status="INFO",
                observed="Plaintext HTTP target inspected (expected only for localhost/loopback).",
                recommendation="Terminate TLS 1.2/1.3 at edge/ingress in staging and production.",
            )
        )

    # 2. Core HTTP Security Headers
    checks.append(evaluate_hsts(headers_lower.get("strict-transport-security"), is_https))
    checks.append(evaluate_csp(headers_lower.get("content-security-policy")))

    xcto = headers_lower.get("x-content-type-options")
    checks.append(
        CheckResult(
            category="Security Headers",
            control="X-Content-Type-Options",
            status="PASS" if (xcto or "").lower() == "nosniff" else "FAIL",
            observed=f"`{xcto}`" if xcto else "Missing",
            recommendation=(
                "Prevents MIME-sniffing content-type confusion."
                if (xcto or "").lower() == "nosniff"
                else "Set `X-Content-Type-Options: nosniff` on all responses."
            ),
        )
    )

    xfo = headers_lower.get("x-frame-options")
    csp_has_fa = "frame-ancestors" in (headers_lower.get("content-security-policy") or "").lower()
    xfo_ok = (xfo or "").upper() in {"DENY", "SAMEORIGIN"}
    checks.append(
        CheckResult(
            category="Security Headers",
            control="X-Frame-Options",
            status="PASS" if xfo_ok else ("WARN" if csp_has_fa else "FAIL"),
            observed=f"`{xfo}`" if xfo else "Missing",
            recommendation=(
                "Legacy framing defense aligned with CSP `frame-ancestors`."
                if xfo_ok
                else "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) alongside CSP `frame-ancestors`."
            ),
        )
    )

    referrer = headers_lower.get("referrer-policy")
    safe_referrers = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    checks.append(
        CheckResult(
            category="Security Headers",
            control="Referrer-Policy",
            status="PASS" if (referrer or "").lower() in safe_referrers else "WARN",
            observed=f"`{referrer}`" if referrer else "Missing",
            recommendation=(
                "Restrictive referrer leakage policy configured."
                if (referrer or "").lower() in safe_referrers
                else "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`."
            ),
        )
    )

    perms = headers_lower.get("permissions-policy")
    checks.append(
        CheckResult(
            category="Security Headers",
            control="Permissions-Policy",
            status="PASS" if perms else "WARN",
            observed=f"`{perms}`" if perms else "Missing",
            recommendation=(
                "Explicit browser feature delegation policy present."
                if perms
                else "Set `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`."
            ),
        )
    )

    # 3. CORS Policy Granularity
    acao = headers_lower.get("access-control-allow-origin")
    acac = (headers_lower.get("access-control-allow-credentials") or "").lower()
    vary = headers_lower.get("vary") or ""
    if acao is None:
        checks.append(
            CheckResult(
                category="CORS Policy",
                control="Access-Control-Allow-Origin",
                status="PASS",
                observed="Not emitted (same-origin default or no `Origin` supplied)",
                recommendation="Maintain explicit origin allowlisting and `Vary: Origin` when cross-origin access is enabled.",
            )
        )
    elif acao.strip() == "*":
        checks.append(
            CheckResult(
                category="CORS Policy",
                control="Access-Control-Allow-Origin",
                status="FAIL" if acac == "true" else "WARN",
                observed=f"`Access-Control-Allow-Origin: {acao}` (Credentials: `{acac or 'absent'}`)",
                recommendation="Replace wildcard `*` with an explicit origin allowlist on authenticated or sensitive APIs.",
            )
        )
    else:
        has_vary_origin = "origin" in vary.lower() or vary.strip() == "*"
        checks.append(
            CheckResult(
                category="CORS Policy",
                control="Access-Control-Allow-Origin & Vary",
                status="PASS" if has_vary_origin else "WARN",
                observed=f"`Access-Control-Allow-Origin: {acao}`, `Vary: {vary or 'Missing'}`",
                recommendation=(
                    "Explicit origin paired with `Vary: Origin` prevents shared-cache poisoning."
                    if has_vary_origin
                    else "Include `Vary: Origin` whenever dynamically reflecting allowed origins."
                ),
            )
        )

    # 4. Server Fingerprinting Leakage
    server_hdr = headers_lower.get("server")
    has_version_leak = bool(server_hdr and re.search(r"\d+\.\d+", server_hdr))
    checks.append(
        CheckResult(
            category="Fingerprinting",
            control="Server Banner Exposure",
            status="WARN" if has_version_leak else "PASS",
            observed=f"`{server_hdr}`" if server_hdr else "Omitted",
            recommendation=(
                "Suppress exact software version tokens (`server_tokens off;` / proxy header scrubbing)."
                if has_version_leak
                else "No detailed server version numbers exposed."
            ),
        )
    )

    leaky_headers = [
        name
        for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime")
        if name in headers_lower
    ]
    checks.append(
        CheckResult(
            category="Fingerprinting",
            control="Framework Signature Headers (X-Powered-By)",
            status="WARN" if leaky_headers else "PASS",
            observed=(
                ", ".join(f"`{h}: {headers_lower[h]}`" for h in leaky_headers)
                if leaky_headers
                else "Absent"
            ),
            recommendation=(
                "Disable framework signature headers (e.g., `app.disable('x-powered-by')`)."
                if leaky_headers
                else "Framework signature headers cleanly suppressed."
            ),
        )
    )

    # 5. Session / Cookie Hygiene (Passive)
    if set_cookies:
        insecure_cookies: list[str] = []
        redacted_list = [redact_set_cookie(c) for c in set_cookies]
        for raw_c in set_cookies:
            low_c = raw_c.lower()
            if "httponly" not in low_c or "secure" not in low_c or "samesite=" not in low_c:
                insecure_cookies.append(redact_set_cookie(raw_c))
        checks.append(
            CheckResult(
                category="Session Hygiene",
                control="Set-Cookie Attributes",
                status="WARN" if insecure_cookies else "PASS",
                observed="; ".join(f"`{rc}`" for rc in redacted_list),
                recommendation=(
                    "Ensure session cookies include `Secure`, `HttpOnly`, `SameSite=Lax|Strict`, and `__Host-` prefix."
                    if insecure_cookies
                    else "All observed cookies include `Secure`, `HttpOnly`, and `SameSite` flags."
                ),
            )
        )

    # 6. Caching, Conditional Requests & Compression
    cache_control = headers_lower.get("cache-control")
    checks.append(
        CheckResult(
            category="Caching & Performance",
            control="Cache-Control Policy",
            status="PASS" if cache_control else "WARN",
            observed=f"`{cache_control}`" if cache_control else "Missing",
            recommendation=(
                "Explicit caching directive declared."
                if cache_control
                else "Declare explicit `Cache-Control` (`no-store` for private/dynamic data; `public, s-maxage=...` for cacheable resources)."
            ),
        )
    )

    etag = headers_lower.get("etag")
    last_modified = headers_lower.get("last-modified")
    is_no_store = "no-store" in (cache_control or "").lower()
    checks.append(
        CheckResult(
            category="Caching & Performance",
            control="Conditional Revalidation (ETag / Last-Modified)",
            status="PASS" if (etag or last_modified or is_no_store) else "WARN",
            observed=(
                f"ETag: `{etag}`"
                if etag
                else (
                    f"Last-Modified: `{last_modified}`"
                    if last_modified
                    else ("Intentionally omitted (`no-store`)" if is_no_store else "Missing")
                )
            ),
            recommendation=(
                "Conditional revalidation (`304 Not Modified`) or explicit `no-store` properly aligned."
                if (etag or last_modified or is_no_store)
                else "Emit weak/strong `ETag` headers on cacheable GET endpoints to save bandwidth via `304 Not Modified`."
            ),
        )
    )

    encoding = headers_lower.get("content-encoding")
    content_length = int(headers_lower.get("content-length", "0") or "0")
    compressed_ok = (encoding or "").lower() in {"br", "gzip", "zstd"}
    checks.append(
        CheckResult(
            category="Caching & Performance",
            control="Payload Compression (Content-Encoding)",
            status="PASS" if (compressed_ok or (0 <= content_length < 1024 and encoding is None)) else "WARN",
            observed=f"`{encoding}`" if encoding else f"Uncompressed (`Content-Length: {content_length or 'chunked/0'}`)",
            recommendation=(
                f"Compressed transfer active (`{encoding}`)."
                if compressed_ok
                else "Enable Brotli (`br`) and `gzip` compression for text/JSON payloads >= 1 KiB."
            ),
        )
    )

    # 7. Observability, Rate Limiting & Latency
    req_id = headers_lower.get("x-request-id") or headers_lower.get("traceparent")
    rl_limit = headers_lower.get("ratelimit-limit") or headers_lower.get("x-ratelimit-limit")
    checks.append(
        CheckResult(
            category="Observability & Resilience",
            control="Correlation & Rate-Limit Headers",
            status="PASS" if (req_id and rl_limit) else "INFO",
            observed=(
                f"Trace Header: `{'present' if req_id else 'absent'}`, "
                f"RateLimit Header: `{rl_limit if rl_limit else 'absent'}`"
            ),
            recommendation="Expose `X-Request-ID` for client error correlation and IETF `RateLimit-*` headers for quota transparency.",
        )
    )

    ttfb_status: StatusLevel = (
        "PASS" if request_ttfb_ms < 250.0 else ("WARN" if request_ttfb_ms < 600.0 else "FAIL")
    )
    checks.append(
        CheckResult(
            category="Caching & Performance",
            control="Time To First Byte (Request TTFB)",
            status=ttfb_status,
            observed=f"`{request_ttfb_ms:.1f} ms`",
            recommendation=(
                "Sub-250ms backend response latency."
                if ttfb_status == "PASS"
                else "Investigate CDN edge caching (`s-maxage`), connection pooling, and indexed query plans to keep TTFB < 250ms."
            ),
        )
    )

    return checks


def run_single_passive_request(
    url: str,
    method: Literal["GET", "HEAD"] = "GET",
    origin: str | None = None,
    timeout_seconds: float = 10.0,
) -> AuditReport:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid target URL '{url}'. Must specify http:// or https:// and a hostname.")

    is_https = parsed.scheme == "https"
    port = parsed.port or (443 if is_https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    request_headers: dict[str, str] = {
        "User-Agent": "CynbitPassiveHeaderAuditor/1.0 (+passive-single-request)",
        "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
        "Accept-Encoding": "br, gzip, deflate",
        "Connection": "close",
    }
    if origin:
        request_headers["Origin"] = origin

    conn: http.client.HTTPConnection | http.client.HTTPSConnection
    if is_https:
        ssl_ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            port=port,
            timeout=timeout_seconds,
            context=ssl_ctx,
        )
    else:
        conn = http.client.HTTPConnection(
            parsed.hostname,
            port=port,
            timeout=timeout_seconds,
        )

    tls_version: str | None = None
    tls_cipher: str | None = None

    t_total_start = time.perf_counter()
    try:
        conn.connect()
        if is_https and isinstance(conn.sock, ssl.SSLSocket):
            tls_version = conn.sock.version()
            cipher_info = conn.sock.cipher()
            tls_cipher = cipher_info[0] if cipher_info else None

        t_req_start = time.perf_counter()
        conn.request(method, path, headers=request_headers)
        resp = conn.getresponse()
        t_first_byte = time.perf_counter()

        total_ttfb_ms = (t_first_byte - t_total_start) * 1000.0
        request_ttfb_ms = (t_first_byte - t_req_start) * 1000.0

        # Read at most 4 KiB to allow clean socket teardown without downloading large bodies
        if method == "GET":
            resp.read(4096)

        raw_headers = resp.getheaders()
        headers_lower = {k.lower(): v for k, v in raw_headers}
        set_cookies = resp.msg.get_all("Set-Cookie") or []
        http_version = "HTTP/1.1" if resp.version == 11 else "HTTP/1.0"

        checks = evaluate_headers(
            headers_lower=headers_lower,
            set_cookies=set_cookies,
            is_https=is_https,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            request_ttfb_ms=request_ttfb_ms,
        )

        return AuditReport(
            target_url=url,
            method=method,
            timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            http_status=resp.status,
            http_reason=resp.reason,
            http_version=http_version,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            total_ttfb_ms=round(total_ttfb_ms, 2),
            request_ttfb_ms=round(request_ttfb_ms, 2),
            checks=checks,
        )
    finally:
        conn.close()


def format_markdown_report(report: AuditReport) -> str:
    pass_count = sum(1 for c in report.checks if c.status == "PASS")
    warn_count = sum(1 for c in report.checks if c.status == "WARN")
    fail_count = sum(1 for c in report.checks if c.status == "FAIL")

    lines = [
        "# Passive HTTP Header & Transport Audit Checklist",
        "",
        f"- **Target URL:** `{report.target_url}`",
        f"- **HTTP Method:** `{report.method}` *(single non-intrusive request)*",
        f"- **Observed Status:** `{report.http_status} {report.http_reason}` (`{report.http_version}`)",
        f"- **TLS Handshake:** `{report.tls_version or 'N/A (HTTP)'}`"
        + (f" / `{report.tls_cipher}`" if report.tls_cipher else ""),
        f"- **Latency (TTFB):** `{report.request_ttfb_ms:.2f} ms` *(Total incl. connect/TLS: `{report.total_ttfb_ms:.2f} ms`)*",
        f"- **Timestamp (UTC):** `{report.timestamp_utc}`",
        f"- **Summary Tallies:** **{pass_count}** Passed | **{warn_count}** Warnings | **{fail_count}** Failed",
        "",
        "## Control Checklist",
        "",
    ]

    for check in report.checks:
        badge = STATUS_BADGE[check.status]
        lines.append(f"- {badge} **[{check.category}] {check.control}**")
        lines.append(f"  - *Observed:* {check.observed}")
        lines.append(f"  - *Guidance:* {check.recommendation}")

    lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Perform a single passive GET/HEAD request to evaluate HTTP security headers, "
            "TLS negotiation, server fingerprinting, CORS, caching, and TTFB."
        )
    )
    parser.add_argument(
        "url",
        help="Target URL to inspect passively (e.g., http://127.0.0.1:3000/api/v1/items)",
    )
    parser.add_argument(
        "--method",
        choices=["GET", "HEAD"],
        default="GET",
        help="HTTP method for the single passive request (default: GET)",
    )
    parser.add_argument(
        "--origin",
        default=None,
        help="Optional Origin header to passively observe CORS response headers",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Socket timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of Markdown",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional file path to write the rendered output",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = run_single_passive_request(
            url=args.url,
            method=args.method,
            origin=args.origin,
            timeout_seconds=args.timeout,
        )
    except Exception as exc:
        print(f"Error performing passive request to '{args.url}': {exc}", file=sys.stderr)
        return 1

    rendered = (
        json.dumps(asdict(report), indent=2)
        if args.json
        else format_markdown_report(report)
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered + ("\n" if not rendered.endswith("\n") else ""))
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
