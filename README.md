# Cynbit Backend Technical Audit & Hardened Reference Architecture

A passive backend security & performance assessment, non-intrusive single-request HTTP header/TLS auditor, and production-grade **Node.js / TypeScript (Express)** reference implementation demonstrating modern API hardening patterns.

> **Strict Passive Methodology:**  
> All documentation, middleware modules, and verification utilities in this repository strictly observe **passive, non-intrusive engineering practices**. `scripts/passive_audit.py` issues **at most one standard `GET` or `HEAD` request** per execution and contains zero fuzzing, enumeration, payload injection, or load-testing capabilities.

---

## Executive Summary

Modern web and SaaS backends face recurring architectural challenges across four boundaries:
1. **Edge & Transport Hygiene:** Missing or permissive HTTP security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `Permissions-Policy`), broad CORS policies lacking `Vary: Origin`, and leaked upstream server signatures (`X-Powered-By`, versioned `Server` banners).
2. **Abuse Resistance & Quota Transparency:** Public write endpoints lacking distributed sliding-window rate limits, standardized IETF `RateLimit-*` / `Retry-After` headers, and safe retry idempotency (`Idempotency-Key`).
3. **Ingestion Validation & Standardized Error Telemetry:** Permissive body limits, silent acceptance of unknown JSON keys, and inconsistent `4xx`/`5xx` error shapes instead of **RFC 9457 (`application/problem+json`)** correlated via `X-Request-ID`.
4. **Latency & Bandwidth Efficiency:** Uncompressed JSON responses, missing weak `ETag` conditional revalidation (`304 Not Modified`), missing CDN `s-maxage` + `stale-while-revalidate` directives, and `O(N)` `OFFSET` pagination degradation on deep datasets.

Full architectural analysis, categorized findings matrix, and target Mermaid sequence/topology diagrams are documented in **[`AUDIT_REPORT.md`](AUDIT_REPORT.md)**.

---

## Project Layout

```text
.
├── AUDIT_REPORT.md                 # Comprehensive Passive Backend Technical Audit Report
├── README.md                       # Documentation, quickstart, and Conventional Commits guide
├── .env.example                    # Environment configuration template
├── package.json                    # Node.js / TypeScript scripts and dependencies
├── tsconfig.json                   # Strict TypeScript compiler configuration
├── tsconfig.build.json             # Production build TypeScript configuration
├── scripts/
│   └── passive_audit.py            # Pure-stdlib Python single-request passive header/TLS auditor
├── src/
│   ├── app.ts                      # Deterministic hardened Express middleware pipeline
│   ├── server.ts                   # HTTP entrypoint with Redis/Memory store & graceful shutdown
│   ├── middleware/
│   │   ├── errorHandler.ts         # Correlation IDs + RFC 9457 Problem Details + 500 redaction
│   │   ├── rateLimiter.ts          # Atomic Redis Lua & in-memory sliding-window rate limiter
│   │   ├── securityHeaders.ts      # Strict Helmet CSP/HSTS, Permissions-Policy & allowlist CORS
│   │   └── validate.ts             # Zod .strict() validation, sanitization & byte-size guards
│   └── routes/
│       ├── dashboard.ts            # Interactive root console (GET /) with cryptographic CSP nonce
│       └── exampleApi.ts           # Keyset cursor pagination, weak ETag (304) & Idempotency-Key
└── tests/
    └── app.test.ts                 # Automated integration test suite (node:test)
```

---

## Quickstart

### Prerequisites
- **Node.js** `>= 20.0.0` (tested on Node.js v24)
- **Python** `>= 3.10` (uses standard library only — zero `pip` packages required)
- *(Optional)* **Redis** `>= 6.2` if testing distributed multi-instance rate limiting (`REDIS_URL`); automatically falls back to a bounded in-memory sliding-window store when omitted.

### 1. Install, Typecheck, Test & Run the Reference Backend

```bash
# Install dependencies
npm install

# Run strict TypeScript typechecking
npm run typecheck

# Execute the automated security & performance integration tests
npm test

# Start the development server and open http://localhost:3000 in your browser
cp .env.example .env
npm run dev
```

For production builds:

```bash
npm run build
NODE_ENV=production npm start
```

### 2. Inspect Reference Endpoints Locally

```bash
# 1. Paginated read with ETag, Cache-Control, RateLimit-*, and gzip/br support
curl -i -H "Accept-Encoding: br, gzip" "http://127.0.0.1:3000/api/v1/items?limit=5"

# 2. Conditional request returning 304 Not Modified (replace ETag value from step 1)
curl -i -H 'If-None-Match: W/"<etag-from-step-1>"' "http://127.0.0.1:3000/api/v1/items?limit=5"

# 3. Validated, idempotent state-mutating POST request
curl -i -X POST "http://127.0.0.1:3000/api/v1/contact" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: req-demo-0001" \
  -d '{
    "name": "Jane Doe",
    "email": "jane@cynbit.com",
    "subject": "Architecture Review",
    "message": "Verifying Zod strict validation and idempotent replay handling."
  }'
```

### 3. Run the Passive Header & Configuration Auditor

`scripts/passive_audit.py` performs **one** non-intrusive `GET` or `HEAD` request against an authorized URL (such as the local reference server above) and prints a Markdown audit checklist:

```bash
# Inspect the local reference server (single GET request)
python scripts/passive_audit.py http://127.0.0.1:3000/api/v1/items --origin https://cynbit.com

# Perform a HEAD-only check and export checklist to a file
python scripts/passive_audit.py http://127.0.0.1:3000/healthz --method HEAD --output local_header_check.md

# Emit structured JSON output
python scripts/passive_audit.py http://127.0.0.1:3000/api/v1/items --json
```

---

## Recommended Git Commit Sequence (Conventional Commits)

Rather than committing the entire repository as a single monolithic snapshot, execute the sequence below from the repository root to construct a clean, logical engineering history before pushing to GitHub:

```bash
# 1. Project scaffolding & TypeScript configuration
git add .gitignore .env.example package.json package-lock.json tsconfig.json tsconfig.build.json
git commit -m "chore: bootstrap TypeScript Express reference project configuration"

# 2. Technical audit report & architectural diagrams
git add AUDIT_REPORT.md
git commit -m "docs(audit): add passive backend technical audit report and target diagrams"

# 3. Centralized RFC 9457 error handling & correlation IDs
git add src/middleware/errorHandler.ts
git commit -m "feat(errors): implement RFC 9457 problem details handler and X-Request-ID tracing"

# 4. Transport security headers & strict allowlist CORS
git add src/middleware/securityHeaders.ts
git commit -m "sec(headers): enforce strict CSP, HSTS preload, Permissions-Policy, and allowlist CORS"

# 5. Distributed sliding-window rate limiting
git add src/middleware/rateLimiter.ts
git commit -m "sec(ratelimit): add Redis Lua sliding-window rate limiter with IETF RateLimit headers"

# 6. Ingestion schema validation & payload hardening
git add src/middleware/validate.ts
git commit -m "sec(validation): add strict Zod schema validation, sanitization, and payload caps"

# 7. High-efficiency cursor pagination, weak ETag (304), compression & idempotent routes
git add src/routes/exampleApi.ts src/app.ts src/server.ts
git commit -m "perf(api): implement keyset cursor pagination, weak ETag caching, compression, and idempotency"

# 8. Passive single-request HTTP header & TLS configuration auditor
git add scripts/passive_audit.py
git commit -m "feat(scripts): add strictly passive single-request HTTP header and TLS checklist auditor"

# 9. Automated integration test suite & repository documentation
git add tests/app.test.ts README.md
git commit -m "docs: add quickstart guide, integration test suite, and git workflow documentation"

# Push clean history to GitHub
git push origin main
```
