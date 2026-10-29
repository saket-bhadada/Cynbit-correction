import crypto from 'node:crypto';
import { Router, type Request, type Response } from 'express';

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderDashboardHtml(nonce: string, requestId: string): string {
  const safeRequestId = escapeHtml(requestId);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Cynbit — Hardened Backend Reference Console</title>
  <style nonce="${nonce}">
    :root {
      --bg: #0b1020;
      --surface: #121931;
      --surface-alt: #182242;
      --border: #26345e;
      --text: #e6ecff;
      --muted: #9aa8d1;
      --accent: #4f8cff;
      --accent-hover: #3a78f0;
      --ok: #22c55e;
      --warn: #f59e0b;
      --err: #ef4444;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      line-height: 1.5;
    }
    header {
      border-bottom: 1px solid var(--border);
      background: var(--surface);
      padding: 1.25rem 2rem;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }
    header h1 {
      margin: 0;
      font-size: 1.2rem;
      font-weight: 650;
      letter-spacing: -0.01em;
    }
    header p {
      margin: 0.25rem 0 0;
      font-size: 0.85rem;
      color: var(--muted);
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.4rem 0.8rem;
      border-radius: 999px;
      background: var(--surface-alt);
      border: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 0.78rem;
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--ok);
    }
    main {
      max-width: 1240px;
      margin: 0 auto;
      padding: 1.75rem 2rem 3rem;
      display: grid;
      gap: 1.5rem;
    }
    .grid-two {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 1.5rem;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem 1.4rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .card h2 {
      margin: 0;
      font-size: 1rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
    }
    .card p.desc {
      margin: 0;
      font-size: 0.84rem;
      color: var(--muted);
    }
    .btn-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem;
    }
    button {
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 6px;
      padding: 0.48rem 0.85rem;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s ease;
    }
    button:hover:not(:disabled) { background: var(--accent-hover); }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    button.secondary {
      background: var(--surface-alt);
      border: 1px solid var(--border);
      color: var(--text);
    }
    button.secondary:hover:not(:disabled) { background: #22305c; }
    .meta-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 0.6rem;
      font-family: var(--mono);
      font-size: 0.76rem;
      color: var(--muted);
    }
    .badge {
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-family: var(--mono);
      font-size: 0.74rem;
      font-weight: 600;
    }
    .badge-ok { background: rgba(34, 197, 94, 0.16); color: #4ade80; }
    .badge-warn { background: rgba(245, 158, 11, 0.18); color: #fbbf24; }
    .badge-err { background: rgba(239, 68, 68, 0.18); color: #f87171; }
    pre {
      margin: 0;
      padding: 0.9rem;
      border-radius: 8px;
      background: #080c18;
      border: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 0.77rem;
      overflow-x: auto;
      max-height: 300px;
      color: #d3e0ff;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
    }
    th, td {
      text-align: left;
      padding: 0.48rem 0.6rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 600; width: 32%; }
    td code {
      font-family: var(--mono);
      font-size: 0.75rem;
      word-break: break-all;
      color: #b9ceff;
    }
    .form-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.65rem;
    }
    .form-grid .full { grid-column: 1 / -1; }
    label {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
      font-size: 0.76rem;
      color: var(--muted);
    }
    input, textarea {
      background: #080c18;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.45rem 0.6rem;
      color: var(--text);
      font-family: var(--sans);
      font-size: 0.82rem;
    }
    textarea { resize: vertical; min-height: 62px; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Cynbit — Hardened Backend Reference Architecture</h1>
      <p>Interactive console secured via per-request cryptographic CSP nonce (zero <code>'unsafe-inline'</code>)</p>
    </div>
    <div class="status-pill">
      <span class="dot"></span>
      <span>Boot X-Request-ID: <strong id="boot-req-id">${safeRequestId}</strong></span>
    </div>
  </header>

  <main>
    <section class="card">
      <h2>
        <span>1. Live HTTP Security, Caching &amp; Rate-Limit Headers</span>
        <button class="secondary" id="btn-refresh-headers" type="button">Re-Inspect Headers</button>
      </h2>
      <p class="desc">
        Passively inspected from a live <code>GET /api/v1/items?limit=3</code> call against this Express pipeline.
      </p>
      <table>
        <tbody id="headers-tbody">
          <tr><td colspan="2">Inspecting response headers...</td></tr>
        </tbody>
      </table>
    </section>

    <div class="grid-two">
      <section class="card">
        <h2>2. Cursor Pagination &amp; Weak ETag Explorer</h2>
        <p class="desc">
          Tests keyset pagination (<code>GET /api/v1/items</code>) and conditional <code>If-None-Match</code> (<code>304 Not Modified</code>).
        </p>
        <div class="btn-row">
          <button id="btn-page-first" type="button">Fetch Page 1 (limit=5)</button>
          <button id="btn-page-next" class="secondary" type="button" disabled>Next Cursor Page</button>
          <button id="btn-etag-check" class="secondary" type="button" disabled>Send If-None-Match (304)</button>
        </div>
        <div class="meta-bar" id="items-meta">Ready.</div>
        <pre id="items-output">// Click "Fetch Page 1" to inspect keyset pagination &amp; ETag behavior</pre>
      </section>

      <section class="card">
        <h2>3. Zod Validation, Rate-Limit &amp; Idempotency Sandbox</h2>
        <p class="desc">
          Tests <code>POST /api/v1/contact</code> with strict Zod schema enforcement, <code>Idempotency-Key</code> replay protection, and RFC 9457 errors.
        </p>
        <div class="form-grid">
          <label>
            Name
            <input id="inp-name" type="text" value="Alice Security" />
          </label>
          <label>
            Email
            <input id="inp-email" type="email" value="alice@cynbit.com" />
          </label>
          <label>
            Subject
            <input id="inp-subject" type="text" value="Backend Architecture Verification" />
          </label>
          <label>
            Idempotency-Key
            <input id="inp-idem" type="text" value="idem-console-0001" />
          </label>
          <label class="full">
            Message
            <textarea id="inp-message">Verifying strict Zod validation, sliding-window rate limits, and idempotent replay safety.</textarea>
          </label>
        </div>
        <div class="btn-row">
          <button id="btn-post-valid" type="button">Submit POST (201 / Replay)</button>
          <button id="btn-new-idem" class="secondary" type="button">New Idempotency Key</button>
          <button id="btn-post-invalid" class="secondary" type="button">Trigger 422 Validation Error</button>
          <button id="btn-trigger-404" class="secondary" type="button">Trigger 404 Problem Details</button>
        </div>
        <div class="meta-bar" id="contact-meta">Ready.</div>
        <pre id="contact-output">// Submit a valid or invalid request to inspect RFC 9457 &amp; Idempotency headers</pre>
      </section>
    </div>
  </main>

  <script nonce="${nonce}">
    (function () {
      const headersTbody = document.getElementById('headers-tbody');
      const itemsMeta = document.getElementById('items-meta');
      const itemsOutput = document.getElementById('items-output');
      const btnPageNext = document.getElementById('btn-page-next');
      const btnEtagCheck = document.getElementById('btn-etag-check');
      const contactMeta = document.getElementById('contact-meta');
      const contactOutput = document.getElementById('contact-output');
      const inpIdem = document.getElementById('inp-idem');

      let lastNextCursor = null;
      let lastEtag = null;
      let lastItemsUrl = '/api/v1/items?limit=5';

      function statusBadgeClass(status) {
        if (status >= 200 && status < 400) return 'badge badge-ok';
        if (status === 429 || status === 422) return 'badge badge-warn';
        return 'badge badge-err';
      }

      function renderMeta(el, status, elapsedMs, extraText) {
        el.textContent = '';
        const badge = document.createElement('span');
        badge.className = statusBadgeClass(status);
        badge.textContent = 'HTTP ' + status;
        el.appendChild(badge);

        const info = document.createElement('span');
        info.textContent = elapsedMs.toFixed(1) + ' ms' + (extraText ? ' | ' + extraText : '');
        el.appendChild(info);
      }

      async function inspectSecurityHeaders() {
        const res = await fetch('/api/v1/items?limit=3');
        const trackedHeaders = [
          'strict-transport-security',
          'content-security-policy',
          'x-content-type-options',
          'x-frame-options',
          'referrer-policy',
          'permissions-policy',
          'cache-control',
          'etag',
          'vary',
          'ratelimit-limit',
          'ratelimit-remaining',
          'ratelimit-policy',
          'x-request-id'
        ];

        headersTbody.textContent = '';
        trackedHeaders.forEach((name) => {
          const tr = document.createElement('tr');
          const th = document.createElement('th');
          th.textContent = name;
          const td = document.createElement('td');
          const code = document.createElement('code');
          code.textContent = res.headers.get(name) || '(absent)';
          td.appendChild(code);
          tr.appendChild(th);
          tr.appendChild(td);
          headersTbody.appendChild(tr);
        });
      }

      async function fetchItems(url, ifNoneMatch) {
        const headers = {};
        if (ifNoneMatch) headers['If-None-Match'] = ifNoneMatch;

        const t0 = performance.now();
        const res = await fetch(url, {
          headers,
          cache: ifNoneMatch ? 'no-store' : 'default'
        });
        const elapsed = performance.now() - t0;

        const etag = res.headers.get('etag');
        if (etag) {
          lastEtag = etag;
          btnEtagCheck.disabled = false;
        }

        if (res.status === 304) {
          renderMeta(itemsMeta, 304, elapsed, 'ETag Matched (' + (lastEtag || '') + ') - 0 bytes body');
          itemsOutput.textContent = '// 304 Not Modified: Browser/CDN cache validated via weak ETag without re-downloading JSON body.';
          return;
        }

        const data = await res.json();
        lastItemsUrl = url;
        lastNextCursor = data.pagination && data.pagination.nextCursor ? data.pagination.nextCursor : null;
        btnPageNext.disabled = !lastNextCursor;

        renderMeta(itemsMeta, res.status, elapsed, 'ETag: ' + (etag || 'n/a'));
        itemsOutput.textContent = JSON.stringify(data, null, 2);
      }

      document.getElementById('btn-refresh-headers').addEventListener('click', inspectSecurityHeaders);
      document.getElementById('btn-page-first').addEventListener('click', () => {
        fetchItems('/api/v1/items?limit=5', null);
      });
      btnPageNext.addEventListener('click', () => {
        if (lastNextCursor) {
          fetchItems('/api/v1/items?limit=5&cursor=' + encodeURIComponent(lastNextCursor), null);
        }
      });
      btnEtagCheck.addEventListener('click', () => {
        if (lastEtag) {
          fetchItems(lastItemsUrl, lastEtag);
        }
      });

      document.getElementById('btn-new-idem').addEventListener('click', () => {
        inpIdem.value = 'idem-' + Math.random().toString(36).slice(2, 12);
      });

      document.getElementById('btn-post-valid').addEventListener('click', async () => {
        const payload = {
          name: document.getElementById('inp-name').value,
          email: document.getElementById('inp-email').value,
          subject: document.getElementById('inp-subject').value,
          message: document.getElementById('inp-message').value
        };
        const t0 = performance.now();
        const res = await fetch('/api/v1/contact', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': inpIdem.value
          },
          body: JSON.stringify(payload)
        });
        const elapsed = performance.now() - t0;
        const body = await res.json();
        const replayed = res.headers.get('idempotency-replayed');
        const rem = res.headers.get('ratelimit-remaining');
        renderMeta(
          contactMeta,
          res.status,
          elapsed,
          'Idempotency-Replayed: ' + (replayed || 'n/a') + ' | RateLimit-Remaining: ' + (rem || 'n/a')
        );
        contactOutput.textContent = JSON.stringify(body, null, 2);
      });

      document.getElementById('btn-post-invalid').addEventListener('click', async () => {
        const t0 = performance.now();
        const res = await fetch('/api/v1/contact', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'A',
            email: 'invalid-email-format',
            subject: 'Hi',
            message: 'Too short',
            unrecognizedExtraProperty: true
          })
        });
        const elapsed = performance.now() - t0;
        const body = await res.json();
        renderMeta(contactMeta, res.status, elapsed, 'Content-Type: ' + (res.headers.get('content-type') || ''));
        contactOutput.textContent = JSON.stringify(body, null, 2);
      });

      document.getElementById('btn-trigger-404').addEventListener('click', async () => {
        const t0 = performance.now();
        const res = await fetch('/api/v1/non-existent-resource');
        const elapsed = performance.now() - t0;
        const body = await res.json();
        renderMeta(contactMeta, res.status, elapsed, 'X-Request-ID: ' + (res.headers.get('x-request-id') || ''));
        contactOutput.textContent = JSON.stringify(body, null, 2);
      });

      inspectSecurityHeaders();
      fetchItems('/api/v1/items?limit=5', null);
    })();
  </script>
</body>
</html>`;
}

export function createDashboardRouter(): Router {
  const router = Router();

  /**
   * GET /
   * Content-negotiated root route:
   * - Browser (`Accept: text/html`): Renders interactive reference console protected by a
   *   one-time cryptographic CSP nonce (`script-src 'nonce-...'`, zero `'unsafe-inline'`).
   * - API client (`Accept: application/json`): Returns structured service discovery metadata.
   */
  router.get('/', (req: Request, res: Response) => {
    const preferred = req.accepts(['html', 'json']);
    const requestId =
      typeof res.locals.requestId === 'string' ? res.locals.requestId : crypto.randomUUID();

    if (preferred === 'html') {
      const nonce = crypto.randomBytes(16).toString('base64');
      res
        .status(200)
        .setHeader('Cache-Control', 'no-store')
        .setHeader(
          'Content-Security-Policy',
          `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests`,
        )
        .type('text/html; charset=utf-8')
        .send(renderDashboardHtml(nonce, requestId));
      return;
    }

    res
      .status(200)
      .setHeader('Cache-Control', 'no-store')
      .json({
        service: 'cynbit-backend-reference-architecture',
        version: '1.0.0',
        status: 'operational',
        requestId,
        endpoints: {
          dashboard: 'GET / (Accept: text/html)',
          health: 'GET /healthz',
          catalogItems: 'GET /api/v1/items?limit=10&cursor=<base64url>',
          contactSubmission: 'POST /api/v1/contact',
        },
      });
  });

  return router;
}
