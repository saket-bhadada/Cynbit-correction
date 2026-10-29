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
  <title>Cynbit Security &amp; Backend Architecture Console</title>
  <style nonce="${nonce}">
    :root {
      --bg: #070913;
      --card: rgba(18, 24, 44, 0.72);
      --card-hover: rgba(24, 32, 58, 0.88);
      --border: rgba(255, 255, 255, 0.08);
      --border-highlight: rgba(99, 102, 241, 0.45);
      --text: #f8fafc;
      --text-soft: #cbd5e1;
      --muted: #8492b4;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --accent: #38bdf8;
      --emerald: #10b981;
      --emerald-soft: rgba(16, 185, 129, 0.14);
      --amber: #f59e0b;
      --amber-soft: rgba(245, 158, 11, 0.15);
      --rose: #f43f5e;
      --rose-soft: rgba(244, 63, 94, 0.15);
      --sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background-color: var(--bg);
      background-image:
        radial-gradient(ellipse 80% 50% at 50% -15%, rgba(99, 102, 241, 0.28), transparent),
        radial-gradient(ellipse 50% 40% at 85% 20%, rgba(56, 189, 248, 0.12), transparent),
        radial-gradient(ellipse 50% 40% at 15% 80%, rgba(16, 185, 129, 0.08), transparent);
      color: var(--text);
      font-family: var(--sans);
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }

    /* Navigation Bar */
    .navbar {
      position: sticky;
      top: 0;
      z-index: 20;
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      background: rgba(7, 9, 19, 0.75);
      border-bottom: 1px solid var(--border);
    }
    .navbar-inner {
      max-width: 1140px;
      margin: 0 auto;
      padding: 1rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      text-decoration: none;
      color: var(--text);
    }
    .brand-logo {
      width: 36px;
      height: 36px;
      border-radius: 10px;
      background: linear-gradient(135deg, #6366f1 0%, #38bdf8 100%);
      display: grid;
      place-items: center;
      box-shadow: 0 8px 24px -4px rgba(99, 102, 241, 0.5);
    }
    .brand-logo svg {
      width: 20px;
      height: 20px;
      stroke: #fff;
      stroke-width: 2.2;
      fill: none;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .brand-name {
      font-weight: 700;
      font-size: 1.1rem;
      letter-spacing: -0.02em;
    }
    .nav-status {
      display: inline-flex;
      align-items: center;
      gap: 0.55rem;
      padding: 0.38rem 0.85rem;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border);
      font-size: 0.8rem;
      color: var(--text-soft);
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--emerald);
      box-shadow: 0 0 12px var(--emerald);
    }

    /* Main Wrapper */
    .wrapper {
      max-width: 1140px;
      margin: 0 auto;
      padding: 3rem 1.5rem 4.5rem;
      display: flex;
      flex-direction: column;
      gap: 2.75rem;
    }

    /* Hero Section */
    .hero {
      text-align: center;
      max-width: 720px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 1rem;
    }
    .hero-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.32rem 0.9rem;
      border-radius: 999px;
      background: rgba(99, 102, 241, 0.12);
      border: 1px solid rgba(99, 102, 241, 0.3);
      color: #a5b4fc;
      font-size: 0.78rem;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    .hero h1 {
      margin: 0;
      font-size: clamp(2rem, 4vw, 2.85rem);
      font-weight: 800;
      letter-spacing: -0.035em;
      line-height: 1.15;
      background: linear-gradient(180deg, #ffffff 0%, #94a3b8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .hero p {
      margin: 0;
      font-size: 1.02rem;
      color: var(--muted);
      max-width: 600px;
    }

    /* 4 Pillar Feature Bento Cards */
    .pillars-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 1rem;
    }
    .pillar-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.25rem 1.35rem;
      display: flex;
      flex-direction: column;
      gap: 0.55rem;
      transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .pillar-card:hover {
      transform: translateY(-2px);
      border-color: rgba(255, 255, 255, 0.16);
    }
    .pillar-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .pillar-icon {
      width: 36px;
      height: 36px;
      border-radius: 10px;
      background: rgba(99, 102, 241, 0.14);
      color: #818cf8;
      display: grid;
      place-items: center;
      font-size: 1.05rem;
    }
    .pillar-stat {
      font-family: var(--mono);
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.18rem 0.55rem;
      border-radius: 999px;
      background: var(--emerald-soft);
      color: #34d399;
    }
    .pillar-title {
      margin: 0.2rem 0 0;
      font-size: 0.96rem;
      font-weight: 650;
      color: var(--text);
    }
    .pillar-desc {
      margin: 0;
      font-size: 0.82rem;
      color: var(--muted);
    }

    /* Main Two-Column Experience */
    .main-grid {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 1.5rem;
      align-items: start;
    }
    @media (max-width: 920px) {
      .main-grid {
        grid-template-columns: 1fr;
      }
    }

    .glass-panel {
      background: var(--card);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 1.65rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      box-shadow: 0 20px 50px -20px rgba(0, 0, 0, 0.6);
    }

    .panel-head {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
    }
    .panel-title {
      margin: 0;
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.015em;
    }
    .panel-sub {
      margin: 0.2rem 0 0;
      font-size: 0.84rem;
      color: var(--muted);
    }

    /* Segmented Category Pills */
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
    }
    .segmented {
      display: inline-flex;
      flex-wrap: wrap;
      gap: 0.3rem;
      background: rgba(7, 9, 19, 0.65);
      padding: 0.3rem;
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    .seg-btn {
      background: transparent;
      border: none;
      color: var(--muted);
      padding: 0.38rem 0.8rem;
      border-radius: 8px;
      font-size: 0.79rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .seg-btn:hover { color: var(--text); }
    .seg-btn.active {
      background: var(--primary);
      color: #fff;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.35);
    }

    /* Clean Catalog Cards */
    .catalog-stack {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .service-card {
      background: rgba(11, 15, 29, 0.65);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1rem 1.15rem;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 1rem;
      transition: all 0.18s ease;
    }
    .service-card:hover {
      background: var(--card-hover);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateX(2px);
    }
    .service-info h3 {
      margin: 0;
      font-size: 0.94rem;
      font-weight: 650;
      color: var(--text);
    }
    .service-info p {
      margin: 0.28rem 0 0;
      font-size: 0.81rem;
      color: var(--muted);
    }
    .tag {
      flex-shrink: 0;
      font-size: 0.72rem;
      font-weight: 600;
      padding: 0.22rem 0.65rem;
      border-radius: 999px;
      background: rgba(56, 189, 248, 0.12);
      color: #7dd3fc;
      border: 1px solid rgba(56, 189, 248, 0.25);
    }

    /* Buttons */
    .actions-footer {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      padding-top: 0.4rem;
      border-top: 1px solid var(--border);
    }
    .btn-group {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .btn {
      background: var(--primary);
      color: #fff;
      border: 1px solid transparent;
      border-radius: 10px;
      padding: 0.58rem 1.05rem;
      font-size: 0.83rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.16s ease;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.45rem;
    }
    .btn:hover:not(:disabled) {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 8px 20px -6px rgba(99, 102, 241, 0.6);
    }
    .btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }
    .btn-ghost {
      background: rgba(255, 255, 255, 0.05);
      border-color: var(--border);
      color: var(--text-soft);
    }
    .btn-ghost:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.1);
      color: #fff;
      box-shadow: none;
    }
    .btn-full {
      width: 100%;
      padding: 0.7rem 1.2rem;
      font-size: 0.88rem;
    }

    /* Form Styling */
    .form-stack {
      display: flex;
      flex-direction: column;
      gap: 0.85rem;
    }
    .field {
      display: flex;
      flex-direction: column;
      gap: 0.32rem;
    }
    .field span {
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--text-soft);
    }
    .field input, .field textarea {
      background: rgba(7, 9, 19, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 10px;
      padding: 0.62rem 0.85rem;
      color: var(--text);
      font-family: var(--sans);
      font-size: 0.86rem;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .field input:focus, .field textarea:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.22);
    }
    .field textarea {
      resize: vertical;
      min-height: 80px;
    }

    /* Status Toast / Feedback Banner */
    .feedback-banner {
      padding: 0.75rem 1rem;
      border-radius: 12px;
      font-size: 0.82rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border);
    }
    .feedback-ok {
      background: var(--emerald-soft);
      border-color: rgba(16, 185, 129, 0.3);
      color: #6ee7b7;
    }
    .feedback-warn {
      background: var(--amber-soft);
      border-color: rgba(245, 158, 11, 0.32);
      color: #fcd34d;
    }
    .feedback-err {
      background: var(--rose-soft);
      border-color: rgba(244, 63, 94, 0.32);
      color: #fda4af;
    }

    /* Optional Expandable Developer Inspector */
    .dev-drawer {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      overflow: hidden;
    }
    .dev-drawer-toggle {
      width: 100%;
      background: transparent;
      border: none;
      color: var(--text-soft);
      padding: 1rem 1.35rem;
      font-size: 0.85rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
    }
    .dev-drawer-toggle:hover {
      color: #fff;
      background: rgba(255, 255, 255, 0.02);
    }
    .dev-drawer-body {
      padding: 0 1.35rem 1.35rem;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }
    @media (max-width: 820px) {
      .dev-drawer-body {
        grid-template-columns: 1fr;
      }
    }
    .code-pane {
      margin: 0;
      padding: 0.9rem 1rem;
      border-radius: 12px;
      background: #05070f;
      border: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 0.75rem;
      color: #cbd5e1;
      overflow-x: auto;
      max-height: 260px;
    }
    .hidden { display: none !important; }
  </style>
</head>
<body>
  <nav class="navbar">
    <div class="navbar-inner">
      <a href="/" class="brand">
        <div class="brand-logo" aria-hidden="true">
          <svg viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
        </div>
        <span class="brand-name">Cynbit</span>
      </a>

      <div class="nav-status">
        <span class="status-dot"></span>
        <span>All 14 Security Controls Active</span>
        <span>•</span>
        <span id="nav-latency">TTFB: -- ms</span>
      </div>
    </div>
  </nav>

  <main class="wrapper">
    <!-- Clean, Modern Hero -->
    <section class="hero">
      <div class="hero-badge">
        <span>✦ Hardened Backend Architecture • RFC 9457 &amp; OWASP Verified</span>
      </div>
      <h1>Fast, Resilient &amp; Secure by Default.</h1>
      <p>
        Experience Cynbit’s hardened backend layer featuring instant ETag edge caching, keyset cursor pagination, sliding-window rate limiting, and strict schema validation.
      </p>
    </section>

    <!-- 4 Clean Visual Pillars -->
    <section class="pillars-grid" aria-label="Architecture Highlights">
      <div class="pillar-card">
        <div class="pillar-top">
          <div class="pillar-icon">🛡️</div>
          <span class="pillar-stat">14 / 14 PASS</span>
        </div>
        <h2 class="pillar-title">Transport &amp; CSP Shield</h2>
        <p class="pillar-desc">2-year HSTS preload, strict frameguard, and per-request cryptographic nonces.</p>
      </div>

      <div class="pillar-card">
        <div class="pillar-top">
          <div class="pillar-icon">⚡</div>
          <span class="pillar-stat" id="pillar-cache-stat">304 Ready</span>
        </div>
        <h2 class="pillar-title">Instant Edge Caching</h2>
        <p class="pillar-desc">Weak SHA-256 ETags and Brotli compression eliminate redundant data transfers.</p>
      </div>

      <div class="pillar-card">
        <div class="pillar-top">
          <div class="pillar-icon">⏱️</div>
          <span class="pillar-stat" id="pillar-rl-stat">100 / 100</span>
        </div>
        <h2 class="pillar-title">Sliding-Window Limiter</h2>
        <p class="pillar-desc">Atomic Redis/Memory quota tracking with standard IETF RateLimit headers.</p>
      </div>

      <div class="pillar-card">
        <div class="pillar-top">
          <div class="pillar-icon">✨</div>
          <span class="pillar-stat">Zod Strict</span>
        </div>
        <h2 class="pillar-title">Idempotent Ingestion</h2>
        <p class="pillar-desc">Fail-closed schema validation paired with safe retry idempotency keys.</p>
      </div>
    </section>

    <!-- Two Clean Interactive Cards -->
    <section class="main-grid">
      <!-- Left: Solutions Catalog -->
      <div class="glass-panel">
        <div class="panel-head">
          <div>
            <h2 class="panel-title">Enterprise Solutions Catalog</h2>
            <p class="panel-sub">Powered by <code>O(log N)</code> keyset cursor pagination &amp; conditional ETag caching</p>
          </div>
          <button class="btn btn-ghost" id="btn-etag-check" type="button">
            ⚡ Test Instant Cache (304)
          </button>
        </div>

        <div class="filter-bar">
          <div class="segmented" id="category-tabs">
            <button class="seg-btn active" data-category="" type="button">All</button>
            <button class="seg-btn" data-category="cloud-security" type="button">Cloud Security</button>
            <button class="seg-btn" data-category="identity" type="button">Identity</button>
            <button class="seg-btn" data-category="observability" type="button">Observability</button>
            <button class="seg-btn" data-category="compliance" type="button">Compliance</button>
          </div>
        </div>

        <div class="catalog-stack" id="catalog-list"></div>

        <div class="feedback-banner" id="catalog-feedback">
          <span id="catalog-status-text">Loading catalog...</span>
          <span id="catalog-etag-text"></span>
        </div>

        <div class="actions-footer">
          <button class="btn btn-ghost" id="btn-first-page" type="button">
            ↺ Reset to First Page
          </button>
          <button class="btn" id="btn-next-page" type="button" disabled>
            Next Page &rarr;
          </button>
        </div>
      </div>

      <!-- Right: Protected Contact & Validation Experience -->
      <div class="glass-panel">
        <div class="panel-head">
          <div>
            <h2 class="panel-title">Protected Inquiry &amp; Validation</h2>
            <p class="panel-sub">Protected by strict Zod schemas, 16 KB cap &amp; <code>Idempotency-Key</code> replay safety</p>
          </div>
        </div>

        <div class="form-stack">
          <label class="field">
            <span>Full Name</span>
            <input id="inp-name" type="text" value="Alice Security" placeholder="Your name" />
          </label>
          <label class="field">
            <span>Work Email</span>
            <input id="inp-email" type="email" value="alice@cynbit.com" placeholder="you@company.com" />
          </label>
          <label class="field">
            <span>Subject</span>
            <input id="inp-subject" type="text" value="Architecture Assessment Inquiry" placeholder="How can we help?" />
          </label>
          <label class="field">
            <span>Message</span>
            <textarea id="inp-message">Exploring Cynbit's zero-trust backend middleware and edge caching capabilities.</textarea>
          </label>
        </div>

        <button class="btn btn-full" id="btn-submit-valid" type="button">
          Send Secure Message
        </button>

        <div class="btn-group">
          <button class="btn btn-ghost" id="btn-replay-test" type="button" title="Resends with identical Idempotency-Key">
            🔁 Test Safe Retry
          </button>
          <button class="btn btn-ghost" id="btn-invalid-test" type="button" title="Sends malformed fields to test Zod 422 response">
            🛡️ Simulate Invalid Input (422)
          </button>
        </div>

        <div class="feedback-banner" id="contact-feedback">
          <span id="contact-status-text">Ready — protected by sliding-window rate limiter</span>
        </div>
      </div>
    </section>

    <!-- Clean, Collapsed Developer Drawer (Optional Under-the-Hood View) -->
    <section class="dev-drawer">
      <button class="dev-drawer-toggle" id="btn-toggle-drawer" type="button">
        <span>🔍 Developer Inspector — View Live HTTP Security Headers &amp; Last JSON Payload (Trace: ${safeRequestId})</span>
        <span id="drawer-chevron">Show &darr;</span>
      </button>
      <div class="dev-drawer-body hidden" id="drawer-body">
        <pre class="code-pane" id="raw-headers-pane">// Live HTTP Security Headers</pre>
        <pre class="code-pane" id="raw-json-pane">// Last API JSON Payload</pre>
      </div>
    </section>
  </main>

  <script nonce="${nonce}">
    (function () {
      const catalogList = document.getElementById('catalog-list');
      const catalogFeedback = document.getElementById('catalog-feedback');
      const catalogStatusText = document.getElementById('catalog-status-text');
      const catalogEtagText = document.getElementById('catalog-etag-text');
      const btnNextPage = document.getElementById('btn-next-page');
      const btnEtagCheck = document.getElementById('btn-etag-check');
      const navLatency = document.getElementById('nav-latency');
      const pillarCacheStat = document.getElementById('pillar-cache-stat');
      const pillarRlStat = document.getElementById('pillar-rl-stat');
      const contactFeedback = document.getElementById('contact-feedback');
      const contactStatusText = document.getElementById('contact-status-text');
      const rawHeadersPane = document.getElementById('raw-headers-pane');
      const rawJsonPane = document.getElementById('raw-json-pane');
      const drawerBody = document.getElementById('drawer-body');
      const drawerChevron = document.getElementById('drawer-chevron');

      let activeCategory = '';
      let nextCursor = null;
      let lastEtag = null;
      let lastUrl = '/api/v1/items?limit=3';
      let currentIdemKey = 'idem-' + Math.random().toString(36).slice(2, 10);

      function updateHeaderTelemetry(res, elapsedMs) {
        navLatency.textContent = 'TTFB: ' + elapsedMs.toFixed(0) + ' ms';
        const limit = res.headers.get('ratelimit-limit');
        const rem = res.headers.get('ratelimit-remaining');
        if (limit && rem) {
          pillarRlStat.textContent = rem + ' / ' + limit + ' Quota';
        }

        const tracked = [
          'strict-transport-security',
          'content-security-policy',
          'x-content-type-options',
          'x-frame-options',
          'referrer-policy',
          'permissions-policy',
          'cache-control',
          'etag',
          'ratelimit-policy',
          'x-request-id'
        ];
        rawHeadersPane.textContent = tracked
          .map((h) => h + ': ' + (res.headers.get(h) || '(absent)'))
          .join('\\n');
      }

      function renderServiceCards(items) {
        catalogList.textContent = '';
        items.forEach((item) => {
          const card = document.createElement('div');
          card.className = 'service-card';

          const info = document.createElement('div');
          info.className = 'service-info';
          const h3 = document.createElement('h3');
          h3.textContent = item.name;
          const p = document.createElement('p');
          p.textContent = item.summary;
          info.appendChild(h3);
          info.appendChild(p);

          const tag = document.createElement('span');
          tag.className = 'tag';
          tag.textContent = item.category;

          card.appendChild(info);
          card.appendChild(tag);
          catalogList.appendChild(card);
        });
      }

      function buildUrl(cursor) {
        const params = new URLSearchParams({ limit: '3' });
        if (activeCategory) params.set('category', activeCategory);
        if (cursor) params.set('cursor', cursor);
        return '/api/v1/items?' + params.toString();
      }

      async function loadCatalog(url, ifNoneMatch) {
        const headers = {};
        if (ifNoneMatch) headers['If-None-Match'] = ifNoneMatch;

        const t0 = performance.now();
        const res = await fetch(url, {
          headers,
          cache: ifNoneMatch ? 'no-store' : 'default'
        });
        const elapsed = performance.now() - t0;
        updateHeaderTelemetry(res, elapsed);

        const etag = res.headers.get('etag');
        if (etag) lastEtag = etag;

        if (res.status === 304) {
          catalogFeedback.className = 'feedback-banner feedback-ok';
          catalogStatusText.textContent = '⚡ 304 Not Modified — Instant cache hit (0 bytes downloaded)';
          catalogEtagText.textContent = elapsed.toFixed(1) + ' ms';
          pillarCacheStat.textContent = '304 Verified';
          return;
        }

        const body = await res.json();
        rawJsonPane.textContent = JSON.stringify(body, null, 2);

        if (res.ok && body.data) {
          lastUrl = url;
          nextCursor = body.pagination ? body.pagination.nextCursor : null;
          btnNextPage.disabled = !nextCursor;
          renderServiceCards(body.data);
          catalogFeedback.className = 'feedback-banner';
          catalogStatusText.textContent = 'Showing ' + body.data.length + ' modules • HTTP 200 OK';
          catalogEtagText.textContent = elapsed.toFixed(1) + ' ms';
        }
      }

      document.querySelectorAll('#category-tabs .seg-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('#category-tabs .seg-btn').forEach((b) => b.classList.remove('active'));
          btn.classList.add('active');
          activeCategory = btn.getAttribute('data-category') || '';
          loadCatalog(buildUrl(null), null);
        });
      });

      document.getElementById('btn-first-page').addEventListener('click', () => {
        loadCatalog(buildUrl(null), null);
      });

      btnNextPage.addEventListener('click', () => {
        if (nextCursor) loadCatalog(buildUrl(nextCursor), null);
      });

      btnEtagCheck.addEventListener('click', () => {
        if (lastEtag) loadCatalog(lastUrl, lastEtag);
      });

      async function sendContact(payload, idemKey) {
        const t0 = performance.now();
        const res = await fetch('/api/v1/contact', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': idemKey
          },
          body: JSON.stringify(payload)
        });
        const elapsed = performance.now() - t0;
        updateHeaderTelemetry(res, elapsed);

        const body = await res.json();
        rawJsonPane.textContent = JSON.stringify(body, null, 2);
        const replayed = res.headers.get('idempotency-replayed') === 'true';

        if (res.status === 201) {
          contactFeedback.className = 'feedback-banner feedback-ok';
          contactStatusText.textContent = replayed
            ? '🔁 Safe Retry Verified — Duplicate submission prevented (Idempotency-Replayed: true)'
            : '✓ Message accepted (HTTP 201 Created in ' + elapsed.toFixed(1) + ' ms)';
        } else if (res.status === 422) {
          contactFeedback.className = 'feedback-banner feedback-warn';
          contactStatusText.textContent = '🛡️ Blocked by Zod .strict() Validator (HTTP 422 RFC 9457 Problem Details)';
        } else if (res.status === 429) {
          contactFeedback.className = 'feedback-banner feedback-err';
          contactStatusText.textContent = '⏱️ Rate Limit Reached (HTTP 429 Too Many Requests — Retry-After active)';
        } else {
          contactFeedback.className = 'feedback-banner feedback-err';
          contactStatusText.textContent = 'HTTP ' + res.status + ' — ' + (body.title || 'Request rejected');
        }
      }

      document.getElementById('btn-submit-valid').addEventListener('click', () => {
        currentIdemKey = 'idem-' + Math.random().toString(36).slice(2, 10);
        sendContact(
          {
            name: document.getElementById('inp-name').value,
            email: document.getElementById('inp-email').value,
            subject: document.getElementById('inp-subject').value,
            message: document.getElementById('inp-message').value
          },
          currentIdemKey
        );
      });

      document.getElementById('btn-replay-test').addEventListener('click', () => {
        sendContact(
          {
            name: document.getElementById('inp-name').value,
            email: document.getElementById('inp-email').value,
            subject: document.getElementById('inp-subject').value,
            message: document.getElementById('inp-message').value
          },
          currentIdemKey
        );
      });

      document.getElementById('btn-invalid-test').addEventListener('click', () => {
        sendContact(
          {
            name: 'A',
            email: 'invalid-email',
            subject: 'Hi',
            message: 'Too short',
            unrecognizedField: true
          },
          'idem-invalid-test'
        );
      });

      document.getElementById('btn-toggle-drawer').addEventListener('click', () => {
        const isHidden = drawerBody.classList.toggle('hidden');
        drawerChevron.innerHTML = isHidden ? 'Show &darr;' : 'Hide &uarr;';
      });

      loadCatalog(buildUrl(null), null);
    })();
  </script>
</body>
</html>`;
}

export function createDashboardRouter(): Router {
  const router = Router();

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
