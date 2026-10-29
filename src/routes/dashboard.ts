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
  const safeNoncePreview = escapeHtml(nonce.slice(0, 12) + '…');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Cynbit — Hardened Backend Reference Architecture</title>
  <style nonce="${nonce}">
    :root {
      --bg-deep: #060913;
      --bg-main: #0b1021;
      --surface: rgba(17, 25, 48, 0.88);
      --surface-elevated: rgba(24, 35, 66, 0.92);
      --surface-code: #060a15;
      --border: rgba(99, 130, 209, 0.2);
      --border-strong: rgba(99, 130, 209, 0.38);
      --text: #eef2ff;
      --text-secondary: #a5b4fc;
      --muted: #7f91c0;
      --accent: #3b82f6;
      --accent-glow: rgba(59, 130, 246, 0.28);
      --accent-hover: #2563eb;
      --cyan: #06b6d4;
      --ok: #10b981;
      --ok-bg: rgba(16, 185, 129, 0.14);
      --warn: #f59e0b;
      --warn-bg: rgba(245, 158, 11, 0.15);
      --err: #ef4444;
      --err-bg: rgba(239, 68, 68, 0.16);
      --purple: #8b5cf6;
      --purple-bg: rgba(139, 92, 246, 0.16);
      --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --sans: "Inter", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --radius-lg: 14px;
      --radius-md: 10px;
      --radius-sm: 6px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background-color: var(--bg-deep);
      background-image:
        radial-gradient(circle at 12% 8%, rgba(59, 130, 246, 0.16), transparent 36%),
        radial-gradient(circle at 88% 12%, rgba(6, 182, 212, 0.12), transparent 34%),
        radial-gradient(circle at 50% 90%, rgba(139, 92, 246, 0.1), transparent 40%);
      color: var(--text);
      font-family: var(--sans);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    /* Top Navigation & Header */
    .topbar {
      position: sticky;
      top: 0;
      z-index: 30;
      backdrop-filter: blur(16px);
      background: rgba(9, 14, 28, 0.85);
      border-bottom: 1px solid var(--border);
      padding: 0.9rem 2rem;
    }
    .topbar-inner {
      max-width: 1380px;
      margin: 0 auto;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.85rem;
    }
    .brand-icon {
      width: 38px;
      height: 38px;
      border-radius: 10px;
      background: linear-gradient(135deg, var(--accent), var(--cyan));
      display: grid;
      place-items: center;
      box-shadow: 0 0 20px var(--accent-glow);
      flex-shrink: 0;
    }
    .brand-icon svg {
      width: 22px;
      height: 22px;
      fill: none;
      stroke: #fff;
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .brand-title {
      margin: 0;
      font-size: 1.12rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      display: flex;
      align-items: center;
      gap: 0.55rem;
    }
    .version-chip {
      font-family: var(--mono);
      font-size: 0.7rem;
      font-weight: 600;
      padding: 0.12rem 0.48rem;
      border-radius: 999px;
      background: rgba(59, 130, 246, 0.18);
      border: 1px solid rgba(59, 130, 246, 0.4);
      color: #93c5fd;
    }
    .brand-sub {
      margin: 0.12rem 0 0;
      font-size: 0.79rem;
      color: var(--muted);
    }

    .topbar-meta {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.65rem;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.36rem 0.75rem;
      border-radius: 999px;
      background: var(--surface);
      border: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 0.74rem;
      color: var(--text-secondary);
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--ok);
      box-shadow: 0 0 10px var(--ok);
    }

    /* Main Container */
    .container {
      max-width: 1380px;
      margin: 0 auto;
      padding: 1.5rem 2rem 3.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.4rem;
    }

    /* KPI Scorecard Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1rem;
    }
    .kpi-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 1.1rem 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
      position: relative;
      overflow: hidden;
    }
    .kpi-card::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(90deg, var(--accent), var(--cyan));
    }
    .kpi-label {
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      font-weight: 600;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .kpi-value {
      font-size: 1.55rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      font-family: var(--mono);
      color: var(--text);
    }
    .kpi-sub {
      font-size: 0.77rem;
      color: var(--muted);
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    progress.meter {
      width: 100%;
      height: 6px;
      appearance: none;
      -webkit-appearance: none;
      border: none;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.08);
      overflow: hidden;
      margin-top: 0.25rem;
    }
    progress.meter::-webkit-progress-bar {
      background: rgba(255, 255, 255, 0.08);
      border-radius: 999px;
    }
    progress.meter::-webkit-progress-value {
      background: linear-gradient(90deg, var(--ok), var(--cyan));
      border-radius: 999px;
      transition: width 0.25s ease;
    }
    progress.meter::-moz-progress-bar {
      background: linear-gradient(90deg, var(--ok), var(--cyan));
      border-radius: 999px;
    }
    .text-note { color: #93c5fd; }
    .text-muted-cell { color: var(--muted); }
    .ml-gap { margin-left: 0.5rem; }

    /* Navigation Tabs */
    .tabs-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.75rem;
    }
    .tab-group {
      display: inline-flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      background: var(--surface);
      padding: 0.3rem;
      border-radius: var(--radius-md);
      border: 1px solid var(--border);
    }
    .tab-btn {
      background: transparent;
      color: var(--muted);
      border: none;
      border-radius: 7px;
      padding: 0.48rem 0.95rem;
      font-size: 0.83rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .tab-btn:hover {
      color: var(--text);
    }
    .tab-btn.active {
      background: var(--accent);
      color: #fff;
      box-shadow: 0 2px 10px var(--accent-glow);
    }
    .tab-panel {
      display: none;
      flex-direction: column;
      gap: 1.35rem;
    }
    .tab-panel.active {
      display: flex;
    }

    /* Cards & Layout Grids */
    .workspace-grid {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 1.35rem;
    }
    @media (max-width: 1060px) {
      .workspace-grid {
        grid-template-columns: 1fr;
      }
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 1.35rem 1.45rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .card-header {
      display: flex;
      flex-wrap: wrap;
      align-items: flex-start;
      justify-content: space-between;
      gap: 0.75rem;
    }
    .card-title {
      margin: 0;
      font-size: 1.02rem;
      font-weight: 650;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .card-desc {
      margin: 0.2rem 0 0;
      font-size: 0.82rem;
      color: var(--muted);
    }

    /* Buttons & Controls */
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.65rem;
      padding: 0.65rem 0.8rem;
      background: rgba(8, 12, 24, 0.55);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
    }
    .btn-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.5rem;
    }
    button.btn {
      background: var(--accent);
      color: #fff;
      border: 1px solid transparent;
      border-radius: var(--radius-sm);
      padding: 0.45rem 0.85rem;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }
    button.btn:hover:not(:disabled) {
      background: var(--accent-hover);
      transform: translateY(-1px);
    }
    button.btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }
    button.btn-secondary {
      background: var(--surface-elevated);
      border-color: var(--border-strong);
      color: var(--text);
    }
    button.btn-secondary:hover:not(:disabled) {
      background: #23325e;
    }
    button.btn-warn {
      background: var(--warn-bg);
      border-color: rgba(245, 158, 11, 0.4);
      color: #fcd34d;
    }
    button.btn-warn:hover:not(:disabled) {
      background: rgba(245, 158, 11, 0.25);
    }
    button.btn-danger {
      background: var(--err-bg);
      border-color: rgba(239, 68, 68, 0.4);
      color: #fca5a5;
    }
    button.btn-danger:hover:not(:disabled) {
      background: rgba(239, 68, 68, 0.26);
    }

    select.select-ctrl {
      background: var(--surface-code);
      color: var(--text);
      border: 1px solid var(--border-strong);
      border-radius: var(--radius-sm);
      padding: 0.4rem 0.65rem;
      font-size: 0.79rem;
      font-family: var(--sans);
    }

    /* Filter Chips */
    .chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }
    .filter-chip {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border);
      color: var(--muted);
      border-radius: 999px;
      padding: 0.26rem 0.7rem;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .filter-chip:hover {
      color: var(--text);
      border-color: var(--border-strong);
    }
    .filter-chip.active {
      background: rgba(59, 130, 246, 0.2);
      border-color: var(--accent);
      color: #93c5fd;
    }

    /* Catalog Item Cards */
    .catalog-list {
      display: grid;
      gap: 0.65rem;
    }
    .catalog-item {
      background: rgba(9, 14, 28, 0.7);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 0.85rem 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
      transition: border-color 0.15s ease;
    }
    .catalog-item:hover {
      border-color: var(--border-strong);
    }
    .catalog-item-top {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
    }
    .catalog-item-title {
      font-weight: 600;
      font-size: 0.88rem;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .catalog-item-id {
      font-family: var(--mono);
      font-size: 0.73rem;
      color: var(--text-secondary);
      background: rgba(99, 102, 241, 0.14);
      padding: 0.1rem 0.45rem;
      border-radius: 4px;
    }
    .catalog-item-summary {
      font-size: 0.79rem;
      color: var(--muted);
      margin: 0;
    }
    .catalog-item-foot {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      font-family: var(--mono);
      font-size: 0.72rem;
      color: var(--muted);
      margin-top: 0.15rem;
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      padding: 0.16rem 0.55rem;
      border-radius: 5px;
      font-family: var(--mono);
      font-size: 0.72rem;
      font-weight: 600;
    }
    .badge-ok { background: var(--ok-bg); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-warn { background: var(--warn-bg); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.32); }
    .badge-err { background: var(--err-bg); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.32); }
    .badge-purple { background: var(--purple-bg); color: #c4b5fd; border: 1px solid rgba(139, 92, 246, 0.32); }
    .badge-info { background: rgba(6, 182, 212, 0.15); color: #67e8f9; border: 1px solid rgba(6, 182, 212, 0.32); }

    /* Cursor & ETag Inspector Box */
    .cursor-inspector {
      background: var(--surface-code);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 0.7rem 0.9rem;
      font-family: var(--mono);
      font-size: 0.75rem;
      display: grid;
      gap: 0.35rem;
    }
    .cursor-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
    }
    .cursor-key { color: var(--muted); }
    .cursor-val { color: #93c5fd; word-break: break-all; }

    /* Code Pre & JSON Viewer */
    pre.code-box {
      margin: 0;
      padding: 0.9rem 1rem;
      border-radius: var(--radius-md);
      background: var(--surface-code);
      border: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 0.76rem;
      overflow-x: auto;
      max-height: 290px;
      color: #dbeafe;
      line-height: 1.45;
    }

    /* Form Controls */
    .form-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.75rem;
    }
    .form-grid .full { grid-column: 1 / -1; }
    label.field-label {
      display: flex;
      flex-direction: column;
      gap: 0.28rem;
      font-size: 0.76rem;
      font-weight: 600;
      color: var(--text-secondary);
    }
    input.field-input, textarea.field-input {
      background: var(--surface-code);
      border: 1px solid var(--border-strong);
      border-radius: var(--radius-sm);
      padding: 0.5rem 0.68rem;
      color: var(--text);
      font-family: var(--sans);
      font-size: 0.82rem;
      transition: border-color 0.15s ease;
    }
    input.field-input:focus, textarea.field-input:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 2px var(--accent-glow);
    }
    textarea.field-input {
      resize: vertical;
      min-height: 68px;
    }

    /* Tables */
    .table-wrap {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      background: rgba(6, 10, 21, 0.65);
    }
    table.data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.81rem;
    }
    table.data-table th, table.data-table td {
      text-align: left;
      padding: 0.65rem 0.85rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    table.data-table th {
      background: rgba(17, 25, 48, 0.9);
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    table.data-table tr:last-child td {
      border-bottom: none;
    }
    table.data-table code {
      font-family: var(--mono);
      font-size: 0.75rem;
      color: #bfdbfe;
      word-break: break-all;
    }

    /* Telemetry Timeline Log */
    .log-list {
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
      max-height: 220px;
      overflow-y: auto;
    }
    .log-entry {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.6rem;
      padding: 0.5rem 0.75rem;
      border-radius: var(--radius-sm);
      background: var(--surface-code);
      border: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 0.75rem;
    }
    .log-left {
      display: flex;
      align-items: center;
      gap: 0.55rem;
    }
    .log-right {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      color: var(--muted);
    }
    .hidden { display: none !important; }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <div class="brand-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
        </div>
        <div>
          <h1 class="brand-title">
            Cynbit Security &amp; Backend Architecture Console
            <span class="version-chip">v1.0.0-hardened</span>
          </h1>
          <p class="brand-sub">
            Zero-Trust HTTP Headers • RFC 9457 Problem Details • Keyset Pagination • Weak ETag (304) • Redis/Memory Sliding-Window Rate Limiter
          </p>
        </div>
      </div>

      <div class="topbar-meta">
        <div class="pill" title="Cryptographic nonce regenerated on every HTML document request">
          <span>CSP Nonce:</span>
          <strong id="nonce-display">${safeNoncePreview}</strong>
        </div>
        <div class="pill" title="Correlation ID assigned by correlationIdMiddleware">
          <span class="pulse-dot"></span>
          <span>Trace ID: <strong id="boot-req-id">${safeRequestId}</strong></span>
        </div>
      </div>
    </div>
  </header>

  <main class="container">
    <!-- Top Executive Telemetry KPIs -->
    <section class="kpi-grid" aria-label="Live Backend Telemetry Metrics">
      <div class="kpi-card">
        <div class="kpi-label">
          <span>Passive Header Posture</span>
          <span class="badge badge-ok" id="kpi-posture-badge">PASS</span>
        </div>
        <div class="kpi-value" id="kpi-posture-val">14 / 14</div>
        <progress class="meter" id="kpi-posture-bar" max="100" value="100"></progress>
        <div class="kpi-sub">Strict CSP, 2yr HSTS Preload, Permissions-Policy</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">
          <span>Last API Latency (TTFB)</span>
          <span class="badge badge-info" id="kpi-encoding-badge">br / gzip</span>
        </div>
        <div class="kpi-value" id="kpi-latency-val">-- ms</div>
        <progress class="meter" id="kpi-latency-bar" max="100" value="85"></progress>
        <div class="kpi-sub" id="kpi-latency-sub">Target &lt; 250ms budget</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">
          <span>Sliding-Window Quota</span>
          <span class="badge badge-purple" id="kpi-rl-policy">100;w=60</span>
        </div>
        <div class="kpi-value" id="kpi-rl-remaining">-- / --</div>
        <progress class="meter" id="kpi-rl-bar" max="100" value="100"></progress>
        <div class="kpi-sub" id="kpi-rl-reset">IETF RateLimit-* headers active</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">
          <span>Conditional ETag Cache</span>
          <span class="badge badge-ok" id="kpi-cache-badge">s-maxage=300</span>
        </div>
        <div class="kpi-value" id="kpi-304-count">0 Hits (304)</div>
        <progress class="meter" id="kpi-cache-bar" max="100" value="100"></progress>
        <div class="kpi-sub" id="kpi-etag-sub">Weak ETag + stale-while-revalidate</div>
      </div>
    </section>

    <!-- View Switcher Tabs -->
    <div class="tabs-bar">
      <div class="tab-group" role="tablist">
        <button class="tab-btn active" data-tab="tab-workbench" type="button" role="tab">
          1. Interactive API &amp; Security Workbench
        </button>
        <button class="tab-btn" data-tab="tab-headers" type="button" role="tab">
          2. Live HTTP Security Header Audit (14 Controls)
        </button>
        <button class="tab-btn" data-tab="tab-findings" type="button" role="tab">
          3. Audit Findings &amp; Remediation Matrix (F-01 – F-11)
        </button>
      </div>
      <div class="btn-row">
        <button class="btn btn-secondary" id="btn-toggle-raw" type="button">Toggle Raw JSON View</button>
        <button class="btn btn-secondary" id="btn-refresh-all" type="button">Re-Run Passive Check</button>
      </div>
    </div>

    <!-- TAB 1: Interactive Workbench -->
    <div class="tab-panel active" id="tab-workbench">
      <div class="workspace-grid">
        <!-- Left Column: Keyset Cursor Pagination & Weak ETag Explorer -->
        <section class="card">
          <div class="card-header">
            <div>
              <h2 class="card-title">
                <span>Keyset Cursor Pagination &amp; Weak ETag Explorer</span>
                <span class="badge badge-ok">GET /api/v1/items</span>
              </h2>
              <p class="card-desc">
                Replaces <code>O(N) OFFSET</code> scans with <code>O(log N)</code> composite keyset cursors <code>(createdAt, id)</code> and negotiates <code>304 Not Modified</code>.
              </p>
            </div>
          </div>

          <!-- Category Filter Chips & Page Size -->
          <div class="toolbar">
            <div class="chip-row" id="category-chips">
              <button class="filter-chip active" data-category="" type="button">All (25)</button>
              <button class="filter-chip" data-category="cloud-security" type="button">Cloud Security</button>
              <button class="filter-chip" data-category="identity" type="button">Identity</button>
              <button class="filter-chip" data-category="observability" type="button">Observability</button>
              <button class="filter-chip" data-category="compliance" type="button">Compliance</button>
            </div>
            <div>
              <select class="select-ctrl" id="sel-limit" aria-label="Items per page">
                <option value="4" selected>4 items / page</option>
                <option value="6">6 items / page</option>
                <option value="10">10 items / page</option>
              </select>
            </div>
          </div>

          <!-- Pagination & Conditional Request Action Bar -->
          <div class="btn-row">
            <button class="btn" id="btn-page-first" type="button">First Page</button>
            <button class="btn btn-secondary" id="btn-page-next" type="button" disabled>
              Next Cursor Page &rarr;
            </button>
            <button class="btn btn-warn" id="btn-etag-check" type="button" disabled>
              Revalidate If-None-Match (Test 304)
            </button>
            <button class="btn btn-danger" id="btn-bad-cursor" type="button">
              Tamper Cursor (Test 400)
            </button>
          </div>

          <!-- Cursor & ETag State Inspector -->
          <div class="cursor-inspector">
            <div class="cursor-row">
              <span class="cursor-key">Status / Latency:</span>
              <span id="items-meta">Ready</span>
            </div>
            <div class="cursor-row">
              <span class="cursor-key">Active Weak ETag:</span>
              <span class="cursor-val" id="items-etag-val">—</span>
            </div>
            <div class="cursor-row">
              <span class="cursor-key">Next Cursor (Base64URL &rarr; Decoded Keyset):</span>
              <span class="cursor-val" id="items-cursor-decoded">—</span>
            </div>
          </div>

          <!-- Visual Catalog Cards -->
          <div class="catalog-list" id="catalog-cards"></div>

          <!-- Raw JSON Response Box -->
          <pre class="code-box hidden" id="items-output">// Raw JSON payload</pre>
        </section>

        <!-- Right Column: State-Mutating Validation, Idempotency & RFC 9457 Sandbox -->
        <section class="card">
          <div class="card-header">
            <div>
              <h2 class="card-title">
                <span>Ingestion Validation, Idempotency &amp; RFC 9457 Lab</span>
                <span class="badge badge-purple">POST /api/v1/contact</span>
              </h2>
              <p class="card-desc">
                Enforces Zod <code>.strict()</code> schemas, control-char stripping, <code>16 KiB</code> cap, <code>Idempotency-Key</code> replay safety, and route rate limiting (<code>5 req/min</code>).
              </p>
            </div>
          </div>

          <div class="form-grid">
            <label class="field-label">
              Sender Name (2–100 chars)
              <input class="field-input" id="inp-name" type="text" value="Alice Security" />
            </label>
            <label class="field-label">
              Work Email
              <input class="field-input" id="inp-email" type="email" value="alice@cynbit.com" />
            </label>
            <label class="field-label">
              Subject (4–150 chars)
              <input class="field-input" id="inp-subject" type="text" value="Zero-Trust API Gateway Verification" />
            </label>
            <label class="field-label">
              Idempotency-Key Header
              <input class="field-input" id="inp-idem" type="text" value="idem-console-0001" />
            </label>
            <label class="field-label full">
              Message Payload (10–2000 chars, control chars stripped)
              <textarea class="field-input" id="inp-message">Verifying strict Zod validation, sliding-window rate limits, and idempotent replay safety.</textarea>
            </label>
          </div>

          <div class="btn-row">
            <button class="btn" id="btn-post-valid" type="button">
              Submit Valid POST (201 / Replay)
            </button>
            <button class="btn btn-secondary" id="btn-new-idem" type="button">
              Rotate Idempotency-Key
            </button>
            <button class="btn btn-warn" id="btn-idem-conflict" type="button">
              Mutate Body + Same Key (409)
            </button>
          </div>

          <div class="btn-row">
            <button class="btn btn-danger" id="btn-post-invalid" type="button">
              Invalid Schema + Extra Key (422)
            </button>
            <button class="btn btn-danger" id="btn-bad-ctype" type="button">
              Wrong Content-Type (415)
            </button>
            <button class="btn btn-danger" id="btn-trigger-404" type="button">
              Unmatched Route (404)
            </button>
          </div>

          <div class="cursor-inspector">
            <div class="cursor-row">
              <span class="cursor-key">Response Status:</span>
              <span id="contact-meta">Ready — select a test scenario above</span>
            </div>
            <div class="cursor-row">
              <span class="cursor-key">Idempotency &amp; RateLimit State:</span>
              <span class="cursor-val" id="contact-headers-meta">—</span>
            </div>
          </div>

          <pre class="code-box" id="contact-output">// Click any scenario button above to inspect RFC 9457 Problem Details or 201 Created responses</pre>
        </section>
      </div>

      <!-- Real-Time Request / Response Telemetry Stream -->
      <section class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Live Request / Response Correlation Stream</h2>
            <p class="card-desc">
              Every call made from this console is logged below with its correlated <code>X-Request-ID</code>, HTTP status, and latency.
            </p>
          </div>
          <button class="btn btn-secondary" id="btn-clear-log" type="button">Clear Stream</button>
        </div>
        <div class="log-list" id="telemetry-log"></div>
      </section>
    </div>

    <!-- TAB 2: Live HTTP Security Header Audit -->
    <div class="tab-panel" id="tab-headers">
      <section class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Live Passive HTTP Response Header Inspection</h2>
            <p class="card-desc">
              Evaluated in real time from the Express middleware pipeline (<code>src/middleware/securityHeaders.ts</code> &amp; <code>rateLimiter.ts</code>).
            </p>
          </div>
          <button class="btn" id="btn-refresh-headers" type="button">Re-Inspect Live Headers</button>
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Header / Control</th>
                <th>Live Observed Value</th>
                <th>Architectural Purpose</th>
              </tr>
            </thead>
            <tbody id="headers-tbody">
              <tr><td colspan="4">Inspecting live response headers...</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- TAB 3: Audit Findings & Remediation Matrix -->
    <div class="tab-panel" id="tab-findings">
      <section class="card">
        <div class="card-header">
          <div>
            <h2 class="card-title">Categorized Security &amp; Performance Audit Matrix (F-01 – F-11)</h2>
            <p class="card-desc">
              Complete traceability from passive architectural observations to concrete code modules in <code>src/</code>.
            </p>
          </div>
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Baseline Vulnerability / Bottleneck</th>
                <th>Implemented Fix in Repository</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><code>F-01</code></td>
                <td>Security</td>
                <td><span class="badge badge-err">High</span></td>
                <td>Missing or permissive CSP (<code>'unsafe-inline'</code>) and missing clickjacking frame ancestors.</td>
                <td>Strict API CSP (<code>default-src 'none'; frame-ancestors 'none'</code>) &amp; per-request cryptographic nonces in <code>securityHeaders.ts</code> &amp; <code>dashboard.ts</code>.</td>
              </tr>
              <tr>
                <td><code>F-02</code></td>
                <td>Security</td>
                <td><span class="badge badge-warn">Medium</span></td>
                <td>Missing/short HSTS <code>max-age</code>, missing <code>Permissions-Policy</code>, or missing <code>nosniff</code>.</td>
                <td>2-year HSTS Preload (<code>max-age=63072000; includeSubDomains; preload</code>), <code>nosniff</code>, and hardware-disabling <code>Permissions-Policy</code>.</td>
              </tr>
              <tr>
                <td><code>F-03</code></td>
                <td>Security</td>
                <td><span class="badge badge-err">High</span></td>
                <td>Wildcard CORS (<code>*</code>) or dynamic origin reflection without <code>Vary: Origin</code> (CDN cache poisoning).</td>
                <td>Explicit origin allowlist in <code>createCorsMiddleware()</code> paired with mandatory <code>Vary: Origin</code> and 403 Problem Details rejection.</td>
              </tr>
              <tr>
                <td><code>F-04</code></td>
                <td>Auth / Abuse</td>
                <td><span class="badge badge-err">High</span></td>
                <td>Unthrottled public write endpoints lacking distributed rate limits and <code>Retry-After</code> headers.</td>
                <td>Atomic Redis Lua sliding-window limiter (<code>rateLimiter.ts</code>) with IETF <code>RateLimit-*</code> and <code>Retry-After</code> headers.</td>
              </tr>
              <tr>
                <td><code>F-05</code></td>
                <td>Auth</td>
                <td><span class="badge badge-warn">Medium</span></td>
                <td>Session tokens exposed in <code>localStorage</code> or cookies missing <code>__Host-</code>, <code>HttpOnly</code>, <code>SameSite</code>.</td>
                <td>Documented <code>__Host-</code> cookie invariants + passive redaction &amp; flag verifier in <code>scripts/passive_audit.py</code>.</td>
              </tr>
              <tr>
                <td><code>F-06</code></td>
                <td>Data Validation</td>
                <td><span class="badge badge-warn">Medium</span></td>
                <td>Unbounded JSON bodies, silent acceptance of unknown fields (mass assignment), and form-encoded CSRF writes.</td>
                <td>Zod <code>.strict()</code> schemas, control-char stripping, <code>requireJsonContentType</code> (415), and <code>enforcePayloadSize</code> (413) in <code>validate.ts</code>.</td>
              </tr>
              <tr>
                <td><code>F-07</code></td>
                <td>Data Validation</td>
                <td><span class="badge badge-info">Architecture</span></td>
                <td>Duplicate contact/order creation when mobile clients retry timed-out POST requests.</td>
                <td>SHA-256 payload-hashed <code>Idempotency-Key</code> store in <code>exampleApi.ts</code> (<code>201</code> replay vs <code>409 Conflict</code> on mutated payload).</td>
              </tr>
              <tr>
                <td><code>F-08</code></td>
                <td>Error Handling</td>
                <td><span class="badge badge-warn">Medium</span></td>
                <td>Heterogeneous 4xx/5xx error formats, missing trace correlation, and leaked stack traces in production.</td>
                <td>Centralized <strong>RFC 9457</strong> (<code>application/problem+json</code>) handler in <code>errorHandler.ts</code> with <code>X-Request-ID</code> and production redaction.</td>
              </tr>
              <tr>
                <td><code>F-09</code></td>
                <td>Security</td>
                <td><span class="badge badge-purple">Low</span></td>
                <td>Framework fingerprinting via <code>X-Powered-By: Express</code> and verbose server banners.</td>
                <td>Explicit <code>app.disable('x-powered-by')</code> and Helmet header suppression.</td>
              </tr>
              <tr>
                <td><code>F-10</code></td>
                <td>Performance</td>
                <td><span class="badge badge-warn">Medium</span></td>
                <td>Uncompressed JSON transfers and missing conditional <code>ETag</code> validation (redundant 200 OK downloads).</td>
                <td>Brotli (<code>br</code>) &amp; <code>gzip</code> dynamic compression + SHA-256 weak <code>ETag</code> (<code>W/"..."</code>) returning 0-byte <code>304 Not Modified</code>.</td>
              </tr>
              <tr>
                <td><code>F-11</code></td>
                <td>Performance</td>
                <td><span class="badge badge-info">Architecture</span></td>
                <td><code>OFFSET</code> pagination slowdowns on deep pages and missing CDN edge caching directives.</td>
                <td>Opaque Base64URL keyset cursor pagination + <code>Cache-Control: public, max-age=60, s-maxage=300, stale-while-revalidate=60</code>.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </main>

  <script nonce="${nonce}">
    (function () {
      const headersTbody = document.getElementById('headers-tbody');
      const catalogCards = document.getElementById('catalog-cards');
      const itemsOutput = document.getElementById('items-output');
      const itemsMeta = document.getElementById('items-meta');
      const itemsEtagVal = document.getElementById('items-etag-val');
      const itemsCursorDecoded = document.getElementById('items-cursor-decoded');
      const btnPageNext = document.getElementById('btn-page-next');
      const btnEtagCheck = document.getElementById('btn-etag-check');
      const selLimit = document.getElementById('sel-limit');
      const contactMeta = document.getElementById('contact-meta');
      const contactHeadersMeta = document.getElementById('contact-headers-meta');
      const contactOutput = document.getElementById('contact-output');
      const inpIdem = document.getElementById('inp-idem');
      const telemetryLog = document.getElementById('telemetry-log');

      // KPI Elements
      const kpiLatencyVal = document.getElementById('kpi-latency-val');
      const kpiLatencyBar = document.getElementById('kpi-latency-bar');
      const kpiLatencySub = document.getElementById('kpi-latency-sub');
      const kpiRlPolicy = document.getElementById('kpi-rl-policy');
      const kpiRlRemaining = document.getElementById('kpi-rl-remaining');
      const kpiRlBar = document.getElementById('kpi-rl-bar');
      const kpiRlReset = document.getElementById('kpi-rl-reset');
      const kpi304Count = document.getElementById('kpi-304-count');
      const kpiEtagSub = document.getElementById('kpi-etag-sub');

      let activeCategory = '';
      let lastNextCursor = null;
      let lastEtag = null;
      let lastItemsUrl = '/api/v1/items?limit=4';
      let count304Hits = 0;
      let showRawJson = false;

      function badgeClassForStatus(status) {
        if (status >= 200 && status < 400) return 'badge badge-ok';
        if (status === 422 || status === 429 || status === 409) return 'badge badge-warn';
        return 'badge badge-err';
      }

      function decodeBase64UrlCursor(cursorStr) {
        if (!cursorStr) return 'None (End of dataset or Page 1)';
        try {
          const base64 = cursorStr.replace(/-/g, '+').replace(/_/g, '/');
          const padded = base64 + '==='.slice((base64.length + 3) % 4);
          return cursorStr + ' -> ' + atob(padded);
        } catch (_e) {
          return cursorStr;
        }
      }

      function appendTelemetry(method, path, status, elapsedMs, requestId, note) {
        const row = document.createElement('div');
        row.className = 'log-entry';

        const left = document.createElement('div');
        left.className = 'log-left';

        const statusSpan = document.createElement('span');
        statusSpan.className = badgeClassForStatus(status);
        statusSpan.textContent = method + ' ' + status;
        left.appendChild(statusSpan);

        const pathSpan = document.createElement('strong');
        pathSpan.textContent = path;
        left.appendChild(pathSpan);

        if (note) {
          const noteSpan = document.createElement('span');
          noteSpan.className = 'text-note';
          noteSpan.textContent = '(' + note + ')';
          left.appendChild(noteSpan);
        }

        const right = document.createElement('div');
        right.className = 'log-right';
        right.textContent = elapsedMs.toFixed(1) + ' ms | X-Request-ID: ' + (requestId || 'n/a');

        row.appendChild(left);
        row.appendChild(right);
        telemetryLog.prepend(row);
      }

      function updateKpisFromHeaders(res, elapsedMs) {
        kpiLatencyVal.textContent = elapsedMs.toFixed(1) + ' ms';
        const pctLatency = Math.max(8, Math.min(100, 100 - (elapsedMs / 250) * 60));
        kpiLatencyBar.value = pctLatency;
        kpiLatencySub.textContent = elapsedMs < 250 ? 'Optimal (< 250ms SLO)' : 'Elevated latency';

        const limit = Number(res.headers.get('ratelimit-limit') || 0);
        const remaining = Number(res.headers.get('ratelimit-remaining') || 0);
        const reset = res.headers.get('ratelimit-reset');
        const policy = res.headers.get('ratelimit-policy');

        if (limit > 0) {
          kpiRlRemaining.textContent = remaining + ' / ' + limit;
          kpiRlBar.value = Math.max(0, Math.min(100, (remaining / limit) * 100));
        }
        if (policy) kpiRlPolicy.textContent = policy;
        if (reset) kpiRlReset.textContent = 'Window resets in ' + reset + 's';
      }

      function renderCatalogCards(items) {
        catalogCards.textContent = '';
        if (!items || items.length === 0) {
          const empty = document.createElement('div');
          empty.className = 'catalog-item';
          empty.textContent = 'No items matched this filter.';
          catalogCards.appendChild(empty);
          return;
        }

        items.forEach((item) => {
          const card = document.createElement('div');
          card.className = 'catalog-item';

          const top = document.createElement('div');
          top.className = 'catalog-item-top';

          const titleWrap = document.createElement('div');
          titleWrap.className = 'catalog-item-title';

          const idChip = document.createElement('span');
          idChip.className = 'catalog-item-id';
          idChip.textContent = item.id;
          titleWrap.appendChild(idChip);

          const nameSpan = document.createElement('span');
          nameSpan.textContent = item.name;
          titleWrap.appendChild(nameSpan);

          const catBadge = document.createElement('span');
          catBadge.className = 'badge badge-info';
          catBadge.textContent = item.category;

          top.appendChild(titleWrap);
          top.appendChild(catBadge);

          const summary = document.createElement('p');
          summary.className = 'catalog-item-summary';
          summary.textContent = item.summary;

          const foot = document.createElement('div');
          foot.className = 'catalog-item-foot';
          const slugSpan = document.createElement('span');
          slugSpan.textContent = 'slug: ' + item.slug;
          const dateSpan = document.createElement('span');
          dateSpan.textContent = 'createdAt: ' + item.createdAt;
          foot.appendChild(slugSpan);
          foot.appendChild(dateSpan);

          card.appendChild(top);
          card.appendChild(summary);
          card.appendChild(foot);
          catalogCards.appendChild(card);
        });
      }

      async function inspectSecurityHeaders() {
        const t0 = performance.now();
        const res = await fetch('/api/v1/items?limit=3');
        const elapsed = performance.now() - t0;
        updateKpisFromHeaders(res, elapsed);

        const controls = [
          {
            name: 'strict-transport-security',
            purpose: 'Enforces HTTPS for 2 years across all subdomains + HSTS preload list eligibility.'
          },
          {
            name: 'content-security-policy',
            purpose: 'Blocks unauthorized script/style execution and iframe embedding (frame-ancestors).'
          },
          {
            name: 'x-content-type-options',
            purpose: 'Prevents browser MIME-sniffing content-type confusion (nosniff).'
          },
          {
            name: 'x-frame-options',
            purpose: 'Legacy clickjacking defense paired with CSP frame-ancestors.'
          },
          {
            name: 'referrer-policy',
            purpose: 'Strips sensitive URL paths/query tokens when navigating cross-origin.'
          },
          {
            name: 'permissions-policy',
            purpose: 'Disables unused browser hardware APIs (camera, mic, geolocation, USB, payment).'
          },
          {
            name: 'cross-origin-opener-policy',
            purpose: 'Process-isolates browsing context against cross-origin window references.'
          },
          {
            name: 'cross-origin-resource-policy',
            purpose: 'Restricts cross-origin subresource loading to same-origin.'
          },
          {
            name: 'cache-control',
            purpose: 'Configures browser (max-age=60) and shared CDN edge (s-maxage=300, stale-while-revalidate).'
          },
          {
            name: 'etag',
            purpose: 'Deterministic SHA-256 weak ETag enabling 0-byte 304 Not Modified responses.'
          },
          {
            name: 'vary',
            purpose: 'Partitions CDN cache by Origin and Accept-Encoding to prevent cache poisoning.'
          },
          {
            name: 'ratelimit-policy',
            purpose: 'Advertises IETF sliding-window quota policy to API consumers.'
          },
          {
            name: 'x-request-id',
            purpose: 'Correlates client requests with backend structured JSON logs and RFC 9457 errors.'
          },
          {
            name: 'x-powered-by',
            expectAbsent: true,
            purpose: 'Suppressed to prevent passive Express/Node runtime fingerprinting.'
          }
        ];

        headersTbody.textContent = '';
        controls.forEach((ctrl) => {
          const val = res.headers.get(ctrl.name);
          const passed = ctrl.expectAbsent ? val === null : Boolean(val);

          const tr = document.createElement('tr');

          const tdStatus = document.createElement('td');
          const badge = document.createElement('span');
          badge.className = passed ? 'badge badge-ok' : 'badge badge-warn';
          badge.textContent = passed ? 'PASS' : 'WARN';
          tdStatus.appendChild(badge);

          const tdName = document.createElement('td');
          const strong = document.createElement('strong');
          strong.textContent = ctrl.name;
          tdName.appendChild(strong);

          const tdVal = document.createElement('td');
          const code = document.createElement('code');
          code.textContent = ctrl.expectAbsent
            ? (val === null ? 'Suppressed (Absent)' : val)
            : (val || 'Missing');
          tdVal.appendChild(code);

          const tdPurpose = document.createElement('td');
          tdPurpose.className = 'text-muted-cell';
          tdPurpose.textContent = ctrl.purpose;

          tr.appendChild(tdStatus);
          tr.appendChild(tdName);
          tr.appendChild(tdVal);
          tr.appendChild(tdPurpose);
          headersTbody.appendChild(tr);
        });
      }

      function buildItemsUrl(cursor) {
        const limit = selLimit.value || '4';
        const params = new URLSearchParams({ limit });
        if (activeCategory) params.set('category', activeCategory);
        if (cursor) params.set('cursor', cursor);
        return '/api/v1/items?' + params.toString();
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
        const reqId = res.headers.get('x-request-id');

        updateKpisFromHeaders(res, elapsed);

        const etag = res.headers.get('etag');
        if (etag) {
          lastEtag = etag;
          itemsEtagVal.textContent = etag;
          kpiEtagSub.textContent = 'Latest ETag: ' + etag;
          btnEtagCheck.disabled = false;
        }

        itemsMeta.textContent = '';
        const badge = document.createElement('span');
        badge.className = badgeClassForStatus(res.status);
        badge.textContent = 'HTTP ' + res.status;
        itemsMeta.appendChild(badge);
        const timeSpan = document.createElement('span');
        timeSpan.className = 'ml-gap';
        timeSpan.textContent = elapsed.toFixed(1) + ' ms | X-Request-ID: ' + (reqId || 'n/a');
        itemsMeta.appendChild(timeSpan);

        if (res.status === 304) {
          count304Hits += 1;
          kpi304Count.textContent = count304Hits + (count304Hits === 1 ? ' Hit (304)' : ' Hits (304)');
          appendTelemetry('GET', url, 304, elapsed, reqId, 'ETag 304 Not Modified - 0 B body');
          itemsOutput.textContent = '// HTTP 304 Not Modified: Weak ETag matched If-None-Match header. Zero payload bytes transferred.';
          return;
        }

        const body = await res.json();
        itemsOutput.textContent = JSON.stringify(body, null, 2);

        if (res.ok && body.data) {
          lastItemsUrl = url;
          lastNextCursor = body.pagination && body.pagination.nextCursor ? body.pagination.nextCursor : null;
          btnPageNext.disabled = !lastNextCursor;
          itemsCursorDecoded.textContent = decodeBase64UrlCursor(lastNextCursor);
          renderCatalogCards(body.data);
          appendTelemetry('GET', url, res.status, elapsed, reqId, body.data.length + ' items');
        } else {
          appendTelemetry('GET', url, res.status, elapsed, reqId, body.title || 'Error');
        }
      }

      // Tab Switching
      document.querySelectorAll('.tab-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
          document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
          btn.classList.add('active');
          const target = document.getElementById(btn.getAttribute('data-tab'));
          if (target) target.classList.add('active');
        });
      });

      // Toggle Raw JSON View
      document.getElementById('btn-toggle-raw').addEventListener('click', () => {
        showRawJson = !showRawJson;
        itemsOutput.classList.toggle('hidden', !showRawJson);
      });

      // Category Filter Chips
      document.querySelectorAll('#category-chips .filter-chip').forEach((chip) => {
        chip.addEventListener('click', () => {
          document.querySelectorAll('#category-chips .filter-chip').forEach((c) => c.classList.remove('active'));
          chip.classList.add('active');
          activeCategory = chip.getAttribute('data-category') || '';
          fetchItems(buildItemsUrl(null), null);
        });
      });

      selLimit.addEventListener('change', () => {
        fetchItems(buildItemsUrl(null), null);
      });

      document.getElementById('btn-page-first').addEventListener('click', () => {
        fetchItems(buildItemsUrl(null), null);
      });

      btnPageNext.addEventListener('click', () => {
        if (lastNextCursor) {
          fetchItems(buildItemsUrl(lastNextCursor), null);
        }
      });

      btnEtagCheck.addEventListener('click', () => {
        if (lastEtag) {
          fetchItems(lastItemsUrl, lastEtag);
        }
      });

      document.getElementById('btn-bad-cursor').addEventListener('click', () => {
        showRawJson = true;
        itemsOutput.classList.remove('hidden');
        fetchItems('/api/v1/items?limit=4&cursor=corrupted_non_base64_cursor', null);
      });

      document.getElementById('btn-refresh-headers').addEventListener('click', inspectSecurityHeaders);
      document.getElementById('btn-refresh-all').addEventListener('click', () => {
        inspectSecurityHeaders();
        fetchItems(buildItemsUrl(null), null);
      });

      document.getElementById('btn-clear-log').addEventListener('click', () => {
        telemetryLog.textContent = '';
      });

      // Contact & Error Lab Actions
      function renderContactResponse(res, elapsed, body, note) {
        const reqId = res.headers.get('x-request-id');
        const replayed = res.headers.get('idempotency-replayed');
        const rem = res.headers.get('ratelimit-remaining');
        const retryAfter = res.headers.get('retry-after');

        updateKpisFromHeaders(res, elapsed);

        contactMeta.textContent = '';
        const badge = document.createElement('span');
        badge.className = badgeClassForStatus(res.status);
        badge.textContent = 'HTTP ' + res.status;
        contactMeta.appendChild(badge);
        const detail = document.createElement('span');
        detail.className = 'ml-gap';
        detail.textContent = elapsed.toFixed(1) + ' ms | ' + (note || '');
        contactMeta.appendChild(detail);

        contactHeadersMeta.textContent =
          'Idempotency-Replayed: ' + (replayed || 'n/a') +
          ' | RateLimit-Remaining: ' + (rem || 'n/a') +
          (retryAfter ? ' | Retry-After: ' + retryAfter + 's' : '') +
          ' | X-Request-ID: ' + (reqId || 'n/a');

        contactOutput.textContent = JSON.stringify(body, null, 2);
        appendTelemetry(res.url.includes('non-existent') ? 'GET' : 'POST', new URL(res.url).pathname, res.status, elapsed, reqId, note);
      }

      document.getElementById('btn-new-idem').addEventListener('click', () => {
        inpIdem.value = 'idem-' + Math.random().toString(36).slice(2, 11);
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
        const isReplay = res.headers.get('idempotency-replayed') === 'true';
        renderContactResponse(
          res,
          elapsed,
          body,
          isReplay ? 'Idempotent Replay (Duplicate Prevented)' : (body.title || 'Created (201)')
        );
      });

      document.getElementById('btn-idem-conflict').addEventListener('click', async () => {
        const payload = {
          name: document.getElementById('inp-name').value,
          email: document.getElementById('inp-email').value,
          subject: 'MUTATED SUBJECT WITH SAME IDEMPOTENCY KEY ' + Date.now(),
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
        renderContactResponse(res, elapsed, body, 'Idempotency Payload Hash Mismatch');
      });

      document.getElementById('btn-post-invalid').addEventListener('click', async () => {
        const t0 = performance.now();
        const res = await fetch('/api/v1/contact', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'A',
            email: 'not-a-valid-email',
            subject: 'Hi',
            message: 'Short',
            unexpectedExtraProperty: 'Rejected by Zod .strict()'
          })
        });
        const elapsed = performance.now() - t0;
        const body = await res.json();
        renderContactResponse(res, elapsed, body, 'RFC 9457 Validation Error (422)');
      });

      document.getElementById('btn-bad-ctype').addEventListener('click', async () => {
        const t0 = performance.now();
        const res = await fetch('/api/v1/contact', {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: 'plain text body blocked by requireJsonContentType'
        });
        const elapsed = performance.now() - t0;
        const body = await res.json();
        renderContactResponse(res, elapsed, body, 'Unsupported Media Type (415)');
      });

      document.getElementById('btn-trigger-404').addEventListener('click', async () => {
        const t0 = performance.now();
        const res = await fetch('/api/v1/non-existent-endpoint');
        const elapsed = performance.now() - t0;
        const body = await res.json();
        renderContactResponse(res, elapsed, body, 'RFC 9457 Resource Not Found (404)');
      });

      inspectSecurityHeaders();
      fetchItems(buildItemsUrl(null), null);
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
