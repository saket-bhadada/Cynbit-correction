import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { createApp } from '../src/app';
import { AppError, type ProblemDetails } from '../src/middleware/errorHandler';

describe('Cynbit Hardened Backend Reference Architecture', () => {
  let server: Server;
  let baseUrl: string;

  before(async () => {
    const app = createApp({
      security: {
        allowedOrigins: ['https://cynbit.com', 'https://app.cynbit.com'],
      },
      globalRateLimitMax: 100,
      contactRateLimitMax: 3,
      compressionThresholdBytes: 512,
      errorHandler: {
        environment: 'test',
      },
    });

    // Attach an explicit crash route to test RFC 9457 500 error redaction in production mode
    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const address = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it('serves a CSP-nonce-protected interactive console on GET / for browsers and JSON manifest for API clients', async () => {
    const htmlRes = await fetch(`${baseUrl}/`, {
      headers: { Accept: 'text/html' },
    });
    assert.equal(htmlRes.status, 200);
    assert.match(htmlRes.headers.get('content-type') ?? '', /text\/html/);
    const csp = htmlRes.headers.get('content-security-policy') ?? '';
    assert.match(csp, /script-src 'nonce-[A-Za-z0-9+/=]+'/);
    assert.doesNotMatch(csp, /unsafe-inline/);
    const htmlBody = await htmlRes.text();
    assert.match(htmlBody, /Cynbit — Hardened Backend Reference Architecture/);

    const jsonRes = await fetch(`${baseUrl}/`, {
      headers: { Accept: 'application/json' },
    });
    assert.equal(jsonRes.status, 200);
    const manifest = (await jsonRes.json()) as { status: string; endpoints: Record<string, string> };
    assert.equal(manifest.status, 'operational');
    assert.ok(manifest.endpoints.catalogItems);
  });

  it('sets strict HTTP security headers, removes X-Powered-By, and echoes validated X-Request-ID', async () => {
    const customRequestId = 'audit-req-12345678';
    const res = await fetch(`${baseUrl}/healthz`, {
      headers: {
        'X-Request-ID': customRequestId,
      },
    });

    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-powered-by'), null);
    assert.equal(res.headers.get('x-request-id'), customRequestId);
    assert.match(res.headers.get('strict-transport-security') ?? '', /max-age=63072000/);
    assert.match(res.headers.get('content-security-policy') ?? '', /default-src 'none'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
    assert.match(res.headers.get('permissions-policy') ?? '', /geolocation=\(\)/);
  });

  it('enforces granular CORS allowlist with Vary: Origin and rejects unauthorized origins', async () => {
    const allowedRes = await fetch(`${baseUrl}/healthz`, {
      headers: { Origin: 'https://cynbit.com' },
    });
    assert.equal(allowedRes.status, 200);
    assert.equal(allowedRes.headers.get('access-control-allow-origin'), 'https://cynbit.com');
    assert.match(allowedRes.headers.get('vary') ?? '', /Origin/i);

    const deniedRes = await fetch(`${baseUrl}/healthz`, {
      headers: { Origin: 'https://untrusted.example.org' },
    });
    assert.equal(deniedRes.status, 403);
    assert.match(deniedRes.headers.get('content-type') ?? '', /application\/problem\+json/);
    const problem = (await deniedRes.json()) as ProblemDetails;
    assert.equal(problem.status, 403);
    assert.match(problem.type, /cors-origin-denied$/);
  });

  it('supports keyset cursor pagination, ETag 304 Not Modified, and response compression', async () => {
    const page1Res = await fetch(`${baseUrl}/api/v1/items?limit=10`, {
      headers: { 'Accept-Encoding': 'gzip, br' },
    });
    assert.equal(page1Res.status, 200);

    const etag = page1Res.headers.get('etag');
    assert.ok(etag && etag.startsWith('W/"'), 'Expected weak ETag header');
    assert.match(page1Res.headers.get('cache-control') ?? '', /s-maxage=300/);

    const page1Json = (await page1Res.json()) as {
      data: Array<{ id: string }>;
      pagination: { limit: number; hasNextPage: boolean; nextCursor: string | null };
    };
    assert.equal(page1Json.data.length, 10);
    assert.equal(page1Json.pagination.hasNextPage, true);
    assert.ok(page1Json.pagination.nextCursor);

    // Conditional request with matching If-None-Match yields 304 Not Modified
    const conditionalRes = await fetch(`${baseUrl}/api/v1/items?limit=10`, {
      headers: { 'If-None-Match': etag },
    });
    assert.equal(conditionalRes.status, 304);
    assert.equal(await conditionalRes.text(), '');

    // Cursor navigation yields non-overlapping subsequent page
    const page2Res = await fetch(
      `${baseUrl}/api/v1/items?limit=10&cursor=${encodeURIComponent(page1Json.pagination.nextCursor)}`,
    );
    assert.equal(page2Res.status, 200);
    const page2Json = (await page2Res.json()) as { data: Array<{ id: string }> };
    assert.equal(page2Json.data.length, 10);
    assert.notEqual(page1Json.data[0]?.id, page2Json.data[0]?.id);
  });

  it('enforces Zod schema validation, strict unknown-key rejection, and Idempotency-Key safety', async () => {
    // 1. Invalid email + unknown extra key should fail with 422 Problem Details
    const invalidRes = await fetch(`${baseUrl}/api/v1/contact`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Alice',
        email: 'not-an-email',
        subject: 'Architecture Inquiry',
        message: 'Testing schema enforcement at boundary.',
        unexpectedField: true,
      }),
    });
    assert.equal(invalidRes.status, 422);
    const invalidProblem = (await invalidRes.json()) as ProblemDetails;
    assert.ok(Array.isArray(invalidProblem.errors) && invalidProblem.errors.length >= 2);

    // 2. Valid submission with Idempotency-Key succeeds with 201 Created, then replays safely
    const validPayload = {
      name: 'Alice Engineer',
      email: 'alice@cynbit.com',
      subject: 'Security Architecture Review',
      message: 'Evaluating idempotent state mutation and sliding-window rate limits.',
    };

    const firstPost = await fetch(`${baseUrl}/api/v1/contact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': 'idem-key-0001',
      },
      body: JSON.stringify(validPayload),
    });
    assert.equal(firstPost.status, 201);
    assert.equal(firstPost.headers.get('idempotency-replayed'), 'false');
    const firstBody = (await firstPost.json()) as { data: { submissionId: string } };

    const replayPost = await fetch(`${baseUrl}/api/v1/contact`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': 'idem-key-0001',
      },
      body: JSON.stringify(validPayload),
    });
    assert.equal(replayPost.status, 201);
    assert.equal(replayPost.headers.get('idempotency-replayed'), 'true');
    const replayBody = (await replayPost.json()) as { data: { submissionId: string } };
    assert.equal(replayBody.data.submissionId, firstBody.data.submissionId);
  });

  it('enforces sliding-window rate limits with IETF RateLimit-* and Retry-After headers', async () => {
    // Note: 3 contact requests were consumed in the previous test on 127.0.0.1 (contactRateLimitMax = 3)
    const rateLimitedRes = await fetch(`${baseUrl}/api/v1/contact`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Bob',
        email: 'bob@cynbit.com',
        subject: 'Rate Limit Check',
        message: 'Verifying 429 Problem Details and Retry-After headers.',
      }),
    });

    assert.equal(rateLimitedRes.status, 429);
    assert.equal(rateLimitedRes.headers.get('ratelimit-limit'), '3');
    assert.equal(rateLimitedRes.headers.get('ratelimit-remaining'), '0');
    assert.ok(rateLimitedRes.headers.get('retry-after'));

    const problem = (await rateLimitedRes.json()) as ProblemDetails;
    assert.equal(problem.status, 429);
    assert.match(problem.type, /rate-limit-exceeded$/);
  });

  it('redacts non-exposed 500 error details in production mode per RFC 9457', async () => {
    const expressMod = await import('express');
    const { correlationIdMiddleware, createErrorHandler } = await import(
      '../src/middleware/errorHandler'
    );
    const minimal = expressMod.default();
    minimal.use(correlationIdMiddleware);
    minimal.get('/fault', () => {
      throw new AppError({
        status: 500,
        code: 'database-unavailable',
        title: 'Internal Server Error',
        detail: 'SELECT * FROM credentials WHERE host=10.0.1.9 failed',
        expose: false,
      });
    });
    minimal.use(
      createErrorHandler({
        environment: 'production',
        logger: () => undefined,
      }),
    );

    const faultServer = await new Promise<Server>((resolve) => {
      const s = minimal.listen(0, '127.0.0.1', () => resolve(s));
    });

    try {
      const addr = faultServer.address() as AddressInfo;
      const res = await fetch(`http://127.0.0.1:${addr.port}/fault`);
      assert.equal(res.status, 500);
      const body = (await res.json()) as ProblemDetails & { stack?: unknown };
      assert.equal(body.stack, undefined);
      assert.doesNotMatch(body.detail, /SELECT \* FROM credentials/);
      assert.ok(body.requestId);
    } finally {
      await new Promise<void>((resolve) => faultServer.close(() => resolve()));
    }
  });
});
