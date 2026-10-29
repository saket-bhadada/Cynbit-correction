import crypto from 'node:crypto';
import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { AppError } from '../middleware/errorHandler';
import { createRateLimiter, type RateLimitStore } from '../middleware/rateLimiter';
import {
  enforcePayloadSize,
  requireJsonContentType,
  sanitizedString,
  validateRequest,
} from '../middleware/validate';

export interface ServiceCatalogItem {
  id: string;
  slug: string;
  name: string;
  category: 'cloud-security' | 'identity' | 'observability' | 'compliance';
  summary: string;
  createdAt: string;
}

interface DecodedCursor {
  createdAt: string;
  id: string;
}

/**
 * Deterministic in-memory reference dataset ordered descending by `(createdAt, id)`.
 * Mirrors an indexed PostgreSQL table queried via composite keyset pagination:
 * `WHERE (created_at, id) < ($1, $2) ORDER BY created_at DESC, id DESC LIMIT $3 + 1`
 */
const CATALOG_ITEMS: readonly ServiceCatalogItem[] = Array.from({ length: 25 }, (_, index) => {
  const reverseIdx = 25 - index;
  const padded = String(reverseIdx).padStart(3, '0');
  const categories: ServiceCatalogItem['category'][] = [
    'cloud-security',
    'identity',
    'observability',
    'compliance',
  ];
  const category = categories[index % categories.length] ?? 'cloud-security';
  const day = String(Math.max(1, Math.min(28, reverseIdx))).padStart(2, '0');

  return {
    id: `svc_${padded}`,
    slug: `enterprise-module-${padded}`,
    name: `Cynbit Enterprise Hardening Module ${padded}`,
    category,
    summary:
      'Production-hardened backend service module featuring zero-trust transport security, automated schema enforcement, and distributed edge caching.',
    createdAt: `2026-09-${day}T12:00:00.000Z`,
  };
});

const CURSOR_SCHEMA = z
  .object({
    createdAt: z.string().datetime(),
    id: z.string().min(1).max(64),
  })
  .strict();

export function encodeCursor(cursor: DecodedCursor): string {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

export function decodeCursor(encoded: string): DecodedCursor {
  try {
    const json = Buffer.from(encoded, 'base64url').toString('utf8');
    const parsed: unknown = JSON.parse(json);
    const validated = CURSOR_SCHEMA.safeParse(parsed);
    if (!validated.success) {
      throw new Error('Cursor schema mismatch');
    }
    return validated.data;
  } catch {
    throw new AppError({
      status: 400,
      code: 'invalid-pagination-cursor',
      title: 'Invalid Pagination Cursor',
      detail: 'The supplied pagination cursor is malformed or corrupted.',
    });
  }
}

/**
 * Computes a deterministic weak entity tag (`W/"..."`) per RFC 9110 §8.8.1.
 * Weak ETags remain semantically valid across content-encoding transformations (`gzip` / `br`),
 * allowing CDN edges and browsers to negotiate `304 Not Modified` seamlessly alongside compression.
 */
export function computeWeakETag(payload: string): string {
  const hash = crypto.createHash('sha256').update(payload, 'utf8').digest('base64url').slice(0, 27);
  return `W/"${hash}"`;
}

/**
 * Evaluates RFC 9110 `If-None-Match` conditional headers using weak comparison.
 */
export function matchesIfNoneMatch(ifNoneMatchHeader: string | undefined, currentETag: string): boolean {
  if (!ifNoneMatchHeader) {
    return false;
  }

  const trimmed = ifNoneMatchHeader.trim();
  if (trimmed === '*') {
    return true;
  }

  const normalizeTag = (tag: string): string => tag.trim().replace(/^W\//i, '');
  const targetNormalized = normalizeTag(currentETag);

  return trimmed
    .split(',')
    .map(normalizeTag)
    .some((candidate) => candidate === targetNormalized);
}

const listItemsQuerySchema = z
  .object({
    limit: z.coerce
      .number()
      .int('limit must be an integer.')
      .min(1, 'limit must be at least 1.')
      .max(50, 'limit must not exceed 50.')
      .default(10),
    cursor: z.string().min(4).max(256).optional(),
    category: z
      .enum(['cloud-security', 'identity', 'observability', 'compliance'])
      .optional(),
  })
  .strict();

const contactBodySchema = z
  .object({
    name: sanitizedString(2, 100),
    email: z
      .string()
      .trim()
      .toLowerCase()
      .email('Must be a valid email address.')
      .max(254),
    company: sanitizedString(2, 120).optional(),
    subject: sanitizedString(4, 150),
    message: sanitizedString(10, 2000),
  })
  .strict();

const idempotencyHeaderSchema = z
  .object({
    'idempotency-key': z
      .string()
      .regex(
        /^[a-zA-Z0-9._-]{8,128}$/,
        'Idempotency-Key must be 8-128 alphanumeric, dot, underscore, or hyphen characters.',
      )
      .optional(),
  })
  .passthrough();

interface StoredIdempotentResponse {
  payloadHash: string;
  statusCode: number;
  body: Record<string, unknown>;
  createdAtMs: number;
}

export interface ExampleRouterOptions {
  rateLimitStore?: RateLimitStore;
  contactRateLimitMax?: number;
}

export function createExampleApiRouter(options: ExampleRouterOptions = {}): Router {
  const router = Router();
  const idempotencyCache = new Map<string, StoredIdempotentResponse>();
  const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

  const contactLimiter = createRateLimiter({
    limit: options.contactRateLimitMax ?? 5,
    windowMs: 60_000,
    policyName: 'contact-write',
    store: options.rateLimitStore,
  });

  /**
   * GET /healthz
   * Uncached readiness probe suitable for load balancers and Kubernetes ingress checks.
   */
  router.get('/healthz', (_req: Request, res: Response) => {
    res
      .status(200)
      .setHeader('Cache-Control', 'no-store')
      .json({
        status: 'ok',
        timestamp: new Date().toISOString(),
      });
  });

  /**
   * GET /api/v1/items
   * Demonstrates:
   * - Opaque keyset/cursor pagination (`O(log N)` index seek vs. `OFFSET` table scan)
   * - Deterministic weak `ETag` + `If-None-Match` -> `304 Not Modified`
   * - Explicit CDN + browser `Cache-Control` (`s-maxage`, `stale-while-revalidate`)
   * - Automatic `gzip` / `br` compression when negotiated via `Accept-Encoding`
   */
  router.get(
    '/api/v1/items',
    validateRequest({ query: listItemsQuerySchema }),
    (req: Request, res: Response, next: NextFunction) => {
      try {
        const { limit, cursor, category } = req.query as unknown as z.infer<
          typeof listItemsQuerySchema
        >;

        let filtered = category
          ? CATALOG_ITEMS.filter((item) => item.category === category)
          : CATALOG_ITEMS;

        if (cursor) {
          const decoded = decodeCursor(cursor);
          filtered = filtered.filter(
            (item) =>
              item.createdAt < decoded.createdAt ||
              (item.createdAt === decoded.createdAt && item.id < decoded.id),
          );
        }

        // Fetch `limit + 1` rows to detect whether a subsequent page exists without `COUNT(*)`
        const slice = filtered.slice(0, limit + 1);
        const hasNextPage = slice.length > limit;
        const pageItems = hasNextPage ? slice.slice(0, limit) : slice;
        const lastItem = pageItems[pageItems.length - 1];
        const nextCursor =
          hasNextPage && lastItem
            ? encodeCursor({ createdAt: lastItem.createdAt, id: lastItem.id })
            : null;

        const responsePayload = {
          data: pageItems,
          pagination: {
            limit,
            hasNextPage,
            nextCursor,
          },
        };

        const serialized = JSON.stringify(responsePayload);
        const etag = computeWeakETag(serialized);

        res.setHeader(
          'Cache-Control',
          'public, max-age=60, s-maxage=300, stale-while-revalidate=60',
        );
        res.setHeader('ETag', etag);
        res.vary('Accept-Encoding');

        if (matchesIfNoneMatch(req.header('if-none-match'), etag)) {
          res.status(304).end();
          return;
        }

        res.status(200).type('application/json; charset=utf-8').send(serialized);
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/contact
   * Demonstrates:
   * - Strict route-level rate limiting (`5 req / 60s`)
   * - `Content-Type: application/json` enforcement (415 on mismatch)
   * - Strict 16 KiB payload limit (413 on excess)
   * - Strict `.strict()` Zod schema validation & control-character sanitization (422 on invalid fields)
   * - `Idempotency-Key` safe retry handling (409 on payload mutation with identical key)
   */
  router.post(
    '/api/v1/contact',
    contactLimiter,
    requireJsonContentType,
    enforcePayloadSize(16 * 1024),
    validateRequest({
      headers: idempotencyHeaderSchema,
      body: contactBodySchema,
    }),
    (req: Request, res: Response, next: NextFunction) => {
      try {
        const body = req.body as z.infer<typeof contactBodySchema>;
        const idempotencyKey = req.header('idempotency-key');
        const payloadHash = crypto
          .createHash('sha256')
          .update(JSON.stringify(body), 'utf8')
          .digest('hex');

        if (idempotencyKey) {
          const existing = idempotencyCache.get(idempotencyKey);
          const now = Date.now();

          if (existing && now - existing.createdAtMs < IDEMPOTENCY_TTL_MS) {
            if (existing.payloadHash !== payloadHash) {
              throw new AppError({
                status: 409,
                code: 'idempotency-key-conflict',
                title: 'Idempotency Key Conflict',
                detail:
                  'The provided Idempotency-Key was already used with a different request payload.',
              });
            }

            res
              .status(existing.statusCode)
              .setHeader('Cache-Control', 'no-store')
              .setHeader('Idempotency-Replayed', 'true')
              .json(existing.body);
            return;
          }
        }

        const submissionResponse = {
          data: {
            submissionId: `sub_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
            status: 'accepted',
            receivedAt: new Date().toISOString(),
            contact: {
              name: body.name,
              email: body.email,
              subject: body.subject,
            },
          },
        };

        if (idempotencyKey) {
          idempotencyCache.set(idempotencyKey, {
            payloadHash,
            statusCode: 201,
            body: submissionResponse,
            createdAtMs: Date.now(),
          });
        }

        res
          .status(201)
          .setHeader('Cache-Control', 'no-store')
          .setHeader('Idempotency-Replayed', 'false')
          .json(submissionResponse);
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
