import cors, { type CorsOptions } from 'cors';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import helmet from 'helmet';
import { AppError } from './errorHandler';

export interface SecurityMiddlewareOptions {
  /**
   * Explicit list of allowed cross-origin browser origins (e.g., `["https://cynbit.com"]`).
   * Wildcard (`*`) is intentionally prohibited when credentials may be exchanged.
   */
  allowedOrigins?: string[];
  /**
   * Whether cross-origin requests may carry cookies or Authorization headers.
   * Defaults to `true` when paired with an explicit origin allowlist.
   */
  allowCredentials?: boolean;
  /**
   * Max-Age in seconds for browser preflight (`OPTIONS`) caching. Defaults to 600s (10m).
   */
  preflightMaxAgeSeconds?: number;
}

/**
 * Parses comma-separated origins from environment configuration and strips trailing slashes.
 */
export function parseAllowedOrigins(rawOrigins?: string): string[] {
  const source = rawOrigins ?? process.env.CORS_ALLOWED_ORIGINS ?? 'https://cynbit.com,https://app.cynbit.com';
  return source
    .split(',')
    .map((origin) => origin.trim().replace(/\/+$/, ''))
    .filter((origin) => origin.length > 0 && origin !== '*');
}

/**
 * Returns an array of hardened HTTP security header middlewares tailored for modern API backends:
 * - Strict-Transport-Security (2 years + includeSubDomains + preload)
 * - Strict API Content-Security-Policy (`default-src 'none'; frame-ancestors 'none'`)
 * - `X-Content-Type-Options: nosniff` & `X-Frame-Options: DENY`
 * - `Referrer-Policy: strict-origin-when-cross-origin`
 * - Cross-Origin isolation headers (`COOP`, `CORP`)
 * - Restrictive `Permissions-Policy` disabling unused browser hardware/tracking APIs
 */
export function createSecurityHeadersMiddleware(): RequestHandler[] {
  const helmetMiddleware = helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    strictTransportSecurity: {
      maxAge: 63_072_000, // 2 years in seconds (OWASP / HSTS preload baseline)
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin',
    },
    frameguard: {
      action: 'deny',
    },
    xContentTypeOptions: true,
    xDnsPrefetchControl: {
      allow: false,
    },
    xPermittedCrossDomainPolicies: {
      permittedPolicies: 'none',
    },
    crossOriginOpenerPolicy: {
      policy: 'same-origin',
    },
    crossOriginResourcePolicy: {
      policy: 'same-origin',
    },
    hidePoweredBy: true,
  });

  const permissionsPolicyMiddleware: RequestHandler = (
    _req: Request,
    res: Response,
    next: NextFunction,
  ): void => {
    res.setHeader(
      'Permissions-Policy',
      'accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), browsing-topics=()',
    );
    next();
  };

  return [helmetMiddleware, permissionsPolicyMiddleware];
}

/**
 * Builds a strict, allowlist-driven CORS middleware that:
 * 1. Permits server-to-server or same-origin requests (including same-host browser POSTs).
 * 2. Echoes the exact matched `Origin` with `Vary: Origin` to prevent CDN cache poisoning.
 * 3. Rejects unauthorized cross-origin requests with a deterministic 403 Problem Details error.
 */
export function createCorsMiddleware(options: SecurityMiddlewareOptions = {}): RequestHandler {
  const allowedOriginSet = new Set(
    (options.allowedOrigins ?? parseAllowedOrigins()).map((o) => o.replace(/\/+$/, '')),
  );
  const allowCredentials = options.allowCredentials ?? true;
  const maxAge = options.preflightMaxAgeSeconds ?? 600;

  const ensureVaryOrigin: RequestHandler = (_req: Request, res: Response, next: NextFunction) => {
    res.vary('Origin');
    next();
  };

  const configuredCors = cors((req: Request, callback) => {
    const requestOrigin = req.header('origin');

    // Non-browser or same-origin GET/HEAD navigation requests do not include an Origin header
    if (!requestOrigin) {
      callback(null, { origin: false });
      return;
    }

    const normalized = requestOrigin.replace(/\/+$/, '');

    // Check if the browser Origin matches the server's own Host header (same-origin POST/PUT/DELETE)
    const hostHeader = req.header('x-forwarded-host') ?? req.header('host');
    let isSameHost = false;
    if (hostHeader) {
      try {
        const parsedOrigin = new URL(normalized);
        isSameHost = parsedOrigin.host.toLowerCase() === hostHeader.split(',')[0]?.trim().toLowerCase();
      } catch {
        isSameHost = false;
      }
    }

    if (isSameHost || allowedOriginSet.has(normalized)) {
      const corsOptions: CorsOptions = {
        origin: true,
        methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: [
          'Accept',
          'Authorization',
          'Content-Type',
          'If-None-Match',
          'Idempotency-Key',
          'X-Request-ID',
        ],
        exposedHeaders: [
          'ETag',
          'Idempotency-Replayed',
          'RateLimit-Limit',
          'RateLimit-Policy',
          'RateLimit-Remaining',
          'RateLimit-Reset',
          'Retry-After',
          'X-Request-ID',
        ],
        credentials: allowCredentials,
        maxAge,
        optionsSuccessStatus: 204,
      };
      callback(null, corsOptions);
      return;
    }

    callback(
      new AppError({
        status: 403,
        code: 'cors-origin-denied',
        title: 'Cross-Origin Request Denied',
        detail: 'The requesting Origin is not authorized by the server CORS policy.',
      }),
    );
  });

  return (req: Request, res: Response, next: NextFunction): void => {
    ensureVaryOrigin(req, res, () => {
      configuredCors(req, res, next);
    });
  };
}
