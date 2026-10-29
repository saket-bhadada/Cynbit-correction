import compression from 'compression';
import express, { type Express } from 'express';
import {
  correlationIdMiddleware,
  createErrorHandler,
  notFoundHandler,
  type ErrorHandlerConfig,
} from './middleware/errorHandler';
import { createRateLimiter, type RateLimitStore } from './middleware/rateLimiter';
import {
  createCorsMiddleware,
  createSecurityHeadersMiddleware,
  type SecurityMiddlewareOptions,
} from './middleware/securityHeaders';
import { createDashboardRouter } from './routes/dashboard';
import { createExampleApiRouter } from './routes/exampleApi';

export interface AppConfig {
  security?: SecurityMiddlewareOptions;
  rateLimitStore?: RateLimitStore;
  globalRateLimitMax?: number;
  globalRateLimitWindowMs?: number;
  contactRateLimitMax?: number;
  errorHandler?: ErrorHandlerConfig;
  /** Minimum byte threshold before gzip/br compression is applied. Defaults to 1024 bytes. */
  compressionThresholdBytes?: number;
}

/**
 * Constructs the hardened Express reference application with a deterministic middleware pipeline:
 * 1. Proxy awareness & server fingerprint removal (`x-powered-by` disabled, manual semantic `etag`)
 * 2. Correlation ID assignment (`X-Request-ID`)
 * 3. Transport & browser security headers (`Helmet` + `Permissions-Policy`)
 * 4. Explicit allowlist CORS negotiation with `Vary: Origin`
 * 5. Dynamic response compression (`br` / `gzip` above threshold)
 * 6. Global sliding-window rate limiting (`RateLimit-*` IETF headers)
 * 7. Bounded JSON ingestion parser (`64kb` global ceiling)
 * 8. Versioned API routes (`/api/v1/*`)
 * 9. Standardized RFC 9457 (`application/problem+json`) 404 & error boundary
 */
export function createApp(config: AppConfig = {}): Express {
  const app = express();

  app.disable('x-powered-by');
  app.set('etag', false);
  app.set('trust proxy', 1);

  // 1. Distributed tracing / correlation ID
  app.use(correlationIdMiddleware);

  // 2. Security headers & Permissions-Policy
  app.use(createSecurityHeadersMiddleware());

  // 3. Granular allowlist CORS
  app.use(createCorsMiddleware(config.security));

  // 4. Response compression (Brotli & Gzip negotiated via Accept-Encoding)
  app.use(
    compression({
      threshold: config.compressionThresholdBytes ?? 1024,
    }),
  );

  // 5. Global baseline rate limiter
  app.use(
    createRateLimiter({
      limit: config.globalRateLimitMax ?? 100,
      windowMs: config.globalRateLimitWindowMs ?? 60_000,
      policyName: 'global-api',
      store: config.rateLimitStore,
    }),
  );

  // 6. Bounded JSON body parser
  app.use(
    express.json({
      limit: '64kb',
      strict: true,
    }),
  );

  // 7. Interactive CSP-nonce root console & versioned API routes
  app.use(createDashboardRouter());
  app.use(
    createExampleApiRouter({
      rateLimitStore: config.rateLimitStore,
      contactRateLimitMax: config.contactRateLimitMax,
    }),
  );

  // 8. Unmatched route & centralized RFC 9457 error handling
  app.use(notFoundHandler);
  app.use(createErrorHandler(config.errorHandler));

  return app;
}

export const app = createApp();
export default app;

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Object.assign(app, module.exports, {
    default: app,
    app,
    createApp,
  });
}


