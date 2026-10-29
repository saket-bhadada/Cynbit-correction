import crypto from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type Redis from 'ioredis';
import { AppError } from './errorHandler';

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  /** Seconds until the oldest request in the window expires (or window resets). */
  resetSeconds: number;
  /** Seconds client must wait before retrying when `allowed === false`. */
  retryAfterSeconds: number;
}

export interface RateLimitStore {
  consume(key: string, limit: number, windowMs: number): Promise<RateLimitResult>;
}

/**
 * Atomic Lua script implementing a true sliding-window log in Redis sorted sets:
 * 1. Evicts entries older than `now - windowMs`
 * 2. Counts active entries in the current window
 * 3. Inserts the current request member if below `limit`
 * 4. Computes accurate TTL / retry-after from the oldest active entry
 */
const SLIDING_WINDOW_LUA = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

local window_start = now - window_ms
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

local current_count = redis.call('ZCARD', key)
local allowed = 0

if current_count < limit then
  redis.call('ZADD', key, now, member)
  redis.call('PEXPIRE', key, window_ms)
  current_count = current_count + 1
  allowed = 1
end

local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local reset_ms = window_ms
if oldest[2] ~= nil then
  reset_ms = math.max(1, (tonumber(oldest[2]) + window_ms) - now)
end

return { allowed, current_count, reset_ms }
`;

/**
 * Distributed Redis-backed sliding-window store safe across horizontally scaled replicas.
 */
export class RedisSlidingWindowStore implements RateLimitStore {
  private readonly redis: Redis;
  private readonly keyPrefix: string;

  constructor(redisClient: Redis, keyPrefix = 'rl:sw:') {
    this.redis = redisClient;
    this.keyPrefix = keyPrefix;
  }

  public async consume(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    const now = Date.now();
    const member = `${now}:${crypto.randomUUID()}`;
    const fullKey = `${this.keyPrefix}${key}`;

    const raw = (await this.redis.eval(
      SLIDING_WINDOW_LUA,
      1,
      fullKey,
      String(now),
      String(windowMs),
      String(limit),
      member,
    )) as [number, number, number];

    const allowed = raw[0] === 1;
    const count = Number(raw[1]);
    const resetMs = Number(raw[2]);
    const resetSeconds = Math.max(1, Math.ceil(resetMs / 1000));

    return {
      allowed,
      limit,
      remaining: allowed ? Math.max(0, limit - count) : 0,
      resetSeconds,
      retryAfterSeconds: allowed ? 0 : resetSeconds,
    };
  }
}

/**
 * Bounded in-memory sliding-window store for local development, CI testing, or fallback resilience.
 */
export class MemorySlidingWindowStore implements RateLimitStore {
  private readonly buckets = new Map<string, number[]>();
  private readonly maxTrackedKeys: number;

  constructor(maxTrackedKeys = 10_000) {
    this.maxTrackedKeys = maxTrackedKeys;
  }

  public async consume(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = now - windowMs;

    const existing = this.buckets.get(key) ?? [];
    const activeTimestamps = existing.filter((ts) => ts > windowStart);

    if (activeTimestamps.length >= limit) {
      this.buckets.set(key, activeTimestamps);
      const oldest = activeTimestamps[0] ?? now;
      const resetSeconds = Math.max(1, Math.ceil((oldest + windowMs - now) / 1000));
      return {
        allowed: false,
        limit,
        remaining: 0,
        resetSeconds,
        retryAfterSeconds: resetSeconds,
      };
    }

    activeTimestamps.push(now);

    // Prevent unbounded memory growth under high cardinality keys
    if (!this.buckets.has(key) && this.buckets.size >= this.maxTrackedKeys) {
      const oldestKey = this.buckets.keys().next().value;
      if (oldestKey !== undefined) {
        this.buckets.delete(oldestKey);
      }
    }

    this.buckets.set(key, activeTimestamps);
    const oldest = activeTimestamps[0] ?? now;
    const resetSeconds = Math.max(1, Math.ceil((oldest + windowMs - now) / 1000));

    return {
      allowed: true,
      limit,
      remaining: Math.max(0, limit - activeTimestamps.length),
      resetSeconds,
      retryAfterSeconds: 0,
    };
  }
}

export interface RateLimiterOptions {
  /** Maximum permitted requests within `windowMs`. */
  limit: number;
  /** Sliding window duration in milliseconds. */
  windowMs: number;
  /** Logical namespace prefix separating global vs. route-specific policies (e.g., `api`, `contact`). */
  policyName?: string;
  /** Backing store (RedisSlidingWindowStore in production; defaults to MemorySlidingWindowStore). */
  store?: RateLimitStore;
  /** Custom client identifier resolver. Uses Express `req.ip` (respecting `trust proxy`). */
  keyGenerator?: (req: Request) => string;
  /** If true, falls back to allowing traffic when backing store throws an unexpected error. */
  failOpen?: boolean;
}

/**
 * Sliding-window rate-limiting middleware emitting IETF draft-standard `RateLimit-*` headers:
 * - `RateLimit-Limit`
 * - `RateLimit-Remaining`
 * - `RateLimit-Reset`
 * - `RateLimit-Policy`
 * And `Retry-After` + RFC 9457 `429 Too Many Requests` when budget is exhausted.
 */
export function createRateLimiter(options: RateLimiterOptions): RequestHandler {
  const {
    limit,
    windowMs,
    policyName = 'default',
    store = new MemorySlidingWindowStore(),
    keyGenerator = (req: Request) => req.ip || req.socket.remoteAddress || 'unknown',
    failOpen = true,
  } = options;

  const windowSeconds = Math.max(1, Math.ceil(windowMs / 1000));
  const policyHeader = `${limit};w=${windowSeconds}`;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const clientKey = `${policyName}:${keyGenerator(req)}`;

    try {
      const result = await store.consume(clientKey, limit, windowMs);

      res.setHeader('RateLimit-Limit', String(result.limit));
      res.setHeader('RateLimit-Remaining', String(result.remaining));
      res.setHeader('RateLimit-Reset', String(result.resetSeconds));
      res.setHeader('RateLimit-Policy', policyHeader);

      if (!result.allowed) {
        next(
          new AppError({
            status: 429,
            code: 'rate-limit-exceeded',
            title: 'Too Many Requests',
            detail: `Rate limit of ${limit} requests per ${windowSeconds}s window exceeded. Please retry after ${result.retryAfterSeconds}s.`,
            headers: {
              'Retry-After': String(result.retryAfterSeconds),
            },
          }),
        );
        return;
      }

      next();
    } catch (error) {
      if (failOpen) {
        next();
        return;
      }
      next(error);
    }
  };
}
