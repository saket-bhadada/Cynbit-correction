import type Redis from 'ioredis';
import { createApp } from './app';
import {
  MemorySlidingWindowStore,
  RedisSlidingWindowStore,
  type RateLimitStore,
} from './middleware/rateLimiter';

const port = Number.parseInt(process.env.PORT ?? '3000', 10);
const redisUrl = process.env.REDIS_URL;

let redisClient: Redis | undefined;
let rateLimitStore: RateLimitStore;

if (redisUrl) {
  // Lazy-require ioredis only when REDIS_URL is explicitly configured
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const IORedis = require('ioredis') as typeof import('ioredis').default;
  redisClient = new IORedis(redisUrl, {
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
  });
  rateLimitStore = new RedisSlidingWindowStore(redisClient);
} else {
  rateLimitStore = new MemorySlidingWindowStore();
}

export const app = createApp({
  rateLimitStore,
});

export default app;

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Object.assign(app, module.exports, {
    default: app,
    app,
  });
}

// Only bind a local TCP listener when running outside serverless environments (e.g., not on Vercel)
if (!process.env.VERCEL && require.main === module) {
  const server = app.listen(port, () => {
    console.log(
      JSON.stringify({
        level: 'info',
        event: 'server_started',
        port,
        rateLimitBackend: redisUrl ? 'redis' : 'memory',
        timestamp: new Date().toISOString(),
      }),
    );
  });

  const shutdown = async (signal: string): Promise<void> => {
    console.log(
      JSON.stringify({
        level: 'info',
        event: 'server_shutting_down',
        signal,
        timestamp: new Date().toISOString(),
      }),
    );

    server.close(async () => {
      if (redisClient) {
        await redisClient.quit().catch(() => undefined);
      }
      process.exit(0);
    });
  };

  process.on('SIGINT', () => {
    void shutdown('SIGINT');
  });
  process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
}
