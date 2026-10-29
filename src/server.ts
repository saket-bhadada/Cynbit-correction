import Redis from 'ioredis';
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
  redisClient = new Redis(redisUrl, {
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
  });
  rateLimitStore = new RedisSlidingWindowStore(redisClient);
} else {
  rateLimitStore = new MemorySlidingWindowStore();
}

const app = createApp({
  rateLimitStore,
});

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

async function shutdown(signal: string): Promise<void> {
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
}

process.on('SIGINT', () => {
  void shutdown('SIGINT');
});
process.on('SIGTERM', () => {
  void shutdown('SIGTERM');
});
