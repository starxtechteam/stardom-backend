import { createClient, RedisClientType } from 'redis';
import { REDIS_KEYS } from '../constants/redisKeys.ts';
import { ENV } from '../config/env.ts';

export type AppRedisClient = RedisClientType;

const redisClient: AppRedisClient = createClient({
  socket: {
    host: ENV.REDIS_HOST ?? '127.0.0.1',
    port: ENV.REDIS_PORT ? Number(ENV.REDIS_PORT) : 6379,

    // ✅ Correct v4 reconnect strategy
    reconnectStrategy: (retries: number) => {
      console.error(`🔄 Redis reconnecting... Attempt: ${retries}`);
      return Math.min(retries * 100, 3000); // max 3s
    },
  },
});

redisClient.on('connect', () => {
  console.log('✅ Redis socket connected');
});

redisClient.on('ready', () => {
  console.log('🚀 Redis ready to use');
});

redisClient.on('reconnecting', () => {
  console.log('🔄 Redis reconnecting...');
});

redisClient.on('end', () => {
  console.log('🚫 Redis connection closed');
});

redisClient.on('error', (err: Error) => {
  console.error('❌ Redis Error:', err.message);
});

export async function connectRedis(): Promise<void> {
  if (!redisClient.isOpen) {
    try {
      await redisClient.connect();
      console.log('🔗 Redis connection established');
    } catch (error) {
      console.error('❌ Redis connection failed:', error);
      throw error;
    }
  }
}

const shutdownRedis = async (): Promise<void> => {
  try {
    if (redisClient.isOpen) {
      await redisClient.quit();
      console.log('👋 Redis disconnected gracefully');
    }
  } catch (error) {
    console.error('❌ Error while disconnecting Redis:', error);
  } finally {
    process.exit(0);
  }
};

process.on('SIGINT', shutdownRedis);
process.on('SIGTERM', shutdownRedis);

export { redisClient, REDIS_KEYS };