export const REDIS_KEYS = {
  blacklistToken: (token: string) => `users:blacklist:${token}`,
  userTemp: (hash: string) => `users:temp:${hash}`,
  registerOtp: (token: string) => `register:otp:${token}`,
  usernameTemp: (username: string) => `temp:username:${username}`
};

export const REG_IP_KEY = (ip: string) => `register:ip:${ip}`;