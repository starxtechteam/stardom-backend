export const REDIS_KEYS = {
  blacklistToken: (token: string) => `users:blacklist:${token}`,
  userTemp: (hash: string) => `users:temp:${hash}`,
  registerOtp: (token: string) => `register:otp:${token}`,
  resendRegisterOTP: (token: string) => `register:resend:${token}`,
  
  loginOtp: (token: string) => `login:otp:${token}`,
  usernameTemp: (username: string) => `temp:username:${username}`,
  isotp: (token: string) =>  `otp:genarate:${token}`,
  otpVerify: (tokenHash: string) => `otp:verify:${tokenHash}`,
  identifier: (tokenHash: string) => `users:identifier:${tokenHash}`,
  identifierHash: (userHash: string) => `users:hash:${userHash}`,
};

export const REG_IP_KEY = (ip: string) => `register:ip:${ip}`;