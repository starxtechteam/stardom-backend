export type DeviceInfo = {
  deviceName: string;
  deviceType: string;
  os: string;
  browser: string;
};

export type LoginAttempts = DeviceInfo & {
  identifier: string;
  ipAddress: string;
  success: boolean;
  message: string;
};

export type AuthSession = {
  id: string,
  userId: string,
  deviceName: string | null,
  ipAddress: string | null,
  userAgent: string | null,
  role: "user" | "admin",
  token: string,
}
