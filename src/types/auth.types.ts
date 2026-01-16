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
