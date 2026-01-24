import {
  CloudFrontClient,
  CreateInvalidationCommand,
  CreateInvalidationCommandInput,
} from "@aws-sdk/client-cloudfront";
import logger from "../utils/logger.ts";
import { ENV } from "./env.ts";

const cloudfront = new CloudFrontClient({
  region: ENV.AWS_REGION,
  credentials: {
    accessKeyId: ENV.AWS_ACCESS_KEY_ID,
    secretAccessKey: ENV.AWS_SECRET_ACCESS_KEY,
  },
});

export const invalidateCache = async (paths: string[] = ["/*"]): Promise<void> => {
  try {
    const params: CreateInvalidationCommandInput = {
      DistributionId: ENV.CLOUDFRONT_DISTRIBUTION_ID,
      InvalidationBatch: {
        CallerReference: Date.now().toString(),
        Paths: {
          Quantity: paths.length,
          Items: paths,
        },
      },
    };

    const command = new CreateInvalidationCommand(params);
    const res = await cloudfront.send(command);

    logger.info(
      "🚀 Cache invalidation started:",
      res.Invalidation?.Id ?? "unknown-id"
    );
  } catch (err: unknown) {
    const error = err as Error;
    logger.error("❌ CloudFront invalidation failed:", error.message);
  }
};
