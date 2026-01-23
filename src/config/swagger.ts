import swaggerJSDoc from "swagger-jsdoc";
import { ENV } from "./env.ts";

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Stardom APP API",
      version: "1.0.0",
      description: "Complete REST API documentation for Stardom APP - A social media platform with secure authentication and user management",
      contact: {
        name: "Stardom Team",
        url: "https://trinitycoin.ai",
      },
    },
    servers: [
      {
        url: `http://localhost:${ENV.PORT}` || "http://localhost:4000",
        description: "Development",
      },
      {
        url: "https://mining.trinitycoin.ai",
        description: "Production",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "JWT token obtained after successful login",
        },
      },
      schemas: {
        Error: {
          type: "object",
          properties: {
            error: {
              type: "string",
            },
            message: {
              type: "string",
            },
            statusCode: {
              type: "number",
            },
          },
        },
      },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: ["./src/routes/**/*.ts", "./src/routes/**/*.js", "./src/modules/**/*.ts"],
};

export const swaggerSpec = swaggerJSDoc(swaggerOptions);
