import type { Request, Response } from "express";
import { asyncHandler } from "../../utils/async-handler.js";
import { ApiError } from "../../utils/api-error.js";
import { prisma } from "../../config/prisma.config.ts";

export const registerOtp = asyncHandler(
  async (
    req: Request<{}, {}, { username: string; email: string, password: string }>,
    res: Response
  ) => {
    const { username, email, password } = req.body;

    const exitsUser = await prisma.user.findUnique({
      where: { username: username, email: email }
    });

    if(exitsUser){
      throw new ApiError(409, "User already exists");
    }

    const user = await prisma.user.create({
      data:{
        username: username, email: email,  password: password
      }
    })

    res.json({ message: "Login successful", user});
  }
);
