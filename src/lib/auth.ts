import jwt from "jsonwebtoken";
import { auth } from "@clerk/nextjs/server"
import { NextRequest } from "next/server";

const SECRET_KEY = process.env.JWT_SECRET as string; // Load from .env

// ✅ Function to verify JWT token
export function verifyToken(token: string) {
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    return decoded as { id: string; role: string };
  } catch (error) {
    return null; // Invalid token
  }
}

export async function verifyAuth(req: NextRequest) {
  try {
    const authResponse = await auth();
    console.log("Auth response:", authResponse); // Detailed debug log
    return authResponse;
  } catch (error) {
    console.error("Auth error:", error);
    return null;
  }
}
