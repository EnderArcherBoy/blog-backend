import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();

export async function GET(req: NextRequest) {
  try {
    // Get the authorization header and validate format
    const authHeader = req.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: "Invalid authorization header" }, { status: 401 });
    }

    // Verify JWT_SECRET exists
    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
      console.error("JWT_SECRET is not defined");
      return NextResponse.json({ error: "Server configuration error" }, { status: 500 });
    }

    try {
      // Extract token and decode
      const token = authHeader.split(' ')[1];
      const decodedToken = jwt.verify(token, JWT_SECRET) as {
        id: string;
        role: string;
      };

      if (!decodedToken || !decodedToken.id) {
        return NextResponse.json({ error: "Invalid token" }, { status: 401 });
      }

      // Check if requester is admin
      const requester = await prisma.user.findUnique({ 
        where: { id: decodedToken.id },
        select: { id: true, role: true }
      });

      if (!requester || requester.role !== "admin") {
        return NextResponse.json({ error: "Only admins can view users" }, { status: 403 });
      }

      // Fetch all users
      const users = await prisma.user.findMany({
        select: { 
          id: true, 
          email: true, 
          username: true, 
          role: true, 
          createdAt: true 
        },
        orderBy: {
          createdAt: 'desc'
        }
      });

      return NextResponse.json({
        success: true,
        users,
        total: users.length
      });

    } catch (jwtError) {
      console.error("JWT verification error:", jwtError);
      return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    }

  } catch (error) {
    console.error("Error fetching users:", error);
    return NextResponse.json({ 
      error: "Failed to fetch users",
      details: error instanceof Error ? error.message : "Unknown error"
    }, { status: 500 });
  }
}
