import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { auth } from "@clerk/nextjs/server";
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();

// ✅ PATCH: Update user role (Admin Only)
export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
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
      const admin = await prisma.user.findUnique({ 
        where: { id: decodedToken.id },
        select: { id: true, role: true }
      });

      if (!admin || admin.role !== "admin") {
        return NextResponse.json({ error: "Only admins can update users" }, { status: 403 });
      }

      const { role } = await req.json();
      if (!["admin", "writer", "reader"].includes(role)) {
        return NextResponse.json({ error: "Invalid role" }, { status: 400 });
      }

      const updatedUser = await prisma.user.update({
        where: { id: params.id },
        data: { role },
        select: {
          id: true,
          email: true,
          username: true,
          role: true
        }
      });

      return NextResponse.json({
        success: true,
        message: "User role updated successfully",
        user: updatedUser
      });

    } catch (jwtError) {
      console.error("JWT verification error:", jwtError);
      return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    }

  } catch (error) {
    console.error("Error updating user role:", error);
    return NextResponse.json({
      error: "Failed to update user",
      details: error instanceof Error ? error.message : "Unknown error"
    }, { status: 500 });
  }
}

// ✅ DELETE: Remove user (Admin Only)
export async function DELETE(req: NextRequest, { params }: { params: { id: string } }) {
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
      const admin = await prisma.user.findUnique({ 
        where: { id: decodedToken.id },
        select: { id: true, role: true }
      });

      if (!admin || admin.role !== "admin") {
        return NextResponse.json({ error: "Only admins can delete users" }, { status: 403 });
      }

      // Prevent admin from deleting themselves
      if (decodedToken.id === params.id) {
        return NextResponse.json({ error: "Cannot delete your own account" }, { status: 400 });
      }

      // Check if user exists before deletion
      const userToDelete = await prisma.user.findUnique({
        where: { id: params.id },
        select: {
          id: true,
          email: true,
          username: true,
          role: true,
          createdAt: true
        }
      });

      if (!userToDelete) {
        return NextResponse.json({ error: "User not found" }, { status: 404 });
      }

      // Delete the user
      await prisma.user.delete({ where: { id: params.id } });

      return NextResponse.json({
        success: true,
        message: "User deleted successfully",
        deletedUser: {
          ...userToDelete,
          deletedAt: new Date().toISOString()
        }
      });

    } catch (jwtError) {
      console.error("JWT verification error:", jwtError);
      return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    }

  } catch (error) {
    console.error("Error deleting user:", error);
    return NextResponse.json({ 
      error: "Failed to delete user",
      details: error instanceof Error ? error.message : "Unknown error"
    }, { status: 500 });
  }
}
