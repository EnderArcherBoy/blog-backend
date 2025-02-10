import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { auth } from "@clerk/nextjs/server";

const prisma = new PrismaClient();

export async function PATCH(req: NextRequest) {
  try {
    const { userId } = await auth(); // Get user ID from Clerk auth
    if (!userId) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Fetch the current user from the database
    const currentUser = await prisma.user.findUnique({ where: { id: userId } });

    if (!currentUser || currentUser.role !== "admin") {
      return NextResponse.json({ error: "Forbidden: Only admins can change roles" }, { status: 403 });
    }

    // Parse the request body
    const { email, role } = await req.json();

    // Ensure the new role is valid
    if (!["reader", "writer", "admin"].includes(role)) {
      return NextResponse.json({ error: "Invalid role specified" }, { status: 400 });
    }

    // Update the user's role
    const updatedUser = await prisma.user.update({
      where: { email },
      data: { role },
    });

    return NextResponse.json({ message: "Role updated successfully", user: updatedUser }, { status: 200 });

  } catch (error) {
    console.error("Error updating user role:", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}
