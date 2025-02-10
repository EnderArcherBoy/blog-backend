import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid"; // Generate unique IDs

const prisma = new PrismaClient();

export async function POST(req: NextRequest) {
  try {
    const payload = await req.json();

    // Extract user data from Clerk webhook
    const { id, email_addresses, username, password } = payload.data;

    if (!password) {
      return NextResponse.json({ error: "Password is required" }, { status: 400 });
    }

    const email = email_addresses?.[0]?.email_address || "";

    // Ensure a unique ID (use Clerk ID if available, otherwise generate one)
    const userId = id || uuidv4();

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user in Prisma with default role "reader"
    await prisma.user.create({
      data: {
        id: userId, // Ensure unique ID
        email,
        username,
        password: hashedPassword, // Store securely hashed password
        role: "reader", // Default role
      },
    });

    return NextResponse.json({ message: "User created successfully", userId }, { status: 201 });

  } catch (error) {
    console.error("Error in Clerk Webhook:", error);
    return NextResponse.json({ error: "Failed to create user" }, { status: 500 });
  }
}
