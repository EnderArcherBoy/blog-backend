import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";

const prisma = new PrismaClient();
const SECRET_KEY = process.env.JWT_SECRET; // Load from .env

export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization");

    // Check if Authorization header exists
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Extract the token
    const token = authHeader.split(" ")[1];

    // Verify JWT token
    const decoded = jwt.verify(token, SECRET_KEY as string);

    if (typeof decoded === 'object' && decoded !== null) {
      if (decoded.role !== "writer" && decoded.role !== "admin") {
        return NextResponse.json({ error: "Permission denied" }, { status: 403 });
      }
    } else {
      // Handle the case where decoded is not an object
      return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    }

    const { title, content } = await req.json();

    // Ensure required fields exist
    if (!title || !content) {
      return NextResponse.json({ error: "Title and content are required" }, { status: 400 });
    }

    // Create the article
    const newArticle = await prisma.article.create({
      data: {
        title,
        content,
        authorId: decoded.id, // Use the logged-in user’s ID
      },
    });

    return NextResponse.json({ message: "Article created", article: newArticle }, { status: 201 });
  } catch (error) {
    console.error("Error creating article:", error);
    return NextResponse.json({ error: "Failed to create article" }, { status: 500 });
  }
}

export async function GET(req: NextRequest) {
  try {
    const articles = await prisma.article.findMany({
      select: {
        id: true,
        title: true,
        content: true,
        createdAt: true,
        author: {
          select: { username: true, email: true },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(articles);
  } catch (error) {
    console.error("Error fetching articles:", error);
    return NextResponse.json({ error: "Failed to fetch articles" }, { status: 500 });
  }
}