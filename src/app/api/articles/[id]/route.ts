import { NextRequest, NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { verifyToken } from "@/lib/auth"; // Correct import
import { JwtPayload } from "jsonwebtoken";

const prisma = new PrismaClient();

type ArticleUpdateInput = {
    title?: string;
    content?: string;
    status?: string;
};

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
    try {
      const authHeader = req.headers.get("Authorization");
      if (!authHeader) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  
      const token = authHeader.split(" ")[1];
      const user = verifyToken(token);
      if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 403 });
  
      const { title, content, status } = await req.json();
      const article = await prisma.article.findUnique({ where: { id: params.id } });
  
      if (!article) return NextResponse.json({ error: "Article not found" }, { status: 404 });
  
      // Only author or admin can update
      if (article.authorId !== (user as JwtPayload).id && (user as JwtPayload).role !== "admin") {
        return NextResponse.json({ error: "Forbidden" }, { status: 403 });
      }
  
      // Build update data dynamically
      const updateData: any = { title, content };
      if (status !== undefined) updateData.status = status; // Only add status if provided
  
      const updatedArticle = await prisma.article.update({
          where: { id: params.id },
          data: updateData,
      });
  
      return NextResponse.json({ message: "Article updated", updatedArticle }, { status: 200 });
    } catch (error) {
      console.error("Error updating article:", error);
      return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
  }

export async function DELETE(req: NextRequest, { params }: { params: { id: string } }) {
    try {
      const authHeader = req.headers.get("Authorization");
      if (!authHeader) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  
      const token = authHeader.split(" ")[1];
      const user = verifyToken(token);
      if (!user) return NextResponse.json({ error: "Invalid token" }, { status: 403 });
  
      const article = await prisma.article.findUnique({ where: { id: params.id } });
  
      if (!article) return NextResponse.json({ error: "Article not found" }, { status: 404 });
  
      // Only the author or admin can delete
      if (article.authorId !== (user as JwtPayload).id && (user as JwtPayload).role !== "admin") {
        return NextResponse.json({ error: "Forbidden" }, { status: 403 });
      }
  
      await prisma.article.delete({ where: { id: params.id } });
  
      return NextResponse.json({ message: "Article deleted" }, { status: 200 });
    } catch (error) {
      console.error("Error deleting article:", error);
      return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}

  