import { clerkMiddleware } from "@clerk/nextjs/server";
import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

export default clerkMiddleware((auth, req) => {
  const publicRoutes = ['/api/auth/webhook', '/api/auth/logout'];

  if (req.nextUrl.pathname.startsWith('/api/') && !publicRoutes.includes(req.nextUrl.pathname)) {
    const authHeader = req.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Add JWT verification logic here
    try {
      const token = authHeader.split(' ')[1];
      if (!JWT_SECRET) {
        console.error("JWT_SECRET is not defined");
        return NextResponse.json({ error: "Server configuration error" }, { status: 500 });
      }

      const decodedToken = jwt.verify(token, JWT_SECRET);
      if (!decodedToken) {
        return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
      }

      return NextResponse.next();
    } catch (error) {
      console.error("JWT verification error:", error);
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }
  }

  return NextResponse.next();
});

export const config = {
  matcher: [
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    '/(api|trpc)(.*)',
    '/',
    '/api/:path*',
  ],
};