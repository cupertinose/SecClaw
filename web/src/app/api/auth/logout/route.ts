import { NextResponse } from "next/server";

import { sessionCookieName } from "@/lib/session";

export async function POST(request: Request) {
  const response = NextResponse.redirect(new URL("/login", request.url), 303);
  response.cookies.set(sessionCookieName, "", { maxAge: 0, path: "/" });
  return response;
}
