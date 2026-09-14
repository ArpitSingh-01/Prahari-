import { NextRequest, NextResponse } from "next/server";

/** Legacy email-confirmation links: Supabase may send token-pair links
 * (?token=...&type=...) when "Confirm email" uses the token flow. We can't
 * exchange those server-side (they're a v1 flow) — forward to the hash
 * handler on the login page, which completes them client-side. */
export async function GET(request: NextRequest) {
  const { searchParams, origin } = request.nextUrl;
  const token = searchParams.get("token");
  const type = searchParams.get("type") ?? "signup";
  if (!token) {
    return NextResponse.redirect(`${origin}/login`);
  }
  // hand the token to the client verify step (supports email signup,
  // recovery and email-change confirmation types)
  const params = new URLSearchParams({ token, type });
  return NextResponse.redirect(
    `${origin}/login?${params.toString()}#verify-token`,
  );
}
