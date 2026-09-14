"use client";

/** Supabase clients (cookie-based sessions via @supabase/ssr).
 *
 * NEXT_PUBLIC_SUPABASE_URL unset -> local/demo mode and every helper here
 * is never called (SUPABASE_CONFIGURED gates the call sites).
 */
import { createBrowserClient } from "@supabase/ssr";

let browserClient: ReturnType<typeof createBrowserClient> | null = null;

export function getBrowserClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anon) {
    throw new Error("Supabase is not configured on this deployment");
  }
  if (!browserClient) {
    browserClient = createBrowserClient(url, anon);
  }
  return browserClient;
}
