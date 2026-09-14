/** Server-side Supabase client (App Router route handlers / server
 * components). Cookie-based session via @supabase/ssr. */
import { cookies } from "next/headers";
import { createServerClient } from "@supabase/ssr";

export async function getServerClient() {
  const cookieStore = await cookies();
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anon) return null;
  return createServerClient(url, anon, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) =>
            cookieStore.set(name, value, options),
          );
        } catch {
          // called from a Server Component render — middleware refreshes
        }
      },
    },
  });
}
