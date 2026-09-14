"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { SessionExpired } from "@/lib/api";
import { ToastProvider, useToasts } from "@/components/Toast";

function SessionWatcher() {
  const router = useRouter();
  const { toast } = useToasts();
  useEffect(() => {
    const onExpired = (e: Event) => {
      toast("Your session expired. Sign in again.", "error");
      router.push("/login");
    };
    window.addEventListener("prahari:session-expired", onExpired);
    return () => window.removeEventListener("prahari:session-expired", onExpired);
  }, [router, toast]);
  return null;
}

function ApiErrorBridge() {
  const { toast } = useToasts();
  useEffect(() => {
    const onError = (e: Event) => {
      const message = (e as CustomEvent<string>).detail;
      if (message) toast(message, "error");
    };
    window.addEventListener("prahari:api-error", onError);
    return () => window.removeEventListener("prahari:api-error", onError);
  }, [toast]);
  return null;
}

/** Translate api() rejections into console events for the bridge above.
 * (Call sites keep their inline error UI; this adds a toast for errors the
 * page doesn't already show.) */
export function notifyApiError(err: unknown) {
  if (err instanceof Error && !(err instanceof SessionExpired)) {
    window.dispatchEvent(
      new CustomEvent("prahari:api-error", { detail: err.message }),
    );
  }
  if (err instanceof SessionExpired) {
    window.dispatchEvent(new Event("prahari:session-expired"));
  }
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: (failureCount, error) => {
              notifyApiError(error);
              return !(error instanceof SessionExpired) && failureCount < 2;
            },
            refetchOnWindowFocus: false,
            staleTime: 10_000,
          },
        },
      }),
  );
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>
        <SessionWatcher />
        <ApiErrorBridge />
        {children}
      </ToastProvider>
    </QueryClientProvider>
  );
}
