"use client";

import { useEffect } from "react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("app error boundary:", error);
  }, [error]);

  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-5 px-6 text-center">
      <h1 className="text-3xl font-medium tracking-tight">Something broke on this page</h1>
      <p className="max-w-md text-[15px] leading-[1.4] text-subtle">
        {error.message || "An unexpected error occurred."} The rest of the
        console keeps working — retry or head back to the dashboard.
      </p>
      <div className="flex gap-3">
        <button onClick={reset} className="btn btn-primary">Retry</button>
        <a href="/dashboard" className="btn btn-ghost">Dashboard</a>
      </div>
    </main>
  );
}
