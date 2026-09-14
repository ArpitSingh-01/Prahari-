import Link from "next/link";

export default function NotFound() {
  return (
    <main className="theme-light flex min-h-dvh flex-col items-center justify-center gap-5 px-6 text-center">
      <span className="brand-edge h-4 w-4 rounded-[4px]" aria-hidden />
      <h1 className="text-4xl font-medium tracking-tight text-ink">
        404 — nothing on this wire
      </h1>
      <p className="max-w-md text-[15px] leading-[1.4] text-subtle">
        The page you asked for doesn&apos;t exist. The console itself is one
        click away.
      </p>
      <div className="flex gap-3">
        <Link href="/" className="btn btn-ghost">Home</Link>
        <Link href="/dashboard" className="btn btn-primary">Open the console</Link>
      </div>
    </main>
  );
}
