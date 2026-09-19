"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, useReducedMotion } from "motion/react";
import {
  FileArrowUp,
  Gear,
  GitDiff,
  SquaresFour,
} from "@phosphor-icons/react/dist/ssr";

const EASE = [0.32, 0.72, 0, 1] as const;

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: SquaresFour },
  { href: "/scans/new", label: "New scan", icon: FileArrowUp },
  { href: "/compare", label: "Compare", icon: GitDiff },
  { href: "/settings", label: "Settings", icon: Gear },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const reduce = useReducedMotion();

  return (
    <div className="flex min-h-dvh">
      <aside
        className="fixed inset-y-0 left-0 z-20 flex w-60 flex-col border-r border-white/[0.07] bg-surface max-lg:w-14"
        aria-label="Console navigation"
      >
        <Link
          href="/"
          className="flex h-14 items-center gap-2.5 border-b border-white/[0.07] px-5 max-lg:justify-center max-lg:px-0"
        >
          <span className="brand-edge h-3.5 w-3.5 shrink-0 rounded-[3px]" aria-hidden />
          <span className="text-[14px] font-medium tracking-tight max-lg:hidden">
            Prahari
          </span>
        </Link>
        <nav className="mt-3 flex-1 space-y-1 px-3 max-lg:px-2" aria-label="Primary">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                className={`relative flex items-center gap-3 rounded-[6px] px-3 py-2.5 text-[14px] transition-colors duration-200 max-lg:justify-center max-lg:px-0 ${
                  active ? "bg-raised text-ink" : "text-subtle hover:bg-raised hover:text-ink"
                }`}
              >
                {active && (
                  <motion.span
                    aria-hidden
                    layoutId="rail-active"
                    className="absolute left-0 top-1/2 h-5 w-[2px] -translate-y-1/2 rounded-full"
                    style={{ background: "var(--color-accent)" }}
                    transition={reduce ? { duration: 0.1 } : { duration: 0.25, ease: EASE }}
                  />
                )}
                <Icon size={17} weight={active ? "fill" : "regular"} aria-hidden />
                <span className="max-lg:hidden">{label}</span>
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-white/[0.07] px-5 py-4 max-lg:px-0">
          <span className="text-[12px] text-faint max-lg:hidden">
            open workspace — scans are shared
          </span>
        </div>
      </aside>

      <main className="ml-60 flex-1 px-6 py-8 max-lg:ml-14 max-lg:px-4 lg:px-10">
        <motion.div
          className="mx-auto max-w-6xl"
          initial={reduce ? { opacity: 0 } : { opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: reduce ? 0.15 : 0.4, ease: EASE }}
        >
          {children}
        </motion.div>
      </main>
    </div>
  );
}
