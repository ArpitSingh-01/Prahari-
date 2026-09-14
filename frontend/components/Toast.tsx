"use client";

/** Minimal toast queue with motion enter/exit. Usage:
 *   const { toast } = useToasts();  toast("message", "error");
 * Toasts auto-dismiss (4s) and respect reduced motion. */
import {
  AnimatePresence,
  motion,
  useReducedMotion,
} from "motion/react";
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
} from "react";

const EASE = [0.32, 0.72, 0, 1] as const;
type ToastKind = "info" | "error" | "success";
type ToastItem = { id: number; kind: ToastKind; message: string };

const ToastCtx = createContext<{
  toast: (message: string, kind?: ToastKind) => void;
}>({ toast: () => {} });

export function useToasts() {
  return useContext(ToastCtx);
}

const HUE: Record<ToastKind, { bg: string; fg: string }> = {
  info: { bg: "var(--color-low-bg)", fg: "var(--color-low)" },
  error: { bg: "var(--color-critical-bg)", fg: "var(--color-critical)" },
  success: { bg: "var(--color-pass-bg)", fg: "var(--color-pass)" },
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const reduce = useReducedMotion();
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const toast = useCallback((message: string, kind: ToastKind = "info") => {
    const id = nextId.current++;
    setItems((cur) => [...cur.slice(-3), { id, kind, message }]);
    setTimeout(() => {
      setItems((cur) => cur.filter((t) => t.id !== id));
    }, 4000);
  }, []);

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastCtx.Provider value={value}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed bottom-5 right-5 z-[90] flex w-80 flex-col gap-2"
      >
        <AnimatePresence>
          {items.map((t) => (
            <motion.div
              key={t.id}
              role="status"
              initial={reduce ? { opacity: 0 } : { opacity: 0, y: 12, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={reduce ? { opacity: 0 } : { opacity: 0, y: 6, scale: 0.98 }}
              transition={{ duration: 0.25, ease: EASE }}
              className="rounded-[8px] px-4 py-3 text-[14px] leading-[1.3] shadow-lg"
              style={{ background: HUE[t.kind].bg, color: HUE[t.kind].fg }}
            >
              {t.message}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastCtx.Provider>
  );
}
