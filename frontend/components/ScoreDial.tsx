"use client";

import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "motion/react";

const EASE = [0.22, 1, 0.36, 1] as const;

function gradeHue(grade: string): "pass" | "low" | "medium" | "high" | "critical" {
  if (grade === "A") return "pass";
  if (grade === "B") return "low";
  if (grade === "C") return "medium";
  if (grade === "D") return "high";
  return "critical";
}

/** SVG arc 0-100 with centred grade letter; count-up runs once on mount. */
export function ScoreDial({
  score,
  grade,
  size = 150,
}: {
  score: number;
  grade: string;
  size?: number;
}) {
  const reduce = useReducedMotion();
  const [shown, setShown] = useState(score);

  useEffect(() => {
    if (reduce) {
      setShown(score);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const dur = 600;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / dur);
      setShown(Math.round(score * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [score, reduce]);

  const stroke = 10;
  const r = (size - stroke) / 2;
  const c = size / 2;
  const arc = Math.PI * r * 1.5; // 270° sweep
  const circumference = 2 * Math.PI * r;
  const hue = gradeHue(grade);

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img"
        aria-label={`Posture score ${score} of 100, grade ${grade}`}>
        <circle
          cx={c} cy={c} r={r} fill="none"
          stroke="var(--color-paper-3)" strokeWidth={stroke}
          strokeDasharray={`${arc} ${circumference}`}
          strokeLinecap="butt"
          transform={`rotate(135 ${c} ${c})`}
        />
        <motion.circle
          cx={c} cy={c} r={r} fill="none"
          stroke={`var(--color-${hue})`} strokeWidth={stroke}
          strokeLinecap="butt"
          transform={`rotate(135 ${c} ${c})`}
          initial={{ strokeDasharray: `0 ${circumference}` }}
          animate={{ strokeDasharray: `${(arc * shown) / 100} ${circumference}` }}
          transition={{ duration: reduce ? 0.1 : 0.4, ease: EASE }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="tabular text-3xl font-semibold" style={{ color: `var(--color-${hue})` }}>
          {shown}
        </span>
        <span className="font-mono text-xs uppercase tracking-widest text-subtle">
          grade {grade}
        </span>
      </div>
    </div>
  );
}
