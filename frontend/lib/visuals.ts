/** Shared visual mappings (severity palette + helpers). */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
/** Hue token — severity palette plus "pass" (grade A / healthy). */
export type Hue = Severity | "pass";

export function severityHue(gradeOrSev: string): Hue {
  switch (gradeOrSev) {
    case "A":
    case "pass":
      return "pass";
    case "B":
    case "low":
      return "low";
    case "C":
    case "medium":
      return "medium";
    case "D":
    case "high":
      return "high";
    default:
      return "critical";
  }
}

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function ms(n: number): string {
  if (n < 1000) return `${n} ms`;
  return `${(n / 1000).toFixed(1)} s`;
}
