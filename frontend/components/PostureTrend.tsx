"use client";

import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

/** Posture score across scans, oldest to newest. Real data only. */
export function PostureTrend({
  points,
}: {
  points: { name: string; date: string; score: number }[];
}) {
  return (
    <div className="h-44">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: -22 }}>
          <XAxis
            dataKey="date"
            tick={{ fill: "var(--color-muted)", fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            tick={{ fill: "var(--color-muted)", fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            cursor={{ stroke: "var(--color-rule)" }}
            contentStyle={{
              background: "var(--color-paper-3)",
              border: "none",
              borderRadius: 6,
              color: "var(--color-ink)",
              fontSize: 13,
            }}
            formatter={(v: number) => [`${v}/100`, "posture"]}
          />
          <Line
            type="monotone"
            dataKey="score"
            stroke="var(--color-accent)"
            strokeWidth={2}
            dot={{ r: 3, fill: "var(--color-accent)", strokeWidth: 0 }}
            activeDot={{ r: 5 }}
          />
        </LineChart>
      </ResponsiveContainer>
      <table className="sr-only">
        <caption>Posture scores by scan date</caption>
        <tbody>
          {points.map((p, i) => (
            <tr key={i}>
              <th scope="row">{p.date}</th>
              <td>{p.score}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
