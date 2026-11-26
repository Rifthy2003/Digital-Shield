import { Link } from "react-router-dom";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card } from "@/components/Card";

interface ThreatActivityChartProps {
  high: number;
  medium: number;
  info: number;
}

export function ThreatActivityChart({ high, medium, info }: ThreatActivityChartProps) {
  const total = high + medium + info;
  const chartData = [
    { name: "Critical / High", count: high, color: "#dc2626" },
    { name: "Medium", count: medium, color: "#d97706" },
    { name: "Informational", count: info, color: "#2563eb" },
  ];

  return (
    <Card className="flex h-full flex-col justify-between space-y-4 border-slate-800/80 bg-surface-raised/90">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Threat Activity Overview
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Live open alert distribution by severity
          </p>
        </div>
        <span className="font-mono text-xs text-slate-400">{total} open</span>
      </div>

      {total === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-slate-800 p-6 text-center">
          <p className="text-sm font-medium text-slate-300">No open threat alerts recorded</p>
          <p className="max-w-xs text-xs text-slate-400">
            Run a URL scan, phishing message check, or breach lookup to populate live threat
            telemetry.
          </p>
          <div className="flex flex-wrap justify-center gap-2 pt-1">
            <Link
              to="/url-checker"
              className="rounded-lg border border-slate-700 bg-surface px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
            >
              Scan a URL
            </Link>
            <Link
              to="/message-checker"
              className="rounded-lg border border-slate-700 bg-surface px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
            >
              Analyze Message
            </Link>
          </div>
        </div>
      ) : (
        <div className="h-52 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <XAxis
                dataKey="name"
                tick={{ fill: "#94a3b8", fontSize: 11 }}
                axisLine={{ stroke: "#1e293b" }}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "#94a3b8", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: "rgba(148, 163, 184, 0.08)" }}
                contentStyle={{
                  backgroundColor: "#0b1220",
                  borderColor: "#1e293b",
                  borderRadius: "0.75rem",
                  color: "#f1f5f9",
                  fontSize: "12px",
                }}
              />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {chartData.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  );
}
