import { useState } from "react";

import { checkPasswordStrength } from "@/api/endpoints";
import type { PasswordStrengthResult } from "@/api/types";
import { Card } from "@/components/Card";

const LABEL_COLOR: Record<string, string> = {
  "very weak": "bg-risk-high",
  weak: "bg-risk-high",
  fair: "bg-risk-medium",
  strong: "bg-risk-low",
  "very strong": "bg-risk-low",
};

export default function PasswordHealth() {
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<PasswordStrengthResult | null>(null);
  const [checking, setChecking] = useState(false);

  async function handleChange(value: string) {
    setPassword(value);
    if (!value) {
      setResult(null);
      return;
    }
    setChecking(true);
    try {
      setResult(await checkPasswordStrength(value));
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Password Health</h1>
        <p className="text-sm text-slate-500">
          This check runs against the password you type here only — it is never stored or logged,
          and is not linked to any of your saved account passwords.
        </p>
      </div>

      <Card className="space-y-4">
        <div>
          <label className="mb-1 block text-sm font-medium" htmlFor="pw">Try a password</label>
          <input
            id="pw"
            type="password"
            value={password}
            onChange={(e) => handleChange(e.target.value)}
            placeholder="Type a password to test its strength"
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-surface"
          />
        </div>

        {checking && <p className="text-sm text-slate-500">Checking…</p>}

        {result && (
          <div className="space-y-3">
            <div>
              <div className="mb-1 flex justify-between text-sm">
                <span className="capitalize font-medium">{result.label}</span>
                <span className="text-slate-500">{result.score}/4</span>
              </div>
              <div className="flex gap-1">
                {[0, 1, 2, 3].map((i) => (
                  <div key={i} className={`h-2 flex-1 rounded-full ${i < result.score ? LABEL_COLOR[result.label] : "bg-slate-100 dark:bg-slate-800"}`} />
                ))}
              </div>
            </div>
            {result.is_common && (
              <p className="rounded-lg bg-risk-high/10 p-3 text-sm font-medium text-risk-high">
                This is one of the most commonly breached passwords. Avoid it entirely.
              </p>
            )}
            <ul className="list-inside list-disc space-y-1 text-sm text-slate-600 dark:text-slate-400">
              {result.suggestions.map((s, i) => <li key={i}>{s}</li>)}
            </ul>
          </div>
        )}
      </Card>
    </div>
  );
}
