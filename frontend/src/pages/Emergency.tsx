import { useState } from "react";
import { Link } from "react-router-dom";

import { Card } from "@/components/Card";

const STEPS = [
  { title: "Secure your primary email", body: "Change your email password immediately and enable MFA — it's the recovery key to everything else.", link: "/password-health", linkLabel: "Check password strength" },
  { title: "Change compromised passwords", body: "Update passwords on any account that shares the compromised one. Never reuse a password across accounts.", link: "/breach-checker", linkLabel: "Check breach exposure" },
  { title: "Sign out unknown sessions", body: "Go to each account's official security settings page and sign out of all sessions you don't recognize." },
  { title: "Enable multi-factor authentication", body: "Turn on MFA everywhere it's offered — it's the single most effective step against account takeover." },
  { title: "Contact your bank if financial information is compromised", body: "Call your bank using the number on the back of your card or their official website — never a number from a suspicious message." },
  { title: "Preserve screenshots and evidence", body: "Save screenshots of the suspicious message, email, or activity before it disappears. You'll need this for your report." },
  { title: "Report the incident", body: "File a report so there's a record and you get guidance on next steps.", link: "/incidents", linkLabel: "File an incident report" },
];

export default function Emergency() {
  const [completed, setCompleted] = useState<boolean[]>(() => STEPS.map(() => false));

  function toggle(i: number) {
    setCompleted((c) => c.map((v, idx) => (idx === i ? !v : v)));
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-risk-high">I've Been Hacked</h1>
        <p className="text-sm text-slate-500">Take a breath. Work through these steps one at a time — in order, if you can.</p>
      </div>

      <div className="space-y-3">
        {STEPS.map((step, i) => (
          <Card key={i} className={completed[i] ? "opacity-60" : ""}>
            <div className="flex items-start gap-3">
              <button
                onClick={() => toggle(i)}
                className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border-2 text-xs font-bold ${
                  completed[i] ? "border-risk-low bg-risk-low text-white" : "border-slate-300 dark:border-slate-600"
                }`}
              >
                {completed[i] ? "✓" : i + 1}
              </button>
              <div>
                <p className="font-medium">{step.title}</p>
                <p className="text-sm text-slate-500">{step.body}</p>
                {step.link && (
                  <Link to={step.link} className="mt-1 inline-block text-sm font-medium text-brand-600">
                    {step.linkLabel} →
                  </Link>
                )}
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
