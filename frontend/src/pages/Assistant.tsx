import { useState, type FormEvent } from "react";

import { askAssistant } from "@/api/endpoints";
import { Card } from "@/components/Card";

interface Turn {
  role: "user" | "assistant";
  text: string;
  mode?: string;
}

const STARTERS = [
  "Is this message safe? URGENT your account will be suspended, verify your OTP now.",
  "How do I enable 2FA on my accounts?",
  "I think I've been hacked, what do I do first?",
];

export default function Assistant() {
  const [turns, setTurns] = useState<Turn[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  async function send(question: string) {
    if (!question.trim()) return;
    setTurns((t) => [...t, { role: "user", text: question }]);
    setInput("");
    setLoading(true);
    try {
      const res = await askAssistant(question);
      setTurns((t) => [...t, { role: "assistant", text: res.answer, mode: res.mode }]);
    } catch {
      setTurns((t) => [...t, { role: "assistant", text: "Something went wrong answering that. Please try again." }]);
    } finally {
      setLoading(false);
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    send(input);
  }

  return (
    <div className="mx-auto flex h-full max-w-2xl flex-col space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">AI Cybersecurity Assistant</h1>
        <p className="text-sm text-slate-500">Ask about a suspicious message, link, or how to secure an account.</p>
      </div>

      {turns.length === 0 && (
        <div className="flex flex-wrap gap-2">
          {STARTERS.map((s) => (
            <button key={s} onClick={() => send(s)} className="rounded-full border border-slate-300 px-3 py-1.5 text-xs hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800">
              {s}
            </button>
          ))}
        </div>
      )}

      <div className="flex-1 space-y-3">
        {turns.map((t, i) => (
          <Card key={i} className={t.role === "user" ? "ml-auto max-w-[80%] bg-brand-500/10" : "mr-auto max-w-[80%]"}>
            <p className="whitespace-pre-wrap text-sm">{t.text}</p>
            {t.mode === "rule_based_fallback" && (
              <p className="mt-2 text-xs italic text-slate-400">Answered by the rule-based assistant (no external AI provider configured).</p>
            )}
          </Card>
        ))}
        {loading && <p className="text-sm text-slate-500">Thinking…</p>}
      </div>

      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Paste a suspicious message or ask a question…"
          className="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-surface"
        />
        <button type="submit" disabled={loading} className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-500 disabled:opacity-60">
          Send
        </button>
      </form>
    </div>
  );
}
