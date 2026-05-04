import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Check, Cpu, Loader2, LogOut, RotateCcw } from "lucide-react";
import { MODEL_GROUPS, labelForAgent } from "../lib/models";
import { useSettings } from "../store/settings";
import { useAuth } from "../store/auth";
import { UserAvatar } from "../components/UserFooter";

export default function Settings() {
  const agents = useSettings((s) => s.agents);
  const selections = useSettings((s) => s.selections);
  const loading = useSettings((s) => s.loading);
  const saving = useSettings((s) => s.saving);
  const error = useSettings((s) => s.error);
  const fetch = useSettings((s) => s.fetch);
  const setSelection = useSettings((s) => s.setSelection);
  const save = useSettings((s) => s.save);

  const [savedAt, setSavedAt] = useState(null);

  useEffect(() => {
    fetch();
  }, [fetch]);

  const onSave = async () => {
    const ok = await save();
    if (ok) {
      setSavedAt(Date.now());
      setTimeout(() => setSavedAt(null), 2500);
    }
  };

  const onReset = () => {
    for (const a of agents) setSelection(a.id, "default");
  };

  const masterAgent = agents.find((a) => a.id === "secmind");
  const subAgents = agents.filter((a) => a.id !== "secmind");

  return (
    <div className="px-8 py-12 max-w-5xl w-full mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-[var(--text-h)] tracking-tight mb-2">
          Settings
        </h1>
        <p className="text-[var(--text-muted)]">
          Pick which AI model each agent uses. Changes apply on the next
          message — no restart needed.
        </p>
      </div>

      {error && (
        <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3 text-[13px] text-red-500">
          {error}
        </div>
      )}

      <AccountSection />

      {loading && agents.length === 0 ? (
        <div className="rounded-2xl border border-[var(--border-soft)] bg-[var(--bg-elev)] p-10 text-center text-[var(--text-muted)]">
          <Loader2 size={20} className="animate-spin mx-auto mb-2" />
          Loading settings…
        </div>
      ) : (
        <>
          <Section title="Master agent" agents={masterAgent ? [masterAgent] : []} selections={selections} onChange={setSelection} />
          <Section title="Sub-agents" agents={subAgents} selections={selections} onChange={setSelection} />

          <div className="mt-8 flex items-center gap-3">
            <button
              type="button"
              onClick={onSave}
              disabled={saving}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-h)] text-white text-[14px] font-medium disabled:opacity-60 transition-colors"
            >
              {saving && <Loader2 size={14} className="animate-spin" />}
              Save changes
            </button>
            <button
              type="button"
              onClick={onReset}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[14px] text-[var(--text-muted)] hover:text-[var(--text-h)] hover:bg-[var(--bg-subtle)] transition-colors"
            >
              <RotateCcw size={14} /> Reset to defaults
            </button>
            {savedAt && (
              <span className="inline-flex items-center gap-1.5 text-[13px] text-emerald-500">
                <Check size={14} /> Saved
              </span>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function AccountSection() {
  const user = useAuth((s) => s.user);
  const logout = useAuth((s) => s.logout);
  const navigate = useNavigate();
  const [signingOut, setSigningOut] = useState(false);

  if (!user) return null;

  const onSignOut = async () => {
    setSigningOut(true);
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="mb-6">
      <h2 className="text-[13px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-3">
        Account
      </h2>
      <div className="rounded-2xl border border-[var(--border-soft)] bg-[var(--bg-elev)] p-4 flex items-center gap-4">
        <UserAvatar user={user} size={44} />
        <div className="min-w-0 flex-1">
          <div className="text-[14px] font-medium text-[var(--text-h)] truncate">
            {user.name || user.email.split("@")[0]}
          </div>
          <div className="text-[12px] text-[var(--text-muted)] truncate">
            {user.email}
          </div>
        </div>
        <button
          type="button"
          onClick={onSignOut}
          disabled={signingOut}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-[var(--border-soft)] text-[13px] text-[var(--text)] hover:text-[var(--text-h)] hover:bg-[var(--bg-subtle)] disabled:opacity-60 transition-colors"
        >
          {signingOut ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <LogOut size={14} />
          )}
          Sign out
        </button>
      </div>
    </div>
  );
}

function Section({ title, agents, selections, onChange }) {
  if (!agents || agents.length === 0) return null;
  return (
    <div className="mb-6">
      <h2 className="text-[13px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-3">
        {title}
      </h2>
      <div className="rounded-2xl border border-[var(--border-soft)] bg-[var(--bg-elev)] divide-y divide-[var(--border-soft)] overflow-hidden">
        {agents.map((a) => (
          <AgentRow
            key={a.id}
            agent={a}
            value={selections[a.id] || "default"}
            onChange={(v) => onChange(a.id, v)}
          />
        ))}
      </div>
    </div>
  );
}

function AgentRow({ agent, value, onChange }) {
  return (
    <div className="flex items-center gap-4 px-4 py-3.5">
      <div className="size-9 rounded-lg bg-[var(--bg-subtle)] grid place-items-center text-[var(--text-muted)] shrink-0">
        <Cpu size={16} strokeWidth={1.75} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-[14px] font-medium text-[var(--text-h)] truncate">
          {labelForAgent(agent.id)}
        </div>
        <div className="text-[12px] text-[var(--text-muted)] font-mono truncate">
          {agent.id}
        </div>
      </div>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="px-3 py-2 rounded-lg bg-[var(--bg)] border border-[var(--border-soft)] text-[13px] text-[var(--text-h)] outline-none focus:border-[var(--accent-ring)] font-mono"
      >
        <option value="default">Default ({agent.default})</option>
        {MODEL_GROUPS.map((g) => (
          <optgroup key={g.provider} label={g.provider}>
            {g.models.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
    </div>
  );
}
