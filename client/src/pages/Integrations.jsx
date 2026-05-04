import { useEffect, useMemo, useState } from "react";
import { AnimatePresence } from "framer-motion";
import { Loader2, Plus } from "lucide-react";
import IntegrationCard from "../components/IntegrationCard";
import IntegrationForm from "../components/IntegrationForm";
import { CATEGORIES, getProvider } from "../lib/integrations";
import { useIntegrations } from "../store/integrations";

export default function Integrations() {
  const items = useIntegrations((s) => s.items);
  const loading = useIntegrations((s) => s.loading);
  const error = useIntegrations((s) => s.error);
  const fetch = useIntegrations((s) => s.fetch);

  const [editing, setEditing] = useState(null); // null | "new" | item

  useEffect(() => {
    fetch();
  }, [fetch]);

  const grouped = useMemo(() => {
    const byCat = {};
    for (const it of items) {
      const cat = getProvider(it.provider).category || "other";
      (byCat[cat] ||= []).push(it);
    }
    return CATEGORIES.map((c) => ({ ...c, items: byCat[c.id] || [] })).filter(
      (c) => c.items.length > 0
    );
  }, [items]);

  return (
    <div className="px-8 py-12 max-w-5xl w-full mx-auto">
      <div className="flex items-end gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-[var(--text-h)] tracking-tight mb-2">
            Integrations
          </h1>
          <p className="text-[var(--text-muted)]">
            Connect GitHub, GCP, AWS, Azure, Jira, and more so each sub-agent can
            access your environment.
          </p>
        </div>
        {editing === null && (
          <button
            type="button"
            onClick={() => setEditing("new")}
            className="ml-auto inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-h)] text-white text-[14px] font-medium transition-colors"
          >
            <Plus size={16} /> Add integration
          </button>
        )}
      </div>

      <AnimatePresence mode="wait">
        {editing && (
          <div className="mb-6">
            <IntegrationForm
              key={editing === "new" ? "new" : editing.id}
              initial={editing === "new" ? null : editing}
              onClose={() => setEditing(null)}
            />
          </div>
        )}
      </AnimatePresence>

      {error && (
        <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3 text-[13px] text-red-500">
          {error}
        </div>
      )}

      {loading && items.length === 0 ? (
        <div className="rounded-2xl border border-[var(--border-soft)] bg-[var(--bg-elev)] p-10 text-center text-[var(--text-muted)]">
          <Loader2 size={20} className="animate-spin mx-auto mb-2" />
          Loading integrations…
        </div>
      ) : items.length === 0 ? (
        <div className="rounded-2xl border border-[var(--border-soft)] bg-[var(--bg-elev)] p-10 text-center text-[var(--text-muted)]">
          No integrations yet. Click <strong>Add integration</strong> to connect
          your first provider.
        </div>
      ) : (
        <div className="space-y-8">
          {grouped.map((section) => (
            <section key={section.id}>
              <h2 className="text-[13px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-3">
                {section.label}
                <span className="ml-2 text-[var(--text-muted)] font-normal normal-case">
                  · {section.items.length}
                </span>
              </h2>
              <div className="grid gap-3">
                {section.items.map((it) => (
                  <IntegrationCard
                    key={it.id}
                    item={it}
                    onEdit={(item) => setEditing(item)}
                  />
                ))}
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
