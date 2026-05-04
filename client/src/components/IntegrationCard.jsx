import { motion as Motion } from "framer-motion";
import {
  CheckCircle2,
  Loader2,
  Pencil,
  PlugZap,
  Trash2,
  XCircle,
} from "lucide-react";
import { getProvider } from "../lib/integrations";
import { useIntegrations } from "../store/integrations";

export default function IntegrationCard({ item, onEdit }) {
  const provider = getProvider(item.provider);
  const Icon = provider.icon;
  const test = useIntegrations((s) => s.test);
  const remove = useIntegrations((s) => s.remove);
  const update = useIntegrations((s) => s.update);
  const result = useIntegrations((s) => s.testing[item.id]);

  const isTesting = result === "pending";
  const status = result && typeof result === "object" ? result.status : null;
  const message = result && typeof result === "object" ? result.message : null;

  const onDelete = async () => {
    if (!confirm(`Delete integration ${provider.label} / ${item.name}?`)) return;
    try {
      await remove(item.id);
    } catch (err) {
      alert(err.message || "Delete failed");
    }
  };

  const toggle = async () => {
    try {
      await update(item.id, { enabled: !item.enabled });
    } catch (err) {
      alert(err.message || "Toggle failed");
    }
  };

  return (
    <Motion.div
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border border-[var(--border-soft)] bg-[var(--bg-elev)] p-5"
    >
      <div className="flex items-start gap-4">
        <div className="size-10 rounded-xl bg-[var(--bg-subtle)] grid place-items-center text-[var(--text-h)] shrink-0">
          <Icon size={20} strokeWidth={1.75} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[15px] font-semibold text-[var(--text-h)]">
              {provider.label}
            </span>
            <span className="text-[13px] text-[var(--text-muted)] truncate">
              · {item.name}
            </span>
            <button
              type="button"
              onClick={toggle}
              className={[
                "ml-auto text-[11px] px-2 py-0.5 rounded-md font-medium",
                item.enabled
                  ? "bg-[var(--accent-bg)] text-[var(--accent)]"
                  : "bg-[var(--bg-subtle)] text-[var(--text-muted)]",
              ].join(" ")}
            >
              {item.enabled ? "Enabled" : "Disabled"}
            </button>
          </div>
          {item.fields?.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {item.fields.map((f) => (
                <span
                  key={f}
                  className="text-[11px] px-1.5 py-0.5 rounded bg-[var(--bg-subtle)] text-[var(--text-muted)] font-mono"
                >
                  {f}
                </span>
              ))}
            </div>
          )}
          {message && (
            <div
              className={[
                "mt-3 text-[13px] flex items-start gap-1.5",
                status === "success"
                  ? "text-emerald-500"
                  : "text-red-500",
              ].join(" ")}
            >
              {status === "success" ? (
                <CheckCircle2 size={14} className="shrink-0 mt-0.5" />
              ) : (
                <XCircle size={14} className="shrink-0 mt-0.5" />
              )}
              <span className="break-words">{message}</span>
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 flex items-center gap-2">
        <button
          type="button"
          onClick={() => test(item.id)}
          disabled={isTesting}
          className="inline-flex items-center gap-1.5 text-[13px] px-3 py-1.5 rounded-lg border border-[var(--border-soft)] bg-[var(--bg)] hover:bg-[var(--bg-subtle)] text-[var(--text-h)] disabled:opacity-60 transition-colors"
        >
          {isTesting ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <PlugZap size={14} />
          )}
          Test connection
        </button>
        <button
          type="button"
          onClick={() => onEdit(item)}
          className="inline-flex items-center gap-1.5 text-[13px] px-3 py-1.5 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-h)] hover:bg-[var(--bg-subtle)] transition-colors"
        >
          <Pencil size={14} /> Edit
        </button>
        <button
          type="button"
          onClick={onDelete}
          className="ml-auto inline-flex items-center gap-1.5 text-[13px] px-3 py-1.5 rounded-lg text-red-500 hover:bg-red-500/10 transition-colors"
        >
          <Trash2 size={14} /> Delete
        </button>
      </div>
    </Motion.div>
  );
}
