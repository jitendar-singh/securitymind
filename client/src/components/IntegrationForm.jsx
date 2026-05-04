import { useMemo, useState } from "react";
import { motion as Motion } from "framer-motion";
import { Loader2, X } from "lucide-react";
import {
  CATEGORIES,
  getProvider,
  providersInCategory,
} from "../lib/integrations";
import { useIntegrations } from "../store/integrations";

export default function IntegrationForm({ initial, onClose }) {
  const isEdit = Boolean(initial);
  const create = useIntegrations((s) => s.create);
  const update = useIntegrations((s) => s.update);

  // For edit, lock to the existing provider. For new, start with nothing selected
  // so the field section only appears once the user picks a provider.
  const [providerId, setProviderId] = useState(initial?.provider || null);
  const provider = useMemo(
    () => (providerId ? getProvider(providerId) : null),
    [providerId]
  );

  const [name, setName] = useState(initial?.name || "");
  const [values, setValues] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const setField = (k, v) => setValues((prev) => ({ ...prev, [k]: v }));

  const pickProvider = (id) => {
    setProviderId(id);
    setValues({}); // forget unsaved values from the previous provider
  };

  const submit = async (e) => {
    e.preventDefault();
    setError(null);

    if (!provider) {
      setError("Pick a provider above");
      return;
    }

    const config = {};
    for (const f of provider.fields) {
      const v = (values[f.name] ?? "").trim();
      if (f.required && !v && !isEdit) {
        setError(`${f.label} is required`);
        return;
      }
      if (v) config[f.name] = v;
    }

    if (!name.trim()) {
      setError("Name is required");
      return;
    }

    setSubmitting(true);
    try {
      if (isEdit) {
        await update(initial.id, {
          name: name.trim(),
          ...(Object.keys(config).length > 0 ? { config } : {}),
        });
      } else {
        await create({ provider: providerId, name: name.trim(), config });
      }
      onClose();
    } catch (err) {
      setError(err?.body?.error || err?.message || "Save failed");
      setSubmitting(false);
    }
  };

  return (
    <Motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      className="rounded-2xl border border-[var(--border)] bg-[var(--bg-elev)] p-6 shadow-[var(--shadow-md)]"
    >
      <div className="flex items-center mb-4">
        <h2 className="text-[17px] font-semibold text-[var(--text-h)]">
          {isEdit ? `Edit ${getProvider(initial.provider).label}` : "Add integration"}
        </h2>
        <button
          type="button"
          onClick={onClose}
          className="ml-auto size-7 grid place-items-center rounded-md text-[var(--text-muted)] hover:text-[var(--text-h)] hover:bg-[var(--bg-subtle)]"
          aria-label="Close"
        >
          <X size={16} />
        </button>
      </div>

      <form onSubmit={submit} className="space-y-4">
        {!isEdit && (
          <div>
            <label className="block text-[13px] font-medium text-[var(--text-h)] mb-1.5">
              Provider
            </label>
            <div className="space-y-3">
              {CATEGORIES.map((cat) => {
                const inCat = providersInCategory(cat.id);
                if (inCat.length === 0) return null;
                return (
                  <div key={cat.id}>
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)] mb-1.5">
                      {cat.label}
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                      {inCat.map((p) => {
                        const Icon = p.icon;
                        const active = p.id === providerId;
                        return (
                          <button
                            key={p.id}
                            type="button"
                            onClick={() => pickProvider(p.id)}
                            className={[
                              "flex items-center gap-2 px-3 py-2 rounded-lg border text-left transition-colors",
                              active
                                ? "border-[var(--accent-ring)] bg-[var(--accent-bg)] text-[var(--accent)]"
                                : "border-[var(--border-soft)] bg-[var(--bg)] text-[var(--text-h)] hover:bg-[var(--bg-subtle)]",
                            ].join(" ")}
                          >
                            <Icon size={16} strokeWidth={1.75} />
                            <span className="text-[13px] font-medium truncate">{p.label}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
            {provider && (
              <p className="mt-2 text-[12px] text-[var(--text-muted)]">{provider.blurb}</p>
            )}
          </div>
        )}

        {provider && (
          <div className="pt-4 border-t border-[var(--border-soft)] space-y-4">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">
              {provider.label} details
            </div>

            <div>
              <label className="block text-[13px] font-medium text-[var(--text-h)] mb-1.5">
                Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. prod, personal, eng-team"
                className="w-full px-3 py-2 rounded-lg bg-[var(--bg)] border border-[var(--border-soft)] text-[var(--text-h)] placeholder:text-[var(--text-muted)] outline-none focus:border-[var(--accent-ring)]"
              />
            </div>

            {provider.fields.map((f) => (
              <div key={f.name}>
                <label className="block text-[13px] font-medium text-[var(--text-h)] mb-1.5">
                  {f.label}
                  {f.required && <span className="text-red-500"> *</span>}
                  <span className="ml-2 font-mono text-[11px] text-[var(--text-muted)]">
                    {f.name}
                  </span>
                </label>
                <input
                  type={f.type === "password" ? "password" : "text"}
                  value={values[f.name] || ""}
                  onChange={(e) => setField(f.name, e.target.value)}
                  placeholder={
                    isEdit
                      ? "Leave blank to keep existing value"
                      : f.placeholder || ""
                  }
                  autoComplete="off"
                  className="w-full px-3 py-2 rounded-lg bg-[var(--bg)] border border-[var(--border-soft)] text-[var(--text-h)] placeholder:text-[var(--text-muted)] outline-none focus:border-[var(--accent-ring)] font-mono text-[13px]"
                />
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="text-[13px] text-red-500">{error}</div>
        )}

        <div className="flex items-center gap-2 pt-2">
          <button
            type="submit"
            disabled={submitting || !provider}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-h)] text-white text-[14px] font-medium disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
          >
            {submitting && <Loader2 size={14} className="animate-spin" />}
            {isEdit ? "Save changes" : "Add integration"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-[14px] text-[var(--text-muted)] hover:text-[var(--text-h)] hover:bg-[var(--bg-subtle)] transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </Motion.div>
  );
}
