export default function SuggestionChip({ icon: Icon, label, prompt, onPick }) {
  return (
    <button
      type="button"
      onClick={() => onPick?.(prompt)}
      className="group flex items-center gap-3 px-4 py-3 rounded-2xl border border-[var(--border-soft)] bg-[var(--bg-elev)] hover:border-[var(--accent-ring)] hover:bg-[var(--accent-bg)] transition-all text-left max-w-sm"
    >
      {Icon && (
        <Icon
          size={18}
          strokeWidth={1.75}
          className="shrink-0 text-[var(--text-muted)] group-hover:text-[var(--accent)] transition-colors"
        />
      )}
      <span className="text-sm text-[var(--text-h)] truncate">{label}</span>
    </button>
  );
}
