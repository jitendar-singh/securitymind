import { useEffect, useRef, useState } from "react";
import { motion as Motion } from "framer-motion";
import { ArrowUp, Square } from "lucide-react";

const MAX_ROWS = 8;

export default function PromptBar({
  value,
  onChange,
  onSubmit,
  onStop,
  sending,
  autoFocusKey,
}) {
  const ref = useRef(null);
  const [focused, setFocused] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = "auto";
    const lineHeight = parseFloat(getComputedStyle(el).lineHeight) || 22;
    const max = lineHeight * MAX_ROWS;
    el.style.height = Math.min(el.scrollHeight, max) + "px";
    el.style.overflowY = el.scrollHeight > max ? "auto" : "hidden";
  }, [value]);

  useEffect(() => {
    ref.current?.focus();
  }, [autoFocusKey]);

  const handleKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      onSubmit?.();
    } else if (e.key === "Escape") {
      onChange?.("");
    }
  };

  const canSend = value.trim().length > 0 && !sending;
  const showStop = sending && Boolean(onStop);

  return (
    <div className="px-6 pb-6 pt-3 bg-gradient-to-t from-[var(--bg)] via-[var(--bg)] to-transparent">
      <Motion.form
        initial={false}
        animate={{
          y: focused ? -1 : 0,
          boxShadow: focused
            ? "var(--shadow-md)"
            : "var(--shadow-sm)",
        }}
        transition={{ type: "spring", stiffness: 400, damping: 30 }}
        onSubmit={(e) => {
          e.preventDefault();
          if (canSend) onSubmit?.();
        }}
        className="mx-auto max-w-3xl flex items-end gap-2 rounded-3xl border border-[var(--border)] bg-[var(--bg-elev)] px-4 py-3"
      >
        <textarea
          ref={ref}
          value={value}
          onChange={(e) => onChange?.(e.target.value)}
          onKeyDown={handleKey}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          rows={1}
          placeholder="Ask Security Mind anything…"
          aria-label="Message"
          className="flex-1 resize-none bg-transparent outline-none border-none text-[var(--text-h)] placeholder:text-[var(--text-muted)] text-[16px] leading-snug py-1 px-2"
        />
        {showStop ? (
          <button
            type="button"
            onClick={onStop}
            aria-label="Stop"
            className="shrink-0 size-9 grid place-items-center rounded-full bg-[var(--text-h)] hover:opacity-90 text-[var(--bg)] shadow-[var(--shadow-sm)] transition-all"
          >
            <Square size={14} strokeWidth={2.5} fill="currentColor" />
          </button>
        ) : (
          <button
            type="submit"
            disabled={!canSend}
            aria-label="Send"
            className={[
              "shrink-0 size-9 grid place-items-center rounded-full transition-all",
              canSend
                ? "bg-[var(--accent)] hover:bg-[var(--accent-h)] text-white shadow-[var(--shadow-sm)]"
                : "bg-[var(--bg-subtle)] text-[var(--text-muted)] cursor-not-allowed",
            ].join(" ")}
          >
            <ArrowUp size={18} strokeWidth={2.25} />
          </button>
        )}
      </Motion.form>
      <p className="text-center text-[11px] text-[var(--text-muted)] mt-2">
        Press <kbd className="rounded bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[10px] border border-[var(--border-soft)]">Enter</kbd>{" "}
        to send · <kbd className="rounded bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[10px] border border-[var(--border-soft)]">Shift</kbd>+<kbd className="rounded bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[10px] border border-[var(--border-soft)]">Enter</kbd>{" "}
        for new line · <kbd className="rounded bg-[var(--bg-subtle)] px-1.5 py-0.5 text-[10px] border border-[var(--border-soft)]">Esc</kbd>{" "}
        to clear
      </p>
    </div>
  );
}
