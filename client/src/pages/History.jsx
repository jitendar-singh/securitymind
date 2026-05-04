import { useNavigate } from "react-router-dom";
import { motion as Motion } from "framer-motion";
import { MessageSquare, Trash2 } from "lucide-react";
import { useHistory } from "../store/history";
import { useConversation } from "../store/conversation";

const formatWhen = (ts) => {
  const d = new Date(ts);
  const now = new Date();
  const sameDay =
    d.toDateString() === now.toDateString();
  if (sameDay) {
    return d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }
  return d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
};

export default function History() {
  const sessions = useHistory((s) => s.sessions);
  const remove = useHistory((s) => s.remove);
  const clear = useHistory((s) => s.clear);
  const loadFromHistory = useConversation((s) => s.loadFromHistory);
  const navigate = useNavigate();

  const open = (entry) => {
    loadFromHistory(entry);
    navigate("/");
  };

  const onDelete = (e, id) => {
    e.stopPropagation();
    remove(id);
  };

  const onClearAll = () => {
    if (sessions.length === 0) return;
    if (!confirm(`Delete all ${sessions.length} saved conversations?`)) return;
    clear();
  };

  return (
    <div className="px-8 py-12 max-w-5xl w-full mx-auto">
      <div className="flex items-end gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-semibold text-[var(--text-h)] tracking-tight mb-2">
            History
          </h1>
          <p className="text-[var(--text-muted)]">
            Past conversations from this browser. Click one to resume it.
          </p>
        </div>
        {sessions.length > 0 && (
          <button
            type="button"
            onClick={onClearAll}
            className="ml-auto inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[13px] text-red-500 hover:bg-red-500/10 transition-colors"
          >
            <Trash2 size={14} /> Clear all
          </button>
        )}
      </div>

      {sessions.length === 0 ? (
        <div className="rounded-2xl border border-[var(--border-soft)] bg-[var(--bg-elev)] p-10 text-center text-[var(--text-muted)]">
          No saved conversations yet. Start a chat and your history will show up
          here when you start a new one.
        </div>
      ) : (
        <div className="grid gap-2">
          {sessions.map((s) => {
            const turnCount = s.messages.filter((m) => m.role === "user").length;
            return (
              <Motion.button
                key={s.id}
                layout
                type="button"
                onClick={() => open(s)}
                className="w-full text-left flex items-start gap-3 px-4 py-3 rounded-xl border border-[var(--border-soft)] bg-[var(--bg-elev)] hover:border-[var(--accent-ring)] hover:bg-[var(--accent-bg)] transition-all"
              >
                <div className="size-8 rounded-lg bg-[var(--bg-subtle)] grid place-items-center text-[var(--text-muted)] shrink-0 mt-0.5">
                  <MessageSquare size={15} strokeWidth={1.75} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-[14px] text-[var(--text-h)] truncate">
                    {s.title}
                  </div>
                  <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">
                    {turnCount} {turnCount === 1 ? "turn" : "turns"} · {formatWhen(s.updatedAt)}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={(e) => onDelete(e, s.id)}
                  aria-label="Delete conversation"
                  className="shrink-0 size-7 grid place-items-center rounded-md text-[var(--text-muted)] hover:text-red-500 hover:bg-red-500/10 transition-colors"
                >
                  <Trash2 size={14} />
                </button>
              </Motion.button>
            );
          })}
        </div>
      )}
    </div>
  );
}
