import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { LogOut } from "lucide-react";
import { useAuth } from "../store/auth";
import { userInitials } from "../lib/user";

export function UserAvatar({ user, size = 32 }) {
  return (
    <div
      style={{ width: size, height: size }}
      className="shrink-0 rounded-full bg-gradient-to-br from-[var(--accent)] to-[var(--accent-h)] grid place-items-center text-white text-[12px] font-semibold shadow-[var(--shadow-sm)]"
    >
      {userInitials(user)}
    </div>
  );
}

// Sidebar footer slot — shows the current user with a popover menu containing
// "Sign out". Collapses to just the avatar (still clickable) when the rail
// is collapsed.
export default function UserFooter({ collapsed = false }) {
  const user = useAuth((s) => s.user);
  const logout = useAuth((s) => s.logout);
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  if (!user) return null;

  const onSignOut = async () => {
    setOpen(false);
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex items-center gap-3 w-full px-2 py-2 rounded-lg text-left hover:bg-[var(--bg-subtle)] transition-colors"
      >
        <UserAvatar user={user} />
        {!collapsed && (
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-medium text-[var(--text-h)] truncate">
              {user.name || user.email.split("@")[0]}
            </div>
            <div className="text-[11px] text-[var(--text-muted)] truncate">
              {user.email}
            </div>
          </div>
        )}
      </button>

      {open && (
        <div
          role="menu"
          className="absolute bottom-full left-0 mb-2 w-56 rounded-xl border border-[var(--border-soft)] bg-[var(--bg-elev)] shadow-[var(--shadow-md)] p-1 z-20"
        >
          <div className="px-3 py-2 border-b border-[var(--border-soft)] mb-1">
            <div className="text-[13px] font-medium text-[var(--text-h)] truncate">
              {user.name || "—"}
            </div>
            <div className="text-[11px] text-[var(--text-muted)] truncate">
              {user.email}
            </div>
          </div>
          <button
            type="button"
            role="menuitem"
            onClick={onSignOut}
            className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-[13px] text-[var(--text)] hover:text-[var(--text-h)] hover:bg-[var(--bg-subtle)] transition-colors"
          >
            <LogOut size={15} strokeWidth={1.75} />
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}
