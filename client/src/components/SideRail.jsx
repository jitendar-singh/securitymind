import { NavLink } from "react-router-dom";
import { motion as Motion } from "framer-motion";
import {
  MessageSquarePlus,
  Plug,
  FileText,
  History,
  Settings,
  ShieldCheck,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";
import ThemeToggle from "./ThemeToggle";
import UserFooter from "./UserFooter";
import { useConversation } from "../store/conversation";

const NAV = [
  { to: "/", label: "New chat", icon: MessageSquarePlus, end: true, action: "newChat" },
  { to: "/integrations", label: "Integrations", icon: Plug },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/history", label: "History", icon: History },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function SideRail({ collapsed, onToggle }) {
  const newChat = useConversation((s) => s.newChat);

  return (
    <Motion.aside
      initial={false}
      animate={{ width: collapsed ? 72 : 248 }}
      transition={{ type: "spring", stiffness: 360, damping: 32 }}
      className="shrink-0 h-screen sticky top-0 border-r border-[var(--border-soft)] bg-[var(--bg-elev)] flex flex-col"
    >
      {/* Brand */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-[var(--border-soft)]">
        <div className="size-8 rounded-lg bg-gradient-to-br from-[var(--accent)] to-[var(--accent-h)] grid place-items-center text-white shadow-[var(--shadow-sm)]">
          <ShieldCheck size={18} strokeWidth={2.25} />
        </div>
        {!collapsed && (
          <div className="flex-1 min-w-0">
            <div className="text-[15px] font-semibold tracking-tight text-[var(--text-h)] truncate">
              Security Mind
            </div>
            <div className="text-[11px] text-[var(--text-muted)] truncate">
              ASPM agent
            </div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        {NAV.map(({ to, label, icon: Icon, end, action }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={action === "newChat" ? () => newChat() : undefined}
            className={({ isActive }) =>
              [
                "flex items-center gap-3 px-3 py-2 rounded-lg transition-colors",
                isActive
                  ? "bg-[var(--accent-bg)] text-[var(--accent)] font-medium"
                  : "text-[var(--text)] hover:text-[var(--text-h)] hover:bg-[var(--bg-subtle)]",
              ].join(" ")
            }
          >
            <Icon size={18} className="shrink-0" strokeWidth={1.75} />
            {!collapsed && <span className="text-sm">{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Footer: theme + collapse + user */}
      <div className="px-2 py-3 border-t border-[var(--border-soft)] space-y-0.5">
        <ThemeToggle collapsed={collapsed} />
        <button
          type="button"
          onClick={onToggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="flex items-center gap-3 w-full px-3 py-2 rounded-lg text-[var(--text)] hover:text-[var(--text-h)] hover:bg-[var(--bg-subtle)] transition-colors"
        >
          {collapsed ? (
            <PanelLeftOpen size={18} className="shrink-0" strokeWidth={1.75} />
          ) : (
            <PanelLeftClose size={18} className="shrink-0" strokeWidth={1.75} />
          )}
          {!collapsed && <span className="text-sm font-medium">Collapse</span>}
        </button>
        <div className="pt-1 mt-1 border-t border-[var(--border-soft)]">
          <UserFooter collapsed={collapsed} />
        </div>
      </div>
    </Motion.aside>
  );
}
