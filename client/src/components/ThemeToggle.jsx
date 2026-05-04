import { useState } from "react";
import { Moon, Sun } from "lucide-react";
import { getStoredTheme, resolveTheme, setTheme } from "../lib/theme";

export default function ThemeToggle({ collapsed = false }) {
  const [current, setCurrent] = useState(() => resolveTheme(getStoredTheme()));

  const toggle = () => {
    const next = current === "dark" ? "light" : "dark";
    setTheme(next);
    setCurrent(next);
  };

  const Icon = current === "dark" ? Sun : Moon;

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${current === "dark" ? "light" : "dark"} mode`}
      className="flex items-center gap-3 w-full px-3 py-2 rounded-lg text-[var(--text)] hover:text-[var(--text-h)] hover:bg-[var(--bg-subtle)] transition-colors"
    >
      <Icon size={18} className="shrink-0" strokeWidth={1.75} />
      {!collapsed && (
        <span className="text-sm font-medium">
          {current === "dark" ? "Light mode" : "Dark mode"}
        </span>
      )}
    </button>
  );
}
