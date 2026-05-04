import { useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import SideRail from "../components/SideRail";
import { initTheme } from "../lib/theme";

const COLLAPSED_KEY = "secmind:rail-collapsed";

export default function AppShell() {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(COLLAPSED_KEY) === "1"
  );

  useEffect(() => {
    initTheme();
  }, []);

  useEffect(() => {
    localStorage.setItem(COLLAPSED_KEY, collapsed ? "1" : "0");
  }, [collapsed]);

  return (
    <div className="flex min-h-screen bg-[var(--bg)] text-[var(--text)]">
      <SideRail
        collapsed={collapsed}
        onToggle={() => setCollapsed((v) => !v)}
      />
      <main className="flex-1 min-w-0 flex flex-col">
        <Outlet />
      </main>
    </div>
  );
}
