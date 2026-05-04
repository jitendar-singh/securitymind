const STORAGE_KEY = "secmind:theme";

export function getStoredTheme() {
  return localStorage.getItem(STORAGE_KEY); // "light" | "dark" | null
}

function systemPrefersDark() {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}

export function resolveTheme(stored = getStoredTheme()) {
  if (stored === "light" || stored === "dark") return stored;
  return systemPrefersDark() ? "dark" : "light";
}

export function applyTheme(theme) {
  const html = document.documentElement;
  html.classList.toggle("dark", theme === "dark");
  html.classList.toggle("light", theme === "light");
}

export function setTheme(theme) {
  if (theme === "system") {
    localStorage.removeItem(STORAGE_KEY);
    applyTheme(resolveTheme(null));
    return "system";
  }
  localStorage.setItem(STORAGE_KEY, theme);
  applyTheme(theme);
  return theme;
}

export function initTheme() {
  applyTheme(resolveTheme());
}
