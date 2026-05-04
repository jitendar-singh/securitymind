import { create } from "zustand";
import { api, ApiError, setOn401 } from "../lib/api";
import { useConversation } from "./conversation";
import { useHistory } from "./history";
import { useIntegrations } from "./integrations";
import { useSettings } from "./settings";

// Auth lives in an httponly session cookie set by the Flask backend. We never
// touch the token in JS — the store just mirrors who the user is so the rest
// of the app can render gating + the user footer. `bootstrap()` runs once at
// app load to hydrate from the cookie via `/auth/me`.

const errMessage = (err) =>
  err instanceof ApiError
    ? err.body?.error || err.message
    : err?.message || "Request failed";

// Avoid leaking transcripts/history/integrations/settings between users on a
// shared computer. Clear conversation FIRST so newChat() doesn't archive a
// dirty transcript into history right before we clear it.
const _resetClientStores = () => {
  const safe = (fn) => {
    try {
      fn();
    } catch {
      /* store not yet hydrated */
    }
  };
  safe(() => useConversation.getState().newChat());
  safe(() => useHistory.getState().clear());
  safe(() => useIntegrations.getState().reset());
  safe(() => useSettings.getState().reset());
};

export const useAuth = create((set, get) => ({
  user: null,
  loading: true,
  error: null,
  _initialized: false,

  bootstrap: async () => {
    if (!get()._initialized) {
      // Register the 401 handler once so api.js can call us mid-session.
      setOn401(() => get().expire());
      set({ _initialized: true });
    }
    set({ loading: true, error: null });
    try {
      const data = await api.get("/auth/me");
      set({ user: data?.user || null, loading: false });
    } catch (err) {
      // 401 just means "not signed in yet" — not an error to surface.
      if (err instanceof ApiError && err.status === 401) {
        set({ user: null, loading: false });
        return;
      }
      set({ user: null, loading: false, error: errMessage(err) });
    }
  },

  signup: async ({ email, password, name }) => {
    set({ error: null });
    try {
      const data = await api.post("/auth/signup", { email, password, name });
      set({ user: data?.user || null });
      return true;
    } catch (err) {
      set({ error: errMessage(err) });
      return false;
    }
  },

  login: async ({ email, password }) => {
    set({ error: null });
    try {
      const data = await api.post("/auth/login", { email, password });
      set({ user: data?.user || null });
      return true;
    } catch (err) {
      set({ error: errMessage(err) });
      return false;
    }
  },

  logout: async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      /* clear local state regardless */
    }
    _resetClientStores();
    set({ user: null, error: null });
  },

  // Called by api.js when a request 401s mid-session — drop local user state
  // so the AuthGuard re-routes to /login on the next render.
  expire: () => {
    _resetClientStores();
    set({ user: null });
  },
}));
