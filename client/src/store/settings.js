import { create } from "zustand";
import { api, ApiError } from "../lib/api";

const errMessage = (err) =>
  err instanceof ApiError
    ? err.body?.error || err.message
    : err?.message || "Request failed";

const initialState = {
  agents: [],          // [{id, model, default}]
  selections: {},      // {agent_id: model}  user overrides
  loading: false,
  saving: false,
  error: null,
};

export const useSettings = create((set, get) => ({
  ...initialState,

  reset: () => set({ ...initialState }),

  fetch: async () => {
    set({ loading: true, error: null });
    try {
      const data = await api.get("/settings/models");
      set({
        agents: data.agents || [],
        selections: data.selections || {},
        loading: false,
      });
    } catch (err) {
      set({ loading: false, error: errMessage(err) });
    }
  },

  setSelection: (agentId, model) => {
    const next = { ...get().selections };
    // empty string / null → "use default" → remove the override
    if (model && model !== "default") next[agentId] = model;
    else delete next[agentId];
    set({ selections: next });
  },

  save: async () => {
    set({ saving: true, error: null });
    try {
      const data = await api.put("/settings/models", {
        selections: get().selections,
      });
      set({
        agents: data.agents || [],
        selections: data.selections || {},
        saving: false,
      });
      return true;
    } catch (err) {
      set({ saving: false, error: errMessage(err) });
      return false;
    }
  },
}));
