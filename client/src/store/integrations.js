import { create } from "zustand";
import { api, ApiError } from "../lib/api";

const errMessage = (err) =>
  err instanceof ApiError
    ? err.body?.error || err.message
    : err?.message || "Request failed";

const initialState = {
  items: [],
  loading: false,
  error: null,
  testing: {}, // id -> { status, message } | "pending"
};

export const useIntegrations = create((set, get) => ({
  ...initialState,

  reset: () => set({ ...initialState }),

  fetch: async () => {
    set({ loading: true, error: null });
    try {
      const items = await api.get("/integrations");
      set({ items, loading: false });
    } catch (err) {
      set({ loading: false, error: errMessage(err) });
    }
  },

  create: async ({ provider, name, config, enabled = true }) => {
    const created = await api.post("/integrations", {
      provider,
      name,
      config,
      enabled,
    });
    set({ items: [...get().items, created] });
    return created;
  },

  update: async (id, patch) => {
    const updated = await api.put(`/integrations/${id}`, patch);
    set({ items: get().items.map((it) => (it.id === id ? updated : it)) });
    return updated;
  },

  remove: async (id) => {
    await api.del(`/integrations/${id}`);
    set({ items: get().items.filter((it) => it.id !== id) });
  },

  test: async (id) => {
    set({ testing: { ...get().testing, [id]: "pending" } });
    try {
      const result = await api.post(`/integrations/${id}/test`);
      set({ testing: { ...get().testing, [id]: result } });
      return result;
    } catch (err) {
      const result = {
        status: "error",
        message:
          err instanceof ApiError
            ? err.body?.message || err.body?.error || err.message
            : err?.message || "Test failed",
      };
      set({ testing: { ...get().testing, [id]: result } });
      return result;
    }
  },
}));
