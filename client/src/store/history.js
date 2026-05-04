import { create } from "zustand";
import { persist } from "zustand/middleware";

const newId = () => `h_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

const titleFrom = (messages) => {
  const firstUser = messages.find((m) => m.role === "user");
  if (!firstUser) return "New conversation";
  const t = firstUser.content.trim().replace(/\s+/g, " ");
  return t.length > 80 ? t.slice(0, 80) + "…" : t;
};

export const useHistory = create(
  persist(
    (set, get) => ({
      sessions: [], // newest first

      archive: ({ sessionId, messages }) => {
        if (!messages || messages.length === 0) return null;
        const entry = {
          id: newId(),
          sessionId,
          title: titleFrom(messages),
          messages,
          createdAt: messages[0]?.createdAt ?? Date.now(),
          updatedAt: messages[messages.length - 1]?.createdAt ?? Date.now(),
        };
        set({ sessions: [entry, ...get().sessions] });
        return entry;
      },

      remove: (id) =>
        set({ sessions: get().sessions.filter((s) => s.id !== id) }),

      clear: () => set({ sessions: [] }),

      get: (id) => get().sessions.find((s) => s.id === id) || null,
    }),
    {
      name: "secmind:history",
      version: 1,
    }
  )
);
