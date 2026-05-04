import { create } from "zustand";
import { persist } from "zustand/middleware";
import { api, ApiError } from "../lib/api";
import { useHistory } from "./history";

const newId = () =>
  globalThis.crypto?.randomUUID?.() ||
  `m_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

const newSessionId = () => `s_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

export const useConversation = create(
  persist(
    (set, get) => ({
      messages: [],
      sending: false,
      sessionId: newSessionId(),
      // dirty = there are unsaved turns since the last archive/load. Without
      // this, deleting a chat in History and clicking New chat would re-archive
      // the still-loaded conversation.
      dirty: false,

      _abortController: null,

      abort: () => {
        const ac = get()._abortController;
        if (ac) ac.abort();
      },

      newChat: () => {
        const { messages, sessionId, dirty, _abortController } = get();
        if (_abortController) _abortController.abort();
        if (dirty && messages.length > 0) {
          useHistory.getState().archive({ sessionId, messages });
        }
        set({
          messages: [],
          sending: false,
          sessionId: newSessionId(),
          dirty: false,
          _abortController: null,
        });
      },

      loadFromHistory: (entry) => {
        // Archive the current chat if it has unsaved turns
        const { messages, sessionId, dirty } = get();
        if (dirty && messages.length > 0 && sessionId !== entry.sessionId) {
          useHistory.getState().archive({ sessionId, messages });
        }
        // Remove the entry from history — the user is "resuming" it. If they
        // continue and click New chat, the updated version archives back.
        useHistory.getState().remove(entry.id);
        set({
          messages: entry.messages,
          sessionId: entry.sessionId,
          sending: false,
          dirty: false,
        });
      },

      send: async (text) => {
        const trimmed = text.trim();
        if (!trimmed || get().sending) return;

        const ac = new AbortController();
        const userMsg = {
          id: newId(),
          role: "user",
          content: trimmed,
          createdAt: Date.now(),
        };
        set({
          messages: [...get().messages, userMsg],
          sending: true,
          dirty: true,
          _abortController: ac,
        });

        try {
          const data = await api.post(
            "/chat",
            { message: trimmed, session_id: get().sessionId },
            { signal: ac.signal }
          );
          const agentMsg = {
            id: newId(),
            role: "agent",
            content: data?.response ?? "",
            agent: data?.agent ?? null, // sub-agent badge, optional
            createdAt: Date.now(),
          };
          set({
            messages: [...get().messages, agentMsg],
            sending: false,
            _abortController: null,
          });
        } catch (err) {
          if (err?.name === "AbortError") {
            set({
              messages: [
                ...get().messages,
                {
                  id: newId(),
                  role: "agent",
                  content: "_Stopped by user._",
                  cancelled: true,
                  createdAt: Date.now(),
                },
              ],
              sending: false,
              _abortController: null,
            });
            return;
          }
          const message =
            err instanceof ApiError
              ? `**Error ${err.status ?? ""}** — ${err.message}`
              : `**Error** — ${err?.message || "Could not reach the agent."}`;
          set({
            messages: [
              ...get().messages,
              {
                id: newId(),
                role: "agent",
                content: message,
                error: true,
                createdAt: Date.now(),
              },
            ],
            sending: false,
            _abortController: null,
          });
        }
      },
    }),
    {
      name: "secmind:conversation",
      partialize: (s) => ({
        messages: s.messages,
        sessionId: s.sessionId,
        dirty: s.dirty,
      }),
      version: 3,
    }
  )
);
