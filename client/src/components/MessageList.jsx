import { useEffect, useRef } from "react";
import MessageBubble from "./MessageBubble";

export default function MessageList({ messages, sending }) {
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages.length, sending]);

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-3xl mx-auto py-6">
        {messages.map((m) => (
          <MessageBubble key={m.id} message={m} />
        ))}
        {sending && (
          <div className="flex gap-3 px-6 py-4">
            <div className="shrink-0 size-8 rounded-full bg-gradient-to-br from-[var(--accent)] to-[var(--accent-h)]" />
            <div className="flex items-center gap-1 pt-2">
              <span className="size-1.5 rounded-full bg-[var(--text-muted)] animate-pulse" />
              <span className="size-1.5 rounded-full bg-[var(--text-muted)] animate-pulse [animation-delay:120ms]" />
              <span className="size-1.5 rounded-full bg-[var(--text-muted)] animate-pulse [animation-delay:240ms]" />
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>
    </div>
  );
}
