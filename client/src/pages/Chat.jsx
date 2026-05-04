import { useState } from "react";
import { useConversation } from "../store/conversation";
import Hero from "../components/Hero";
import MessageList from "../components/MessageList";
import PromptBar from "../components/PromptBar";

export default function Chat() {
  const messages = useConversation((s) => s.messages);
  const sending = useConversation((s) => s.sending);
  const send = useConversation((s) => s.send);
  const abort = useConversation((s) => s.abort);

  const [draft, setDraft] = useState("");
  const [focusKey, setFocusKey] = useState(0);

  const submit = async () => {
    const value = draft.trim();
    if (!value) return;
    setDraft("");
    await send(value);
  };

  const pickSuggestion = (text) => {
    setDraft(text);
    setFocusKey((k) => k + 1);
  };

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {messages.length === 0 ? (
        <Hero onPick={pickSuggestion} />
      ) : (
        <MessageList messages={messages} sending={sending} />
      )}
      <PromptBar
        value={draft}
        onChange={setDraft}
        onSubmit={submit}
        onStop={abort}
        sending={sending}
        autoFocusKey={focusKey}
      />
    </div>
  );
}
