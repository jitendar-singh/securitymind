import { memo, useState } from "react";
import { motion as Motion } from "framer-motion";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Check, Copy, ShieldCheck, User, AlertTriangle } from "lucide-react";

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <button
      type="button"
      onClick={onCopy}
      aria-label="Copy code"
      className="absolute top-2 right-2 size-7 grid place-items-center rounded-md bg-[var(--bg-elev)] border border-[var(--border-soft)] opacity-0 group-hover:opacity-100 transition-opacity text-[var(--text-muted)] hover:text-[var(--text-h)]"
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </button>
  );
}

const markdownComponents = {
  pre: ({ children, ...props }) => {
    // children is a single <code> element; pull its text for copying
    let text = "";
    try {
      const codeEl = Array.isArray(children) ? children[0] : children;
      const inner = codeEl?.props?.children;
      text = Array.isArray(inner) ? inner.join("") : String(inner ?? "");
    } catch {
      /* fall through with empty text */
    }
    return (
      <div className="relative group my-3">
        <pre {...props}>{children}</pre>
        <CopyButton text={text} />
      </div>
    );
  },
  a: (props) => (
    <a
      {...props}
      target="_blank"
      rel="noopener noreferrer"
      className="text-[var(--accent)] hover:underline underline-offset-2"
    />
  ),
  table: (props) => (
    <div className="overflow-x-auto my-3">
      <table {...props} className="text-sm border-collapse" />
    </div>
  ),
  th: (props) => (
    <th
      {...props}
      className="border border-[var(--border-soft)] px-3 py-1.5 text-left bg-[var(--bg-subtle)] font-medium text-[var(--text-h)]"
    />
  ),
  td: (props) => (
    <td
      {...props}
      className="border border-[var(--border-soft)] px-3 py-1.5"
    />
  ),
  ul: (props) => <ul {...props} className="list-disc pl-5 my-2 space-y-1" />,
  ol: (props) => <ol {...props} className="list-decimal pl-5 my-2 space-y-1" />,
};

function MessageBubble({ message }) {
  const isUser = message.role === "user";
  const Icon = message.error ? AlertTriangle : isUser ? User : ShieldCheck;

  return (
    <Motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: "easeOut" }}
      className="flex gap-3 px-6 py-4"
    >
      <div
        className={[
          "shrink-0 size-8 rounded-full grid place-items-center",
          isUser
            ? "bg-[var(--bg-subtle)] text-[var(--text)]"
            : message.error
            ? "bg-red-500/10 text-red-500"
            : "bg-gradient-to-br from-[var(--accent)] to-[var(--accent-h)] text-white",
        ].join(" ")}
      >
        <Icon size={16} strokeWidth={2} />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-[13px] font-semibold text-[var(--text-h)]">
            {isUser ? "You" : "Security Mind"}
          </span>
          {!isUser && message.agent && (
            <span className="text-[11px] px-1.5 py-0.5 rounded-md bg-[var(--accent-bg)] text-[var(--accent)] font-medium">
              {message.agent}
            </span>
          )}
        </div>
        <div className="prose-app text-[var(--text-h)] text-[15px] leading-[1.55]">
          {isUser ? (
            <p className="whitespace-pre-wrap break-words">{message.content}</p>
          ) : (
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={markdownComponents}
            >
              {message.content || ""}
            </ReactMarkdown>
          )}
        </div>
      </div>
    </Motion.div>
  );
}

export default memo(MessageBubble);
