import { ShieldCheck } from "lucide-react";

export default function AuthShell({ title, subtitle, children }) {
  return (
    <div className="min-h-screen grid place-items-center bg-[var(--bg)] px-4 py-12">
      <div className="w-full max-w-md">
        <div className="mb-8 flex items-center justify-center gap-2">
          <div className="size-9 rounded-lg bg-gradient-to-br from-[var(--accent)] to-[var(--accent-h)] grid place-items-center text-white shadow-[var(--shadow-sm)]">
            <ShieldCheck size={20} strokeWidth={2.25} />
          </div>
          <span className="text-lg font-semibold tracking-tight text-[var(--text-h)]">
            Security Mind
          </span>
        </div>

        <div className="rounded-2xl border border-[var(--border-soft)] bg-[var(--bg-elev)] p-8 shadow-[var(--shadow-md)]">
          <div className="mb-6 text-center">
            <h1 className="text-2xl font-semibold text-[var(--text-h)] tracking-tight">
              {title}
            </h1>
            <p className="mt-1 text-sm text-[var(--text-muted)]">{subtitle}</p>
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}

export function AuthField({ label, htmlFor, children }) {
  return (
    <label htmlFor={htmlFor} className="block">
      <span className="text-[13px] font-medium text-[var(--text-h)]">
        {label}
      </span>
      <div className="mt-1.5">{children}</div>
    </label>
  );
}

export function AuthDivider() {
  return (
    <div className="relative my-6">
      <div className="absolute inset-0 flex items-center">
        <div className="w-full border-t border-[var(--border-soft)]" />
      </div>
      <div className="relative flex justify-center">
        <span className="bg-[var(--bg-elev)] px-2 text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
          or
        </span>
      </div>
    </div>
  );
}
