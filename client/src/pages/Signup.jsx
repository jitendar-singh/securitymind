import { useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { useAuth } from "../store/auth";
import AuthShell, { AuthDivider, AuthField } from "../components/AuthShell";

// Same-origin via the Vite proxy by default; same override knob as api.js.
const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export default function Signup() {
  const user = useAuth((s) => s.user);
  const signup = useAuth((s) => s.signup);
  const error = useAuth((s) => s.error);
  const location = useLocation();
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const redirectTo = location.state?.from || "/";
  if (user) return <Navigate to={redirectTo} replace />;

  const onSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    const ok = await signup({ email, password, name: name || undefined });
    setSubmitting(false);
    if (ok) navigate(redirectTo, { replace: true });
  };

  return (
    <AuthShell title="Create your account" subtitle="Start using Security Mind">
      <form onSubmit={onSubmit} className="space-y-4">
        <AuthField label="Name" htmlFor="name">
          <input
            id="name"
            type="text"
            autoComplete="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-2 text-sm text-[var(--text-h)] outline-none focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent-ring)]"
          />
        </AuthField>
        <AuthField label="Email" htmlFor="email">
          <input
            id="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-2 text-sm text-[var(--text-h)] outline-none focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent-ring)]"
          />
        </AuthField>
        <AuthField label="Password" htmlFor="password">
          <input
            id="password"
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-2 text-sm text-[var(--text-h)] outline-none focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent-ring)]"
          />
          <p className="mt-1 text-[12px] text-[var(--text-muted)]">
            At least 8 characters.
          </p>
        </AuthField>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-[13px] text-red-500">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-[var(--accent)] px-4 py-2.5 text-sm font-medium text-white hover:bg-[var(--accent-h)] disabled:opacity-60 transition-colors"
        >
          {submitting && <Loader2 size={16} className="animate-spin" />}
          Create account
        </button>
      </form>

      <AuthDivider />

      <a
        href={`${API_BASE}/auth/google/start`}
        className="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--bg-elev)] px-4 py-2.5 text-sm font-medium text-[var(--text-h)] hover:bg-[var(--bg-subtle)] transition-colors"
      >
        Continue with Google
      </a>

      <p className="mt-6 text-center text-sm text-[var(--text-muted)]">
        Already have an account?{" "}
        <Link
          to="/login"
          state={location.state}
          className="text-[var(--accent)] hover:text-[var(--accent-h)] font-medium"
        >
          Sign in
        </Link>
      </p>
    </AuthShell>
  );
}
