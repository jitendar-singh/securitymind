import { useEffect } from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { useAuth } from "../store/auth";

// Wraps the protected app routes. Bootstraps the session once, redirects to
// /login while unauthenticated, and preserves the originally requested URL
// in location.state so the login flow can return the user there.
export default function AuthGuard() {
  const user = useAuth((s) => s.user);
  const loading = useAuth((s) => s.loading);
  const initialized = useAuth((s) => s._initialized);
  const bootstrap = useAuth((s) => s.bootstrap);
  const location = useLocation();

  useEffect(() => {
    if (!initialized) bootstrap();
  }, [initialized, bootstrap]);

  if (!initialized || loading) {
    return (
      <div className="min-h-screen grid place-items-center bg-[var(--bg)] text-[var(--text-muted)]">
        <Loader2 size={22} className="animate-spin" />
      </div>
    );
  }

  if (!user) {
    return (
      <Navigate
        to="/login"
        replace
        state={{ from: location.pathname + location.search }}
      />
    );
  }

  return <Outlet />;
}
