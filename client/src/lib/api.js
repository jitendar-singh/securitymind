// Default to same-origin so the Vite proxy (see vite.config.js) routes
// /auth/*, /chat, /integrations, /settings, /reports, /conversations to the
// Flask backend. This keeps cookies same-site whether the dev server is hit
// via localhost or a LAN IP. Override with VITE_API_BASE for production
// builds where the backend is on a different origin.
const BASE = import.meta.env.VITE_API_BASE ?? "";

class ApiError extends Error {
  constructor(message, { status, body } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

// Late-bound 401 handler. Set by the auth store (avoids a circular import
// since auth.js imports api.js). Skipped on /auth/* paths so a failed login
// attempt doesn't trigger a logout side effect.
let _on401 = null;
export function setOn401(handler) {
  _on401 = typeof handler === "function" ? handler : null;
}

async function request(path, { method = "GET", body, signal } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
    signal,
    credentials: "include",
  });

  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }

  if (!res.ok) {
    if (res.status === 401 && _on401 && !path.startsWith("/auth/")) {
      try {
        _on401();
      } catch {
        /* ignore */
      }
    }
    throw new ApiError(data?.error || data?.message || `HTTP ${res.status}`, {
      status: res.status,
      body: data,
    });
  }
  return data;
}

export const api = {
  get: (path, opts) => request(path, { ...opts, method: "GET" }),
  post: (path, body, opts) => request(path, { ...opts, method: "POST", body }),
  put: (path, body, opts) => request(path, { ...opts, method: "PUT", body }),
  del: (path, opts) => request(path, { ...opts, method: "DELETE" }),
};

export { ApiError };
