import { useCallback, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, clearSession } from "../api/client";
import type { User } from "../api/types";
import { AuthContext } from "./AuthContext";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  const signedOut = useCallback(() => { clearSession(); setUser(null); }, []);
  useEffect(() => {
    window.addEventListener("tethysguard:session-expired", signedOut);
    return () => window.removeEventListener("tethysguard:session-expired", signedOut);
  }, [signedOut]);
  useEffect(() => {
    let active = true;
    setLoading(true); setError("");
    api.me().then(session => { if (active) setUser(session.user); }).catch((reason: unknown) => {
      if (!active) return;
      setUser(null);
      if (!(reason instanceof ApiError && reason.status === 401)) setError("Cannot reach the session service. Check the backend and retry.");
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [revision]);
  async function login(username: string, password: string) {
    const session = await api.login(username, password);
    setUser(session.user); setError("");
  }
  async function logout() { await api.logout(); signedOut(); }
  return <AuthContext.Provider value={{user, loading, error, login, logout, signedOut, reload: () => setRevision(value => value + 1)}}>
    {children}
  </AuthContext.Provider>;
}
