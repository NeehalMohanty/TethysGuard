import { useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import "./Accounts.css";

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try { await login(username, password); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to sign in"); setPassword(""); }
    finally { setBusy(false); }
  }
  return <main className="login-page"><section className="panel detail-panel account-panel">
    <p className="eyebrow">TethysGuard · Security Operations</p><h1>Sign in</h1>
    <p>Your account controls what you can view and investigate.</p>
    <form onSubmit={event => void submit(event)}>
      <label>Username<input autoComplete="username" required maxLength={50} value={username} disabled={busy} onChange={e => setUsername(e.target.value)} /></label>
      <label>Password<input type="password" autoComplete="current-password" required maxLength={128} value={password} disabled={busy} onChange={e => setPassword(e.target.value)} /></label>
      <button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form>
    {error && <p role="alert">{error}</p>}
    <p>First time? Create the first admin locally with <code>python -m Backend.manage_users bootstrap --username admin</code>.</p>
    <p>There is no public signup or default password.</p>
  </section></main>;
}
