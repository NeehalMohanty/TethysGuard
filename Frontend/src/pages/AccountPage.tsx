import { useState, type FormEvent } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import "./Accounts.css";

export function AccountPage() {
  const { user, signedOut } = useAuth();
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault(); setError("");
    if (password !== confirm) { setError("New passwords do not match"); return; }
    setBusy(true);
    try { await api.changePassword(current, password); signedOut(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to change password"); }
    finally { setBusy(false); }
  }
  return <div className="page"><h1>Your account</h1><section className="panel detail-panel account-panel">
    <p>{user?.username} · {user?.role}</p><h2>Change password</h2>
    <p>Use 15–128 characters. This signs you out on every device.</p>
    <form onSubmit={event => void submit(event)}><fieldset disabled={busy}>
      <label>Current password<input type="password" required autoComplete="current-password" maxLength={128} value={current} onChange={e => setCurrent(e.target.value)} /></label>
      <label>New password<input type="password" required autoComplete="new-password" minLength={15} maxLength={128} value={password} onChange={e => setPassword(e.target.value)} /></label>
      <label>Confirm new password<input type="password" required autoComplete="new-password" minLength={15} maxLength={128} value={confirm} onChange={e => setConfirm(e.target.value)} /></label>
      <button>{busy ? "Changing…" : "Change password"}</button>
    </fieldset></form>{error && <p role="alert">{error}</p>}
  </section></div>;
}
