import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { Role, User } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ErrorState, LoadingState } from "../components/PageState";
import "./Accounts.css";

export function UsersPage() {
  const { user } = useAuth();
  const [users, setUsers] = useState<User[] | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (user?.role !== "admin") return;
    let active = true;
    setError("");
    api.users().then(data => { if (active) setUsers(data); }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : "Unable to load users");
    });
    return () => { active = false; };
  }, [user?.role, revision]);
  async function create(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      const created = await api.createUser(username, password, role);
      setUsers(value => [...(value ?? []), created]); setUsername(""); setPassword("");
      setNotice("Account created. Share its initial password privately.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to create user"); }
    finally { setBusy(false); }
  }
  async function update(account: User, nextRole: Role, active: boolean) {
    setBusy(true); setError(""); setNotice("");
    try {
      const saved = await api.updateUser(account.id, nextRole, active);
      setUsers(value => value?.map(item => item.id === saved.id ? saved : item) ?? null);
      setNotice("Account updated; its existing sessions were revoked.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to update user"); }
    finally { setBusy(false); }
  }
  if (user?.role !== "admin") return <ErrorState message="Only admins can manage accounts." />;
  return <div className="page"><h1>User management</h1>
    <section className="panel detail-panel account-panel"><h2>Create account</h2>
      <p>Viewer: read-only. Analyst: investigations. Admin: investigations, user management, and telemetry imports.</p>
      <form onSubmit={event => void create(event)}><fieldset disabled={busy}>
        <label>New username<input required minLength={3} maxLength={50} autoComplete="off" value={username} onChange={e => setUsername(e.target.value)} /></label>
        <label>Initial password<input type="password" required minLength={15} maxLength={128} autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} /></label>
        <label>Role<select value={role} onChange={e => setRole(e.target.value as Role)}>{["viewer", "analyst", "admin"].map(value => <option key={value}>{value}</option>)}</select></label>
        <button>{busy ? "Saving…" : "Create account"}</button>
      </fieldset></form>
      {error && <ErrorState message={error} retry={() => setRevision(value => value + 1)} />}
      {notice && <p role="status">{notice}</p>}
    </section>
    <section className="panel detail-panel"><h2>Accounts</h2>
      {!users ? <LoadingState /> : <div className="table-wrap"><table><thead><tr><th>Username</th><th>Role</th><th>Access</th></tr></thead><tbody>
        {users.map(account => <tr key={account.id}><td>{account.username}{account.id === user.id && " (you)"}</td>
          <td><select aria-label={`Role for ${account.username}`} value={account.role} disabled={busy || account.id === user.id}
            onChange={e => void update(account, e.target.value as Role, account.active)}>
            {["viewer", "analyst", "admin"].map(value => <option key={value}>{value}</option>)}
          </select></td><td><button disabled={busy || account.id === user.id} onClick={() => void update(account, account.role, !account.active)}>{account.active ? "Disable" : "Enable"}</button></td>
        </tr>)}
      </tbody></table></div>}
      <p>You cannot change your own access here. Disabled accounts and their history are retained.</p>
    </section>
  </div>;
}
