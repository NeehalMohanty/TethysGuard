import {
  Activity,
  BellRing,
  Gauge,
  RadioTower,
  ShieldCheck,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import { useState } from "react";
import { useAuth } from "../auth/AuthContext";

const navigation = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/alerts", label: "Alerts", icon: BellRing },
  { to: "/events", label: "Events", icon: Activity },
];

export function Layout() {
  const { user, logout } = useAuth();
  const [logoutError, setLogoutError] = useState("");
  const [busy, setBusy] = useState(false);
  async function signOut() {
    setBusy(true); setLogoutError("");
    try { await logout(); }
    catch { setLogoutError("Sign out failed. Check the connection and try again."); }
    finally { setBusy(false); }
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><ShieldCheck size={24} /></span>
          <div>
            <strong>TethysGuard</strong>
            <small>Security Operations</small>
          </div>
        </div>
        <nav aria-label="Primary navigation">
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
            >
              <Icon size={19} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="account-session">
          <NavLink to="/account">{user?.username} · {user?.role}</NavLink>
          {user?.role === "admin" && <NavLink to="/users">Manage users</NavLink>}
          <button disabled={busy} onClick={() => void signOut()}>{busy ? "Signing out…" : "Sign out"}</button>
          {logoutError && <p role="alert">{logoutError}</p>}
        </div>
        <div className="system-status">
          <span className="status-dot" />
          <div>
            <strong>Local SOC workspace</strong>
            <small>Manual refresh</small>
          </div>
          <RadioTower size={18} />
        </div>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
