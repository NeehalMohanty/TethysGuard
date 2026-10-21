import { useEffect, useState, type ReactNode } from "react";
import { useAuth } from "../auth/AuthContext";
import { connectLive, type LiveStatus } from "./connection";
import { LiveContext } from "./LiveContext";

export function LiveProvider({ children }: { children: ReactNode }) {
  const { signedOut } = useAuth();
  const [revision, setRevision] = useState(0);
  const [attempt, setAttempt] = useState(0);
  const [status, setStatus] = useState<LiveStatus>("Reconnecting");
  useEffect(() => connectLive(setStatus, () => setRevision(value => value + 1), signedOut),
    [attempt, signedOut]);
  return <LiveContext.Provider value={{ revision, status, reconnect: () => setAttempt(value => value + 1) }}>
    {children}
  </LiveContext.Provider>;
}
