import { createContext, useContext } from "react";
import type { User } from "../api/types";

export interface AuthState {
  user: User | null;
  loading: boolean;
  error: string;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  reload: () => void;
  signedOut: () => void;
}
export const AuthContext = createContext<AuthState | null>(null);
export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("Authentication provider is missing");
  return value;
}
