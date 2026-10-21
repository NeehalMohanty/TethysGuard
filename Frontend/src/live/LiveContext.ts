import { createContext, useContext } from "react";
import type { LiveStatus } from "./connection";

export const LiveContext = createContext({
  revision: 0,
  status: "Offline" as LiveStatus,
  reconnect: () => {},
});
export const useLive = () => useContext(LiveContext);
