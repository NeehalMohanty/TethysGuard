import { api, API_BASE_URL } from "../api/client";

export type LiveStatus = "Live" | "Reconnecting" | "Offline";

// One connection per signed-in tab, not one per component. Native EventSource
// cannot expose HTTP error status, so a REST probe handles rejected sessions.
export function connectLive(onStatus: (status: LiveStatus) => void, onChange: () => void,
  onExpired: () => void) {
  let source: EventSource | null = null;
  let stopped = false;
  let failures = 0;
  let probing = false;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let watchdog: ReturnType<typeof setTimeout> | undefined;

  function close() {
    if (source) {
      source.onopen = null; source.onerror = null;
      source.close(); source = null;
    }
    clearTimeout(watchdog);
  }
  function healthy() {
    failures = 0;
    onStatus("Live");
    clearTimeout(watchdog);
    watchdog = setTimeout(failed, 30_000);
  }
  function failed() {
    if (stopped) return;
    close();
    clearTimeout(retry);
    failures++;
    onStatus(navigator.onLine && failures < 3 ? "Reconnecting" : "Offline");
    if (!navigator.onLine) return;
    retry = setTimeout(open, Math.min(2_000 * 2 ** Math.min(failures - 1, 4), 30_000));
    if (!probing) {
      probing = true;
      // 401 is handled by the API client's session-expired event. A network
      // error must not log the user out or discard investigation drafts.
      void api.me().catch(() => {}).finally(() => { probing = false; });
    }
  }
  function open() {
    if (stopped) return;
    close(); clearTimeout(retry);
    if (!navigator.onLine) { onStatus("Offline"); return; }
    onStatus("Reconnecting");
    if (typeof EventSource === "undefined") { onStatus("Offline"); return; }
    const current = new EventSource(`${API_BASE_URL}/api/live/stream`, { withCredentials: true });
    source = current;
    // An opened socket is not proof that the stream is delivering frames.
    watchdog = setTimeout(failed, 30_000);
    current.addEventListener("change", () => {
      if (stopped || source !== current) return;
      healthy(); onChange();
    });
    current.addEventListener("heartbeat", () => {
      if (!stopped && source === current) healthy();
    });
    current.addEventListener("unavailable", () => {
      if (!stopped && source === current) failed();
    });
    current.addEventListener("session_expired", () => {
      if (stopped || source !== current) return;
      stop(); onExpired();
    });
    current.onerror = () => { if (source === current) failed(); };
  }
  function offline() { close(); clearTimeout(retry); onStatus("Offline"); }
  function online() { failures = 0; open(); }
  function stop() {
    stopped = true; close(); clearTimeout(retry);
    window.removeEventListener("offline", offline);
    window.removeEventListener("online", online);
  }
  window.addEventListener("offline", offline);
  window.addEventListener("online", online);
  open();
  return stop;
}
