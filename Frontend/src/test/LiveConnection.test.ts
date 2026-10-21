import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { connectLive } from "../live/connection";
import { api } from "../api/client";

vi.mock("../api/client", () => ({ API_BASE_URL: "", api: { me: vi.fn() } }));
class FakeSource extends EventTarget {
  static all: FakeSource[] = [];
  onerror: ((event: Event) => void) | null = null;
  onopen = null;
  close = vi.fn();
  constructor(public url: string, public options: EventSourceInit) { super(); FakeSource.all.push(this); }
  fail() { this.onerror?.(new Event("error")); }
  emit(type: string) { this.dispatchEvent(new MessageEvent(type)); }
}
let stop = () => {};
const status = vi.fn(), changed = vi.fn(), expired = vi.fn();
beforeEach(() => {
  vi.useFakeTimers(); vi.resetAllMocks(); FakeSource.all = [];
  vi.stubGlobal("EventSource", FakeSource);
  vi.spyOn(navigator, "onLine", "get").mockReturnValue(true);
  vi.mocked(api.me).mockRejectedValue(new Error("Network unavailable"));
  stop = connectLive(status, changed, expired);
});
afterEach(() => { stop(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("uses cookies without URL credentials and refreshes on changes, not heartbeat", () => {
  const source = FakeSource.all[0];
  expect(source.url).toBe("/api/live/stream");
  expect(source.options).toEqual({withCredentials: true});
  source.emit("change"); source.emit("heartbeat");
  expect(changed).toHaveBeenCalledTimes(1);
  expect(status).toHaveBeenLastCalledWith("Live");
  stop(); source.emit("change");
  expect(source.close).toHaveBeenCalledTimes(1);
  expect(changed).toHaveBeenCalledTimes(1);
});

it("backs off, probes auth, reconnects, and resyncs missed changes", async () => {
  FakeSource.all[0].fail();
  expect(status).toHaveBeenLastCalledWith("Reconnecting");
  expect(api.me).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(2_000);
  FakeSource.all[1].fail();
  await vi.advanceTimersByTimeAsync(4_000);
  FakeSource.all[2].fail();
  expect(status).toHaveBeenLastCalledWith("Offline");
  await vi.advanceTimersByTimeAsync(8_000);
  FakeSource.all[3].emit("change");
  expect(status).toHaveBeenLastCalledWith("Live");
  expect(changed).toHaveBeenCalledTimes(1);
  expect(expired).not.toHaveBeenCalled(); // Connectivity failures are not logouts.
});

it("stops immediately on session expiry without reconnecting", async () => {
  FakeSource.all[0].emit("session_expired");
  expect(expired).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(60_000);
  expect(FakeSource.all).toHaveLength(1);
});

it("pauses offline, resumes online and removes listeners on cleanup", async () => {
  window.dispatchEvent(new Event("offline"));
  expect(status).toHaveBeenLastCalledWith("Offline");
  await vi.advanceTimersByTimeAsync(60_000);
  expect(FakeSource.all).toHaveLength(1);
  window.dispatchEvent(new Event("online"));
  expect(FakeSource.all).toHaveLength(2);
  stop(); window.dispatchEvent(new Event("online"));
  expect(FakeSource.all).toHaveLength(2);
});

it("detects a silently stalled connection and honors heartbeats", async () => {
  FakeSource.all[0].emit("change");
  await vi.advanceTimersByTimeAsync(20_000);
  FakeSource.all[0].emit("heartbeat");
  await vi.advanceTimersByTimeAsync(20_000);
  expect(FakeSource.all[0].close).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(10_000);
  expect(FakeSource.all[0].close).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(2_000);
  expect(FakeSource.all).toHaveLength(2);
});

it("retries explicit server unavailability and ignores frames from old sockets", async () => {
  const first = FakeSource.all[0];
  first.emit("unavailable");
  await vi.advanceTimersByTimeAsync(2_000);
  first.emit("change"); first.emit("session_expired");
  expect(changed).not.toHaveBeenCalled();
  expect(expired).not.toHaveBeenCalled();
  FakeSource.all[1].emit("change");
  expect(changed).toHaveBeenCalledOnce();
});
