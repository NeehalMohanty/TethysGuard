import { afterEach, expect, it, vi } from "vitest";
import { api, clearSession } from "../api/client";
afterEach(() => { vi.unstubAllGlobals(); clearSession(); });
it("encodes filters and omits empty parameters", async () => {
  const fetchMock = vi.fn().mockResolvedValue({ok: true, json: async () => ({alerts: [], total: 0})});
  vi.stubGlobal("fetch", fetchMock); await api.alerts({search: "a & b", status: "", offset: 0});
  expect(fetchMock.mock.calls[0][0]).toBe("/api/alerts?search=a+%26+b&offset=0");
});
it("sends status updates as JSON", async () => {
  const fetchMock = vi.fn().mockResolvedValue({ok: true, json: async () => ({})}); vi.stubGlobal("fetch", fetchMock);
  await api.updateAlertStatus(7, "resolved");
  expect(fetchMock).toHaveBeenCalledWith("/api/alerts/7", expect.objectContaining({method: "PATCH", body: '{"status":"resolved"}'}));
});
it("converts structured validation failures into readable errors", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ok: false, status: 422, json: async () => ({detail: [{msg: "Invalid"}]})}));
  await expect(api.events()).rejects.toThrow("Request failed with status 422");
});

it("sends investigation actions and paginated timeline requests", async () => {
  const fetchMock = vi.fn().mockResolvedValue({ok: true, json: async () => ({})});
  vi.stubGlobal("fetch", fetchMock);
  await api.assignAlert(7, null);
  expect(fetchMock).toHaveBeenLastCalledWith("/api/alerts/7/assignment", expect.objectContaining({
    method: "PATCH", body: JSON.stringify({assigned_to: null}),
  }));
  await api.addNote(7, "Evidence checked");
  expect(fetchMock).toHaveBeenLastCalledWith("/api/alerts/7/notes", expect.objectContaining({
    method: "POST", body: JSON.stringify({body: "Evidence checked"}),
  }));
  await api.updateAlertStatus(7, "resolved", "false_positive");
  expect(fetchMock).toHaveBeenLastCalledWith("/api/alerts/7", expect.objectContaining({
    method: "PATCH", body: JSON.stringify({status: "resolved", resolution: "false_positive"}),
  }));
  await api.timeline(7, 25);
  expect(fetchMock.mock.calls.at(-1)?.[0]).toBe("/api/alerts/7/timeline?limit=25&offset=25");
});

it("sends cookies and a session CSRF token, and handles empty logout responses", async () => {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce({ok: true, status: 200, json: async () => ({user: {id: 1}, csrf_token: "session-csrf"})})
    .mockResolvedValueOnce({ok: true, status: 204});
  vi.stubGlobal("fetch", fetchMock);
  await api.me();
  await api.logout();
  expect(fetchMock).toHaveBeenLastCalledWith("/api/auth/logout", expect.objectContaining({
    credentials: "include", headers: expect.objectContaining({"X-CSRF-Token": "session-csrf"}),
  }));
});

it("signals session expiry for protected requests, but not bad login credentials", async () => {
  const listener = vi.fn();
  window.addEventListener("tethysguard:session-expired", listener);
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ok: false, status: 401, json: async () => ({detail: "Unauthorized"})}));
  try {
    await expect(api.login("admin", "wrong")).rejects.toThrow();
    expect(listener).not.toHaveBeenCalled();
    await expect(api.alerts()).rejects.toThrow();
    expect(listener).toHaveBeenCalledOnce();
  } finally { window.removeEventListener("tethysguard:session-expired", listener); }
});
