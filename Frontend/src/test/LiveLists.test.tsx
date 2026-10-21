import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { EventsPage } from "../pages/EventsPage";
import { AlertsPage } from "../pages/AlertsPage";
import { LiveContext } from "../live/LiveContext";

vi.mock("../api/client", () => ({api: {events: vi.fn(), alerts: vi.fn()}}));
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.events).mockResolvedValue({events: [], total: 60, count: 0, limit: 20, offset: 20});
  vi.mocked(api.alerts).mockResolvedValue({alerts: [], total: 60, count: 0, limit: 20, offset: 20});
});

it.each([
  {Page: EventsPage, query: "events" as const, label: "event"},
  {Page: AlertsPage, query: "alerts" as const, label: "alert"},
])("preserves $query filters, pagination, and unfinished search text", async ({Page, query, label}) => {
  const page = (revision: number) => <LiveContext.Provider value={{revision, status: "Live", reconnect: vi.fn()}}>
    <MemoryRouter><Page /></MemoryRouter>
  </LiveContext.Provider>;
  const view = render(page(0)); const user = userEvent.setup();
  await screen.findByRole("button", {name: "Next page"});
  await user.selectOptions(screen.getByLabelText(`Filter ${label} severity`), "high");
  await user.click(screen.getByRole("button", {name: "Next page"}));
  await user.type(screen.getByLabelText(`Search ${query}`), "unfinished search");
  const count = vi.mocked(api[query]).mock.calls.length;
  view.rerender(page(1));
  await waitFor(() => expect(api[query]).toHaveBeenCalledTimes(count + 1));
  expect(api[query]).toHaveBeenLastCalledWith(expect.objectContaining({severity: "high", offset: 20}));
  expect(screen.getByLabelText(`Search ${query}`)).toHaveValue("unfinished search");
  expect(screen.getByLabelText(`Filter ${label} severity`)).toHaveValue("high");
  expect(screen.getByText("21–40 of 60")).toBeInTheDocument();
});
