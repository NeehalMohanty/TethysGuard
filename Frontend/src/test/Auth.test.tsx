import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth/AuthProvider";
import { useAuth } from "../auth/AuthContext";
import { LoginPage } from "../pages/LoginPage";
import { UsersPage } from "../pages/UsersPage";
import { api, ApiError } from "../api/client";

vi.mock("../api/client", async importOriginal => {
  const original = await importOriginal<typeof import("../api/client")>();
  return {...original, api: {...original.api, me: vi.fn(), login: vi.fn(), logout: vi.fn(), users: vi.fn(), createUser: vi.fn(), updateUser: vi.fn()}};
});
const admin = {id: 1, username: "admin", role: "admin" as const, active: true};
const session = {user: admin, csrf_token: "csrf"};
beforeEach(() => vi.resetAllMocks());

function Harness() {
  const auth = useAuth();
  if (auth.loading) return <p>Loading session</p>;
  if (auth.error) return <><p role="alert">{auth.error}</p><button onClick={auth.reload}>Retry session</button></>;
  if (!auth.user) return <LoginPage />;
  return <><p>Welcome {auth.user.username}</p><button onClick={() => void auth.logout()}>Logout</button></>;
}

it("requires login and restores authenticated identity without storing a password", async () => {
  vi.mocked(api.me).mockRejectedValue(new ApiError("Sign in required", 401));
  vi.mocked(api.login).mockResolvedValue(session);
  render(<AuthProvider><Harness /></AuthProvider>);
  const user = userEvent.setup();
  await screen.findByRole("heading", {name: "Sign in"});
  await user.type(screen.getByLabelText("Username"), "admin");
  await user.type(screen.getByLabelText("Password", {exact: true}), "test-only password");
  await user.click(screen.getByRole("button", {name: "Sign in"}));
  await screen.findByText("Welcome admin");
  expect(api.login).toHaveBeenCalledWith("admin", "test-only password");
  expect(localStorage.length).toBe(0);
  expect(sessionStorage.length).toBe(0);
});

it("shows generic login failures and clears the password for retry", async () => {
  vi.mocked(api.me).mockRejectedValue(new ApiError("Sign in required", 401));
  vi.mocked(api.login).mockRejectedValue(new ApiError("Invalid username or password", 401));
  render(<AuthProvider><Harness /></AuthProvider>);
  const user = userEvent.setup();
  await screen.findByLabelText("Username");
  await user.type(screen.getByLabelText("Username"), "admin");
  await user.type(screen.getByLabelText("Password", {exact: true}), "bad");
  await user.click(screen.getByRole("button", {name: "Sign in"}));
  expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password");
  expect(screen.getByLabelText("Password", {exact: true})).toHaveValue("");
});

it("restores a session then removes protected content when it expires", async () => {
  vi.mocked(api.me).mockResolvedValue(session);
  render(<AuthProvider><Harness /></AuthProvider>);
  await screen.findByText("Welcome admin");
  window.dispatchEvent(new Event("tethysguard:session-expired"));
  await screen.findByRole("heading", {name: "Sign in"});
  expect(screen.queryByText("Welcome admin")).not.toBeInTheDocument();
});

it("signs out only after the server logout succeeds", async () => {
  vi.mocked(api.me).mockResolvedValue(session);
  vi.mocked(api.logout).mockResolvedValue();
  render(<AuthProvider><Harness /></AuthProvider>);
  const user = userEvent.setup();
  await screen.findByText("Welcome admin");
  await user.click(screen.getByRole("button", {name: "Logout"}));
  await screen.findByRole("heading", {name: "Sign in"});
  expect(api.logout).toHaveBeenCalledOnce();
});

it("allows retry when the session service is unavailable", async () => {
  vi.mocked(api.me).mockRejectedValueOnce(new Error("offline")).mockResolvedValue(session);
  render(<AuthProvider><Harness /></AuthProvider>);
  const user = userEvent.setup();
  await screen.findByRole("alert");
  await user.click(screen.getByRole("button", {name: "Retry session"}));
  await screen.findByText("Welcome admin");
});

it("blocks the user management screen for viewers without fetching accounts", async () => {
  vi.mocked(api.me).mockResolvedValue({...session, user: {...admin, role: "viewer"}});
  render(<AuthProvider><UsersPage /></AuthProvider>);
  await waitFor(() => expect(api.me).toHaveBeenCalledOnce());
  expect(await screen.findByText("Only admins can manage accounts.")).toBeInTheDocument();
  expect(api.users).not.toHaveBeenCalled();
});

it("lets admins create and disable accounts", async () => {
  vi.mocked(api.me).mockResolvedValue(session);
  vi.mocked(api.users).mockResolvedValue([admin]);
  const viewer = {id: 2, username: "reader", role: "viewer" as const, active: true};
  vi.mocked(api.createUser).mockResolvedValue(viewer);
  vi.mocked(api.updateUser).mockResolvedValue({...viewer, active: false});
  render(<AuthProvider><UsersPage /></AuthProvider>);
  const user = userEvent.setup();
  await screen.findByLabelText("New username");
  await user.type(screen.getByLabelText("New username"), "reader");
  await user.type(screen.getByLabelText("Initial password"), "test-only password long");
  await user.click(screen.getByRole("button", {name: "Create account"}));
  await screen.findByText("reader");
  expect(screen.getByLabelText("Initial password")).toHaveValue("");
  const buttons = screen.getAllByRole("button", {name: "Disable"});
  expect(buttons[0]).toBeDisabled();
  await user.click(buttons[1]);
  await screen.findByRole("button", {name: "Enable"});
  expect(api.updateUser).toHaveBeenCalledWith(2, "viewer", false);
});
