import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { AlertsPage } from "./pages/AlertsPage";
const DashboardPage = lazy(() => import("./pages/DashboardPage").then(module => ({ default: module.DashboardPage })));
import { EventsPage } from "./pages/EventsPage";
import { AuthProvider } from "./auth/AuthProvider";
import { useAuth } from "./auth/AuthContext";
import { LoginPage } from "./pages/LoginPage";
import { UsersPage } from "./pages/UsersPage";
import { AccountPage } from "./pages/AccountPage";
import { ErrorState } from "./components/PageState";
import { LiveProvider } from "./live/LiveProvider";

export default function App() {
  return <AuthProvider><AuthenticatedApp /></AuthProvider>;
}

function AuthenticatedApp() {
  const { user, loading, error, reload } = useAuth();
  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} retry={reload} />;
  if (!user) return <LoginPage />;
  return (
    <LiveProvider key={user.id}><Routes>
      <Route element={<Layout />}>
        <Route index element={<Suspense fallback={<LoadingState />}><DashboardPage /></Suspense>} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="events" element={<EventsPage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="account" element={<AccountPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes></LiveProvider>
  );
}
import { lazy, Suspense } from "react";
import { LoadingState } from "./components/PageState";
