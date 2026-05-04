import { BrowserRouter, Routes, Route } from "react-router-dom";
import AppShell from "./layouts/AppShell";
import AuthGuard from "./components/AuthGuard";
import Chat from "./pages/Chat";
import Integrations from "./pages/Integrations";
import History from "./pages/History";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import Signup from "./pages/Signup";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route element={<AuthGuard />}>
          <Route element={<AppShell />}>
            <Route index element={<Chat />} />
            <Route path="integrations" element={<Integrations />} />
            <Route path="reports" element={<Reports />} />
            <Route path="history" element={<History />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
