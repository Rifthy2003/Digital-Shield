import { Navigate, Route, Routes } from "react-router-dom";

import { AuthProvider } from "@/context/AuthContext";
import { ProtectedRoute } from "@/components/ProtectedRoute";

import Login from "@/pages/Login";
import Register from "@/pages/Register";
import Dashboard from "@/pages/Dashboard";
import UrlChecker from "@/pages/UrlChecker";
import MessageChecker from "@/pages/MessageChecker";
import BreachChecker from "@/pages/BreachChecker";
import PasswordHealth from "@/pages/PasswordHealth";
import AlertsPage from "@/pages/Alerts";
import Incidents from "@/pages/Incidents";
import Assistant from "@/pages/Assistant";
import Emergency from "@/pages/Emergency";
import Profile from "@/pages/Profile";
import Admin from "@/pages/Admin";

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/url-checker" element={<ProtectedRoute><UrlChecker /></ProtectedRoute>} />
        <Route path="/message-checker" element={<ProtectedRoute><MessageChecker /></ProtectedRoute>} />
        <Route path="/breach-checker" element={<ProtectedRoute><BreachChecker /></ProtectedRoute>} />
        <Route path="/password-health" element={<ProtectedRoute><PasswordHealth /></ProtectedRoute>} />
        <Route path="/alerts" element={<ProtectedRoute><AlertsPage /></ProtectedRoute>} />
        <Route path="/incidents" element={<ProtectedRoute><Incidents /></ProtectedRoute>} />
        <Route path="/assistant" element={<ProtectedRoute><Assistant /></ProtectedRoute>} />
        <Route path="/emergency" element={<ProtectedRoute><Emergency /></ProtectedRoute>} />
        <Route path="/profile" element={<ProtectedRoute><Profile /></ProtectedRoute>} />
        <Route path="/admin" element={<ProtectedRoute adminOnly><Admin /></ProtectedRoute>} />

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AuthProvider>
  );
}
