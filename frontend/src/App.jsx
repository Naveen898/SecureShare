import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import UploadPage from './pages/UploadPage';
import FilesPage from './pages/FilesPage';
import ReceivePage from './pages/ReceivePage';
import NotFoundPage from './pages/NotFoundPage';
import authService from './services/authService';
import AdminTransfersPage from './pages/AdminTransfersPage';
import AdminDashboardPage from './pages/AdminDashboardPage';
import MyTransfersPage from './pages/MyTransfersPage';

const PrivateRoute = ({ children }) => {
  return authService.isAuthenticated() ? children : <Navigate to="/login" />;
};

const App = () => (
  <Router>
    <Navbar />
    <div className="main-content">
      <Routes>
  <Route path="/login" element={<LoginPage />} />
  <Route path="/register" element={<RegisterPage />} />
  <Route path="/forgot" element={<ForgotPasswordPage />} />
  <Route path="/reset" element={<ResetPasswordPage />} />
        <Route path="/upload" element={<PrivateRoute><UploadPage /></PrivateRoute>} />
          <Route path="/files" element={<PrivateRoute><FilesPage /></PrivateRoute>} />
          <Route path="/receive" element={<ReceivePage />} />
          <Route path="/admin/transfers" element={<PrivateRoute><AdminTransfersPage /></PrivateRoute>} />
          <Route path="/admin" element={<PrivateRoute><AdminDashboardPage /></PrivateRoute>} />
          <Route path="/transfers" element={<PrivateRoute><MyTransfersPage /></PrivateRoute>} />
        <Route path="/" element={<Navigate to="/files" />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </div>
  </Router>
);

export default App;