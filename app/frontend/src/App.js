import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { CustomThemeProvider } from './context/ThemeContext';
import { AuthProvider } from './context/AuthContext';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import PrivateRoute from './components/auth/PrivateRoute';
import { DockerProvider } from './context/DockerContext';

function App() {
  return (
    <CustomThemeProvider>
      <Router>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/" element={<PrivateRoute><DockerProvider><Dashboard /></DockerProvider></PrivateRoute>} />
          </Routes>
        </AuthProvider>
      </Router>
    </CustomThemeProvider>
  );
}

export default App;
