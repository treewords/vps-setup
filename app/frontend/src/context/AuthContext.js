import React, { createContext, useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import jwt_decode from 'jwt-decode';
import * as api from '../services/api';

const AuthContext = createContext(null);

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(localStorage.getItem('dockerManagerAccessToken'));
  const [refreshToken, setRefreshToken] = useState(localStorage.getItem('dockerManagerRefreshToken'));
  const navigate = useNavigate();

  useEffect(() => {
    try {
      const storedToken = localStorage.getItem('dockerManagerAccessToken');
      if (storedToken) {
        const decoded = jwt_decode(storedToken);
        // Check if token is expired
        if (decoded.exp * 1000 < Date.now()) {
          // Here you would ideally use the refresh token or force logout
          logout();
        } else {
          setUser({ id: decoded.id, role: decoded.role });
          setAccessToken(storedToken);
        }
      }
    } catch (error) {
      // If token is invalid, logout
      logout();
    }
  }, []);

  const login = async (username, password) => {
    const { data } = await api.login(username, password);
    localStorage.setItem('dockerManagerAccessToken', data.accessToken);
    localStorage.setItem('dockerManagerRefreshToken', data.refreshToken);
    const decoded = jwt_decode(data.accessToken);
    setUser({ id: decoded.id, role: decoded.role });
    setAccessToken(data.accessToken);
    setRefreshToken(data.refreshToken);
    navigate('/');
  };

  const logout = async () => {
    try {
        await api.logout(refreshToken);
    } catch (error) {
        console.error("Logout failed, but clearing session anyway.", error);
    } finally {
        localStorage.removeItem('dockerManagerAccessToken');
        localStorage.removeItem('dockerManagerRefreshToken');
        setAccessToken(null);
        setRefreshToken(null);
        setUser(null);
        navigate('/login');
    }
  };

  const value = {
    user,
    accessToken,
    login,
    logout,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
