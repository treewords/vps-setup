import React, { createContext, useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import * as api from '../services/api';

const AuthContext = createContext(null);

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('dockerManagerToken'));
  const navigate = useNavigate();

  useEffect(() => {
    // This effect could be enhanced to verify the token with the backend
    if (token) {
      // For now, we'll assume the token is valid if it exists.
      // A robust implementation would decode the token to get user info or have a /me endpoint
      setUser({ token }); // Simplified user object
    }
  }, [token]);

  const login = async (username, password) => {
    const { data } = await api.login(username, password);
    localStorage.setItem('dockerManagerToken', data.token);
    setToken(data.token);
    setUser({ token: data.token }); // Simplified
    navigate('/');
  };

  const logout = () => {
    localStorage.removeItem('dockerManagerToken');
    setToken(null);
    setUser(null);
    navigate('/login');
  };

  const value = {
    user,
    token,
    login,
    logout,
    isAuthenticated: !!token,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
