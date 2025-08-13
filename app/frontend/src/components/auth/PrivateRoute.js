import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

const PrivateRoute = ({ children }) => {
  const { isAuthenticated } = useAuth();

  // You might want to add a loading state here while auth is being checked
  return isAuthenticated ? children : <Navigate to="/login" />;
};

export default PrivateRoute;
