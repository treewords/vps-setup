import React, { useState } from 'react';
import { TextField, Button, Checkbox, FormControlLabel, Link, Typography } from '@mui/material';
import { useAuth } from '../context/AuthContext';

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      await login(username, password);
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-purple-600 to-blue-500">
      <div className="w-full max-w-md p-8 space-y-8 bg-white bg-opacity-95 backdrop-blur-sm rounded-2xl shadow-2xl">
        <div className="text-center">
            <div className="mx-auto flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-blue-600 to-blue-800 shadow-lg text-white text-4xl">
                🐳
            </div>
            <h2 className="mt-6 text-3xl font-bold text-gray-800">
                Docker Manager
            </h2>
            <p className="mt-2 text-sm text-gray-600">
                Secure Container Management
            </p>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleLogin}>
            {error && <p className="text-center text-red-500">{error}</p>}

            <div className="rounded-md shadow-sm -space-y-px">
                <div>
                    <TextField
                        id="username"
                        label="Username or Email"
                        variant="outlined"
                        fullWidth
                        required
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                    />
                </div>
                <div className="pt-4">
                     <TextField
                        id="password"
                        label="Password"
                        type="password"
                        variant="outlined"
                        fullWidth
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                </div>
            </div>

            <div className="flex items-center justify-between">
                <FormControlLabel control={<Checkbox color="primary" />} label="Remember me" />
                <div className="text-sm">
                    <Link href="#" variant="body2">
                        Forgot your password?
                    </Link>
                </div>
            </div>

            <div>
                <Button
                    type="submit"
                    variant="contained"
                    fullWidth
                    disabled={loading}
                    className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                    {loading ? 'Signing In...' : 'Sign In'}
                </Button>
            </div>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;
