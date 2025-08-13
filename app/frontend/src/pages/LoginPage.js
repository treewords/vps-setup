import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, TextField, Button, Checkbox, FormControlLabel, Typography, Link } from '@mui/material';
import * as api from '../services/api';

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const { data } = await api.login(username, password);
      localStorage.setItem('dockerManagerToken', data.token);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed. Please try again.');
      setLoading(false);
    }
  };

  // The styles are complex and will be simplified for this implementation
  // We'll use MUI components and `sx` props to approximate the design
  return (
    <Box sx={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    }}>
      <Box
        component="form"
        onSubmit={handleLogin}
        sx={{
          width: '100%',
          maxWidth: '400px',
          p: '40px',
          borderRadius: '20px',
          background: 'rgba(255, 255, 255, 0.95)',
          backdropFilter: 'blur(10px)',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
        }}
      >
        <Box sx={{ textAlign: 'center', mb: '30px' }}>
            <Box sx={{
                width: '80px',
                height: '80px',
                background: 'linear-gradient(135deg, var(--primary), var(--primary-dark))',
                borderRadius: '20px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 20px',
                fontSize: '40px',
                color: 'white',
            }}>🐳</Box>
            <Typography variant="h4" sx={{ fontWeight: 700, color: 'var(--dark)' }}>Docker Manager</Typography>
            <Typography sx={{ color: 'var(--text-light)' }}>Secure Container Management</Typography>
        </Box>

        {error && <Typography color="error" sx={{ mb: 2, textAlign: 'center' }}>{error}</Typography>}

        <TextField
          label="Username or Email"
          variant="outlined"
          fullWidth
          required
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          sx={{ mb: '20px' }}
        />
        <TextField
          label="Password"
          type="password"
          variant="outlined"
          fullWidth
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          sx={{ mb: '20px' }}
        />

        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: '25px' }}>
            <FormControlLabel control={<Checkbox />} label="Remember me" />
            <Link href="#" underline="hover">Forgot password?</Link>
        </Box>

        <Button
          type="submit"
          variant="contained"
          fullWidth
          disabled={loading}
          sx={{
            p: '12px',
            borderRadius: '10px',
            fontWeight: 600,
            background: 'linear-gradient(135deg, var(--primary), var(--primary-dark))',
          }}
        >
          {loading ? 'Signing In...' : 'Sign In'}
        </Button>
      </Box>
    </Box>
  );
};

export default LoginPage;
