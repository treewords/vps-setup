import React from 'react';
import { Box, Typography, Button, IconButton } from '@mui/material';
import { Logout } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

const formatUptime = (seconds) => {
    if (!seconds) return '--';
    const days = Math.floor(seconds / (3600 * 24));
    seconds -= days * 3600 * 24;
    const hrs = Math.floor(seconds / 3600);
    seconds -= hrs * 3600;
    const mnts = Math.floor(seconds / 60);
    return `${days}d ${hrs}h ${mnts}m`;
};

const Header = ({ staticInfo }) => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('dockerManagerToken');
    navigate('/login');
  };

  return (
    <Box sx={{
      background: 'rgba(255, 255, 255, 0.95)',
      backdropFilter: 'blur(10px)',
      borderRadius: '16px',
      p: '20px 30px',
      mb: '30px',
      boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
    }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
        <Box sx={{
          width: '48px',
          height: '48px',
          background: 'linear-gradient(135deg, var(--primary), var(--primary-dark))',
          borderRadius: '12px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'white',
          fontSize: '24px',
        }}>
          🐳
        </Box>
        <Typography variant="h4" component="h1" sx={{ color: 'var(--dark)', fontWeight: 600 }}>
          Docker Manager
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
        <Box sx={{ textAlign: 'center' }}>
          <Typography sx={{ fontSize: '12px', color: 'var(--text-light)', textTransform: 'uppercase' }}>Server</Typography>
          <Typography sx={{ fontSize: '18px', fontWeight: 600, color: 'var(--dark)' }}>{staticInfo?.os || '...'}</Typography>
        </Box>
        <Box sx={{ textAlign: 'center' }}>
          <Typography sx={{ fontSize: '12px', color: 'var(--text-light)', textTransform: 'uppercase' }}>Uptime</Typography>
          <Typography sx={{ fontSize: '18px', fontWeight: 600, color: 'var(--dark)' }}>{formatUptime(staticInfo?.uptime)}</Typography>
        </Box>
        <Box sx={{ textAlign: 'center' }}>
          <Typography sx={{ fontSize: '12px', color: 'var(--text-light)', textTransform: 'uppercase' }}>Docker</Typography>
          <Typography sx={{ fontSize: '18px', fontWeight: 600, color: 'var(--dark)' }}>v{staticInfo?.dockerVersion || '...'}</Typography>
        </Box>
        <IconButton onClick={handleLogout} sx={{ color: 'var(--text-light)' }} title="Logout">
            <Logout />
        </IconButton>
      </Box>
    </Box>
  );
};

export default Header;
