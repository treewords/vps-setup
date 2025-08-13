import React, { useState, useEffect } from 'react';
import { Grid, Paper, Typography, Box } from '@mui/material';
import { useDocker } from '../context/DockerContext';

const StatCard = ({ title, value, icon, colorClass }) => (
    <Paper sx={{
        p: '20px',
        borderRadius: '12px',
        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
        position: 'relative',
        overflow: 'hidden',
        background: 'rgba(255, 255, 255, 0.95)',
        backdropFilter: 'blur(10px)',
        '&::before': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: '4px',
            background: `var(--${colorClass})`,
        }
    }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: '10px' }}>
             <Typography variant="h4" component="div" sx={{ fontWeight: 700, color: 'var(--dark)' }}>{value}</Typography>
             <Box sx={{
                width: '40px',
                height: '40px',
                borderRadius: '8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '20px',
                background: `rgba(var(--${colorClass}-rgb), 0.1)`,
                color: `var(--${colorClass})`,
             }}>
                {icon}
             </Box>
        </Box>
        <Typography sx={{ color: 'var(--text-light)', fontSize: '14px' }}>{title}</Typography>
    </Paper>
);

const ContainerStatsGrid = () => {
  const { containers } = useDocker();
  const [stats, setStats] = useState({ total: 0, running: 0, paused: 0, stopped: 0 });

  useEffect(() => {
    if (containers) {
      const running = containers.filter(c => c.State === 'running').length;
      const paused = containers.filter(c => c.State === 'paused').length;
      const stopped = containers.filter(c => c.State === 'exited').length;
      setStats({ total: containers.length, running, paused, stopped });
    }
  }, [containers]);

  return (
    <Box sx={{ mb: '30px' }}>
      <Grid container spacing={2.5}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard title="Total Containers" value={stats.total} icon="📦" colorClass="primary" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard title="Running" value={stats.running} icon="✅" colorClass="success" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard title="Paused" value={stats.paused} icon="⏸️" colorClass="warning" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard title="Stopped" value={stats.stopped} icon="⏹️" colorClass="danger" />
        </Grid>
      </Grid>
    </Box>
  );
};

export default ContainerStatsGrid;
