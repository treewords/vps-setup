import React from 'react';
import { Grid, Paper, Typography, Box } from '@mui/material';
import { useDocker } from '../context/DockerContext';

const ResourceCard = ({ title, value, progress, icon }) => {

    const getProgressColor = (value) => {
        if (value > 80) return 'linear-gradient(90deg, #ef4444, #dc2626)';
        if (value > 60) return 'linear-gradient(90deg, #f59e0b, #d97706)';
        return 'linear-gradient(90deg, #10b981, #059669)';
    };

    return (
        <Paper sx={{
            p: '20px',
            borderRadius: '12px',
            boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
            background: 'rgba(255, 255, 255, 0.95)',
            backdropFilter: 'blur(10px)',
        }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: '15px' }}>
                <Typography sx={{ fontWeight: 600, color: 'var(--dark)' }}>{icon} {title}</Typography>
                <Typography sx={{ fontSize: '24px', fontWeight: 700, color: 'var(--primary)' }}>{value}</Typography>
            </Box>
            <Box sx={{ width: '100%', height: '8px', background: 'var(--light)', borderRadius: '4px', overflow: 'hidden' }}>
                <Box sx={{
                    height: '100%',
                    width: `${progress}%`,
                    background: getProgressColor(progress),
                    borderRadius: '4px',
                    transition: 'width 0.5s ease',
                }} />
            </Box>
        </Paper>
    );
};


const SystemMonitor = () => {
  const { systemStats } = useDocker();

  const cpuUsage = systemStats?.cpu || 0;
  const memUsage = systemStats ? (systemStats.memory.used / systemStats.memory.total) * 100 : 0;
  const diskUsage = systemStats ? (systemStats.disk.used / systemStats.disk.total) * 100 : 0;

  return (
    <Box sx={{ mt: '30px' }}>
        <Grid container spacing={2.5}>
            <Grid item xs={12} md={4}>
                <ResourceCard title="CPU Usage" icon="🖥️" value={`${cpuUsage.toFixed(1)}%`} progress={cpuUsage} />
            </Grid>
            <Grid item xs={12} md={4}>
                <ResourceCard title="Memory Usage" icon="💾" value={`${memUsage.toFixed(1)}%`} progress={memUsage} />
            </Grid>
            <Grid item xs={12} md={4}>
                <ResourceCard title="Disk Usage" icon="💿" value={`${diskUsage.toFixed(1)}%`} progress={diskUsage} />
            </Grid>
        </Grid>
    </Box>
  );
};

export default SystemMonitor;
