import React, { useState, useEffect, useRef } from 'react';
import { Grid, Paper, Typography, Box, LinearProgress } from '@mui/material';

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
  const [liveStats, setLiveStats] = useState(null);
  const ws = useRef(null);

  useEffect(() => {
    const isProduction = process.env.NODE_ENV === 'production';
    const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsHost = isProduction ? window.location.host : 'localhost:3001';
    const wsUrl = `${wsProtocol}://${wsHost}/ws`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      ws.current.send(JSON.stringify({ type: 'get_system_stats' }));
    };

    ws.current.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'system_stats_data') {
        setLiveStats(message.stats);
      }
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  const cpuUsage = liveStats?.cpu || 0;
  const memUsage = liveStats ? (liveStats.memory.used / liveStats.memory.total) * 100 : 0;
  const diskUsage = liveStats ? (liveStats.disk.used / liveStats.disk.total) * 100 : 0;

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
