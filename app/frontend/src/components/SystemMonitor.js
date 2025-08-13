import React, { useState, useEffect, useRef } from 'react';
import { Grid, Paper, Typography, Box, LinearProgress } from '@mui/material';
import * as api from '../services/api';

const StatCard = ({ title, value, progress, color }) => (
  <Paper sx={{ p: 2 }}>
    <Typography variant="subtitle1" color="text.secondary">{title}</Typography>
    <Typography variant="h5" component="div">{value}</Typography>
    {progress !== undefined && (
      <LinearProgress variant="determinate" value={progress} color={color} sx={{ height: 10, borderRadius: 5, mt: 1 }} />
    )}
  </Paper>
);

const SystemMonitor = () => {
  const [staticInfo, setStaticInfo] = useState(null);
  const [liveStats, setLiveStats] = useState(null);
  const ws = useRef(null);

  useEffect(() => {
    // Fetch static info
    const fetchStaticInfo = async () => {
      try {
        const response = await api.getSystemInfo();
        setStaticInfo(response.data);
      } catch (error) {
        console.error("Error fetching system info", error);
      }
    };
    fetchStaticInfo();

    // WebSocket for live stats
    const isProduction = process.env.NODE_ENV === 'production';
    const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsHost = isProduction ? window.location.host : 'localhost:3001';
    const wsUrl = `${wsProtocol}://${wsHost}/ws`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log('System stats WebSocket connected');
      ws.current.send(JSON.stringify({ type: 'get_system_stats' }));
    };

    ws.current.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'system_stats_data') {
        setLiveStats(message.stats);
      }
    };

    ws.current.onclose = () => {
      console.log('System stats WebSocket disconnected');
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  const getProgressColor = (value) => {
    if (value > 90) return 'error';
    if (value > 70) return 'warning';
    return 'success';
  };

  const formatUptime = (seconds) => {
      const days = Math.floor(seconds / (3600*24));
      seconds  -= days*3600*24;
      const hrs   = Math.floor(seconds / 3600);
      seconds  -= hrs*3600;
      const mnts = Math.floor(seconds / 60);
      return `${days}d ${hrs}h ${mnts}m`;
  }

  const cpuUsage = liveStats?.cpu || 0;
  const memUsage = liveStats ? (liveStats.memory.used / liveStats.memory.total) * 100 : 0;
  const diskUsage = liveStats ? (liveStats.disk.used / liveStats.disk.total) * 100 : 0;

  return (
    <Box sx={{ mb: 4 }}>
        <Typography variant="h5" sx={{ mb: 2 }}>System Overview</Typography>
        <Grid container spacing={3}>
            <Grid item xs={12} sm={6} md={3}>
                <StatCard title="CPU Usage" value={`${cpuUsage.toFixed(1)}%`} progress={cpuUsage} color={getProgressColor(cpuUsage)} />
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
                <StatCard title="Memory Usage" value={`${(memUsage).toFixed(1)}%`} progress={memUsage} color={getProgressColor(memUsage)} />
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
                <StatCard title="Disk Usage" value={`${(diskUsage).toFixed(1)}%`} progress={diskUsage} color={getProgressColor(diskUsage)} />
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
                 <Paper sx={{ p: 2, height: '100%' }}>
                    <Typography variant="subtitle1" color="text.secondary">System Info</Typography>
                    <Typography variant="body2">
                        {staticInfo ? `${staticInfo.os} | Docker v${staticInfo.dockerVersion}` : 'Loading...'}
                    </Typography>
                    <Typography variant="body2">
                        Uptime: {staticInfo ? formatUptime(staticInfo.uptime) : '...'}
                    </Typography>
                </Paper>
            </Grid>
        </Grid>
    </Box>
  );
};

export default SystemMonitor;
