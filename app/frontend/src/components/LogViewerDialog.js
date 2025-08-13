import React, { useState, useEffect, useRef } from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions, Button,
  Box, Typography, Paper
} from '@mui/material';
import * as api from '../services/api';

const LogViewerDialog = ({ open, onClose, containerId, containerName }) => {
  const [logs, setLogs] = useState('');
  const [wsStatus, setWsStatus] = useState('Disconnected');
  const ws = useRef(null);
  const logsEndRef = useRef(null);

  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    const fetchAndStreamLogs = async () => {
      if (open && containerId) {
        // Reset state
        setLogs('');
        setWsStatus('Connecting...');

        // 1. Fetch historical logs
        try {
          const response = await api.getContainerLogs(containerId);
          setLogs(prev => prev + response.data);
        } catch (error) {
          console.error("Error fetching historical logs", error);
          setLogs(prev => prev + `\n--- ERROR FETCHING HISTORICAL LOGS: ${error.message} ---\n`);
        }

        // 2. Connect WebSocket for real-time logs
        const isProduction = process.env.NODE_ENV === 'production';
        const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const wsHost = isProduction ? window.location.host : 'localhost:3001';
        const wsUrl = `${wsProtocol}://${wsHost}/ws`;

        ws.current = new WebSocket(wsUrl);

        ws.current.onopen = () => {
          setWsStatus('Connected');
          // Send the container ID to the backend to start the log stream
          ws.current.send(JSON.stringify({ type: 'log', containerId }));
        };

        ws.current.onmessage = (event) => {
          const message = JSON.parse(event.data);
          if (message.type === 'log_data' && message.log) {
            setLogs(prev => prev + message.log);
          } else if (message.type === 'log_error' || message.type === 'error') {
            console.error("WebSocket error:", message.error);
            setLogs(prev => prev + `\n--- WEBSOCKET ERROR: ${message.details || message.error} ---\n`);
          }
        };

        ws.current.onclose = () => {
          setWsStatus('Disconnected');
        };

        ws.current.onerror = (error) => {
          console.error("WebSocket error:", error);
          setWsStatus('Error');
        };
      }
    };

    fetchAndStreamLogs();

    // Cleanup function
    return () => {
      if (ws.current) {
        ws.current.close();
        ws.current = null;
      }
    };
  }, [open, containerId]);

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>
        Logs for {containerName}
        <Typography variant="caption" sx={{ ml: 2 }}>
          WebSocket: {wsStatus}
        </Typography>
      </DialogTitle>
      <DialogContent>
        <Paper variant="outlined" sx={{ backgroundColor: '#1e1e1e', color: '#d4d4d4', p: 2, height: '60vh', overflowY: 'auto', fontFamily: 'monospace' }}>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {logs}
          </pre>
          <div ref={logsEndRef} />
        </Paper>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default LogViewerDialog;
