import React, { useState, useEffect, useRef } from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions, Button, Typography, IconButton
} from '@mui/material';
import { Close } from '@mui/icons-material';
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
        setLogs('');
        setWsStatus('Connecting...');

        try {
          const response = await api.getContainerLogs(containerId);
          setLogs(prev => prev + response.data);
        } catch (error) {
          console.error("Error fetching historical logs", error);
          setLogs(prev => prev + `\n--- ERROR FETCHING HISTORICAL LOGS: ${error.message} ---\n`);
        }

        const isProduction = process.env.NODE_ENV === 'production';
        const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const wsHost = isProduction ? window.location.host : 'localhost:3001';
        const wsUrl = `${wsProtocol}://${wsHost}/ws`;

        ws.current = new WebSocket(wsUrl);

        ws.current.onopen = () => {
          setWsStatus('Connected');
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
    <Dialog
        open={open}
        onClose={onClose}
        fullWidth
        maxWidth="lg"
        PaperProps={{ className: 'h-[90vh] rounded-xl bg-gray-800' }}
    >
      <DialogTitle className="bg-gray-900 text-white flex justify-between items-center p-4">
        <Typography>📋 Logs for {containerName}</Typography>
        <Typography variant="caption">
          WebSocket: {wsStatus}
        </Typography>
        <IconButton onClick={onClose} className="text-white">
            <Close />
        </IconButton>
      </DialogTitle>
      <DialogContent className="p-4 overflow-y-auto font-mono text-gray-300 bg-gray-800">
          <pre className="m-0 whitespace-pre-wrap break-all">
            {logs}
          </pre>
          <div ref={logsEndRef} />
      </DialogContent>
    </Dialog>
  );
};

export default LogViewerDialog;
