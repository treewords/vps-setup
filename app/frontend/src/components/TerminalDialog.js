import React, { useEffect, useRef } from 'react';
import { Dialog, DialogTitle, DialogContent, Box, Typography, IconButton } from '@mui/material';
import { Close } from '@mui/icons-material';
import { Terminal } from 'xterm';
import { AttachAddon } from 'xterm-addon-attach';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';

const TerminalDialog = ({ open, onClose, containerId, containerName }) => {
  const terminalRef = useRef(null);
  const xterm = useRef(null);
  const fitAddon = useRef(null);

  useEffect(() => {
    if (open && terminalRef.current) {
      // Create a new terminal instance if it doesn't exist
      if (!xterm.current) {
        xterm.current = new Terminal({
          cursorBlink: true,
          theme: {
            background: '#1e1e1e',
            foreground: '#d4d4d4',
          },
        });
        fitAddon.current = new FitAddon();
        xterm.current.loadAddon(fitAddon.current);
        xterm.current.open(terminalRef.current);
      }

      // Fit the terminal to the container
      fitAddon.current.fit();

      // Set up WebSocket connection
      const isProduction = process.env.NODE_ENV === 'production';
      const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const wsHost = isProduction ? window.location.host : 'localhost:3001';
      const wsUrl = `${wsProtocol}://${wsHost}/ws/terminal/${containerId}`;

      const socket = new WebSocket(wsUrl);

      socket.onclose = () => {
          if (xterm.current) {
              xterm.current.writeln('');
              xterm.current.writeln('--- CONNECTION CLOSED ---');
          }
      };

      const attachAddon = new AttachAddon(socket);
      xterm.current.loadAddon(attachAddon);

      // Handle resize
      const resizeObserver = new ResizeObserver(() => {
        fitAddon.current.fit();
      });
      resizeObserver.observe(terminalRef.current);

      // Cleanup on close
      return () => {
        socket.close();
        // We don't destroy the xterm instance, just detach the socket
        // so if the dialog is re-opened, it feels faster.
        // If you want to fully clear it, you can call xterm.current.dispose()
        resizeObserver.disconnect();
      };
    }
  }, [open, containerId]);

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="xl" PaperProps={{ sx: { height: '90vh', borderRadius: '12px', background: 'var(--darker)' } }}>
      <DialogTitle sx={{
          background: 'var(--dark)',
          color: 'white',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          p: '15px 20px',
        }}>
        <Typography>📟 Terminal for {containerName}</Typography>
         <IconButton onClick={onClose} sx={{ color: 'white' }}>
            <Close />
        </IconButton>
      </DialogTitle>
      <DialogContent sx={{ p: 0, height: '100%', overflow: 'hidden' }}>
        <Box ref={terminalRef} sx={{ height: '100%', width: '100%' }} />
      </DialogContent>
    </Dialog>
  );
};

export default TerminalDialog;
