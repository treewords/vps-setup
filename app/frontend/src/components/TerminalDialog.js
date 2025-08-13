import React, { useEffect, useRef } from 'react';
import { Dialog, DialogTitle, DialogContent, Typography, IconButton } from '@mui/material';
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
      if (!xterm.current) {
        xterm.current = new Terminal({
          cursorBlink: true,
          theme: {
            background: '#111827', // dark-gray-900
            foreground: '#d1d5db', // gray-300
          },
        });
        fitAddon.current = new FitAddon();
        xterm.current.loadAddon(fitAddon.current);
        xterm.current.open(terminalRef.current);
      }

      fitAddon.current.fit();

      const isProduction = process.env.NODE_ENV === 'production';
      const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const wsHost = isProduction ? window.location.host : 'localhost:3001';
      const wsUrl = `${wsProtocol}://${wsHost}/ws/terminal/${containerId}`;

      const socket = new WebSocket(wsUrl);
      const attachAddon = new AttachAddon(socket);
      xterm.current.loadAddon(attachAddon);

      const resizeObserver = new ResizeObserver(() => {
        fitAddon.current.fit();
      });
      resizeObserver.observe(terminalRef.current);

      return () => {
        socket.close();
        resizeObserver.disconnect();
      };
    }
  }, [open, containerId]);

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="xl" PaperProps={{ className: 'h-[90vh] rounded-xl bg-gray-900' }}>
      <DialogTitle className="bg-gray-800 text-white flex justify-between items-center p-4">
        <Typography>📟 Terminal for {containerName}</Typography>
         <IconButton onClick={onClose} className="text-white">
            <Close />
        </IconButton>
      </DialogTitle>
      <DialogContent className="p-0 h-full overflow-hidden">
        <div ref={terminalRef} className="h-full w-full" />
      </DialogContent>
    </Dialog>
  );
};

export default TerminalDialog;
