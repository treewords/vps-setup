import React, { useState, useEffect, useRef } from 'react';
import {
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper,
  Button, ButtonGroup, Chip, Typography, Box, IconButton, Tooltip
} from '@mui/material';
import { PlayArrow, Stop, RestartAlt, Refresh, Pause, Delete } from '@mui/icons-material';
import * as api from '../services/api';
import ContainerInspectDialog from './ContainerInspectDialog';
import LogViewerDialog from './LogViewerDialog';
import ConfirmationDialog from './ConfirmationDialog';
import TerminalDialog from './TerminalDialog';

// --- Helper Functions ---
const formatMemory = (bytes) => {
  if (bytes === 0) return '0 B';
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${['B', 'KiB', 'MiB', 'GiB'][i]}`;
};

const calculateCPUPercent = (stats) => {
  const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
  const systemCpuDelta = stats.cpu_stats.system_cpu_usage - stats.precpu_stats.system_cpu_usage;
  const numberCpus = stats.cpu_stats.online_cpus || stats.cpu_stats.cpu_usage.percpu_usage.length;

  if (systemCpuDelta > 0.0 && cpuDelta > 0.0) {
    return ((cpuDelta / systemCpuDelta) * numberCpus * 100.0).toFixed(2);
  }
  return '0.00';
};


const ContainerList = () => {
  // --- State ---
  const [containers, setContainers] = useState([]);
  const [containerStats, setContainerStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [inspectDialogOpen, setInspectDialogOpen] = useState(false);
  const [logsDialogOpen, setLogsDialogOpen] = useState(false);
  const [terminalDialogOpen, setTerminalDialogOpen] = useState(false);
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState(null);
  const [confirmAction, setConfirmAction] = useState(null);
  const ws = useRef(null);

  // --- Data Fetching and WebSocket ---
  const fetchContainers = async () => {
    setLoading(true);
    try {
      const response = await api.getContainers();
      setContainers(response.data);
    } catch (error) {
      console.error("Error fetching containers", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchContainers(); // Initial fetch

    // WebSocket for stats
    const isProduction = process.env.NODE_ENV === 'production';
    const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsHost = isProduction ? window.location.host : 'localhost:3001';
    const wsUrl = `${wsProtocol}://${wsHost}/ws`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log('Stats WebSocket connected');
      ws.current.send(JSON.stringify({ type: 'stats' }));
    };

    ws.current.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'stats_data') {
        setContainerStats(prevStats => ({
          ...prevStats,
          [message.id]: message.stats,
        }));
      }
    };

    ws.current.onclose = () => {
      console.log('Stats WebSocket disconnected');
    };

    // Cleanup on unmount
    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  // --- Handlers ---
  const handleAction = async (action, containerId) => {
    try {
      await action(containerId);
      fetchContainers(); // Refresh the list after an action
    } catch (error) {
      console.error(`Error performing action on container ${containerId}`, error);
    }
  };

  const handleRemoveClick = (container) => {
    setSelectedContainer(container);
    setConfirmAction(() => () => handleAction(api.removeContainer, container.Id));
    setConfirmDialogOpen(true);
  };

  const handleConfirmClose = () => {
    setConfirmDialogOpen(false);
    setSelectedContainer(null);
    setConfirmAction(null);
  };

  const handleInspectOpen = (container) => {
    setSelectedContainer(container);
    setInspectDialogOpen(true);
  };

  const handleInspectClose = () => {
    setInspectDialogOpen(false);
    setSelectedContainer(null);
  };

  const handleLogsOpen = (container) => {
    setSelectedContainer(container);
    setLogsDialogOpen(true);
  };

  const handleLogsClose = () => {
    setLogsDialogOpen(false);
    setSelectedContainer(null);
  };

  const handleTerminalOpen = (container) => {
    setSelectedContainer(container);
    setTerminalDialogOpen(true);
  };

  const handleTerminalClose = () => {
    setTerminalDialogOpen(false);
    setSelectedContainer(null);
  };

  // --- Render ---
  const getStatusChip = (state) => {
    switch (state) {
      case 'running':
        return <Chip label={state} color="success" size="small" />;
      case 'exited':
        return <Chip label={state} color="error" size="small" />;
      case 'paused':
        return <Chip label={state} color="warning" size="small" />;
      default:
        return <Chip label={state} color="default" size="small" />;
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h5">Container Status</Typography>
        <Tooltip title="Refresh List">
          <IconButton onClick={fetchContainers} disabled={loading}>
            <Refresh />
          </IconButton>
        </Tooltip>
      </Box>
      <TableContainer component={Paper}>
        <Table sx={{ minWidth: 650 }} aria-label="simple table">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Image</TableCell>
              <TableCell>State</TableCell>
              <TableCell>CPU %</TableCell>
              <TableCell>Memory</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} align="center">Loading...</TableCell>
              </TableRow>
            ) : containers.map((container) => (
              <TableRow key={container.Id} hover>
                <TableCell>{container.Names[0].substring(1)}</TableCell>
                <TableCell>{container.Image}</TableCell>
                <TableCell>{getStatusChip(container.State)}</TableCell>
                <TableCell>
                  {containerStats[container.Id] ? `${calculateCPUPercent(containerStats[container.Id])}%` : '...'}
                </TableCell>
                <TableCell>
                  {containerStats[container.Id] ? formatMemory(containerStats[container.Id].memory_stats.usage) : '...'}
                </TableCell>
                <TableCell align="right">
                  <ButtonGroup variant="outlined" size="small">
                    <Tooltip title="Start">
                      <span>
                        <IconButton
                          color="success"
                          onClick={() => handleAction(api.startContainer, container.Id)}
                          disabled={container.State === 'running' || container.State === 'paused'}
                        >
                          <PlayArrow />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Stop">
                      <span>
                        <IconButton
                          color="error"
                          onClick={() => handleAction(api.stopContainer, container.Id)}
                          disabled={container.State !== 'running'}
                        >
                          <Stop />
                        </IconButton>
                      </span>
                    </Tooltip>
                     <Tooltip title={container.State === 'paused' ? 'Unpause' : 'Pause'}>
                      <span>
                        <IconButton
                          color="warning"
                          onClick={() => handleAction(container.State === 'paused' ? api.unpauseContainer : api.pauseContainer, container.Id)}
                          disabled={container.State !== 'running' && container.State !== 'paused'}
                        >
                          <Pause />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Restart">
                      <span>
                        <IconButton
                          color="info"
                          onClick={() => handleAction(api.restartContainer, container.Id)}
                          disabled={container.State !== 'running'}
                        >
                          <RestartAlt />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Remove">
                      <span>
                        <IconButton
                          color="error"
                          onClick={() => handleRemoveClick(container)}
                          disabled={container.State === 'running'}
                        >
                          <Delete />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </ButtonGroup>
                  <Button sx={{ ml: 1 }} size="small" variant="text" onClick={() => handleInspectOpen(container)}>Inspect</Button>
                  <Button sx={{ ml: 1 }} size="small" variant="text" onClick={() => handleLogsOpen(container)}>Logs</Button>
                  <Button sx={{ ml: 1 }} size="small" variant="text" onClick={() => handleTerminalOpen(container)} disabled={container.State !== 'running'}>Terminal</Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      {selectedContainer && (
        <>
          <ContainerInspectDialog
            open={inspectDialogOpen}
            onClose={handleInspectClose}
            containerId={selectedContainer.Id}
          />
          <LogViewerDialog
            open={logsDialogOpen}
            onClose={handleLogsClose}
            containerId={selectedContainer.Id}
            containerName={selectedContainer.Names[0].substring(1)}
          />
          <TerminalDialog
            open={terminalDialogOpen}
            onClose={handleTerminalClose}
            containerId={selectedContainer.Id}
            containerName={selectedContainer.Names[0].substring(1)}
          />
          <ConfirmationDialog
            open={confirmDialogOpen}
            onClose={handleConfirmClose}
            onConfirm={() => {
              if (confirmAction) {
                confirmAction();
              }
              handleConfirmClose();
            }}
            title="Confirm Action"
            description={`Are you sure you want to perform this action on container ${selectedContainer?.Names[0].substring(1)}? This can't be undone.`}
          />
        </>
      )}
    </Box>
  );
};

export default ContainerList;
