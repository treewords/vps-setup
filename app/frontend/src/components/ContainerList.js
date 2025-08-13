import React, { useState, useEffect, useRef } from 'react';
import {
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper,
  Button, ButtonGroup, Chip, Typography, Box, IconButton, Tooltip, TextField
} from '@mui/material';
import { PlayArrow, Stop, RestartAlt, Refresh, Pause, Delete, Search, Description, Terminal, Add } from '@mui/icons-material';
import * as api from '../services/api';
import ContainerInspectDialog from './ContainerInspectDialog';
import LogViewerDialog from './LogViewerDialog';
import ConfirmationDialog from './ConfirmationDialog';
import TerminalDialog from './TerminalDialog';
import CreateContainerDialog from './CreateContainerDialog';

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
  const [allContainers, setAllContainers] = useState([]);
  const [filteredContainers, setFilteredContainers] = useState([]);
  const [containerStats, setContainerStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [inspectDialogOpen, setInspectDialogOpen] = useState(false);
  const [logsDialogOpen, setLogsDialogOpen] = useState(false);
  const [terminalDialogOpen, setTerminalDialogOpen] = useState(false);
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState(null);
  const [confirmAction, setConfirmAction] = useState(null);
  const ws = useRef(null);

  // --- Data Fetching and WebSocket ---
  const fetchContainers = async () => {
    setLoading(true);
    try {
      const response = await api.getContainers();
      setAllContainers(response.data);
      setFilteredContainers(response.data);
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

  // --- Search and Filter Logic ---
  useEffect(() => {
    const lowercasedFilter = searchTerm.toLowerCase();
    const filtered = allContainers.filter(container => {
      return (
        container.Names[0].substring(1).toLowerCase().includes(lowercasedFilter) ||
        container.Image.toLowerCase().includes(lowercasedFilter)
      );
    });
    setFilteredContainers(filtered);
  }, [searchTerm, allContainers]);


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
        <Typography variant="h5" sx={{ fontWeight: 600, color: 'var(--dark)' }}>
          Containers
        </Typography>
        <Box sx={{ display: 'flex', gap: '10px' }}>
            <TextField
                variant="outlined"
                size="small"
                placeholder="Search containers..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                    startAdornment: <Search sx={{ color: 'var(--text-light)', mr: 1 }} />,
                    sx: { borderRadius: '8px', background: 'white' }
                }}
            />
          <Button variant="contained" onClick={fetchContainers} disabled={loading} startIcon={<Refresh />} sx={{ borderRadius: '8px', textTransform: 'none', background: 'var(--primary)', '&:hover': { background: 'var(--primary-dark)' } }}>
            Refresh
          </Button>
          <Button variant="contained" onClick={() => setCreateDialogOpen(true)} startIcon={<Add />} sx={{ borderRadius: '8px', textTransform: 'none', background: 'var(--success)', '&:hover': { background: '#059669' } }}>
            New Container
          </Button>
        </Box>
      </Box>
      <CreateContainerDialog open={createDialogOpen} onClose={() => setCreateDialogOpen(false)} onCreated={fetchContainers} />
      <TableContainer>
        <Table sx={{
            width: '100%',
            borderCollapse: 'collapse',
            '& th': {
                textAlign: 'left',
                p: '12px',
                background: 'var(--light)',
                color: 'var(--text-light)',
                fontSize: '12px',
                fontWeight: 600,
                textTransform: 'uppercase',
                borderBottom: '2px solid var(--border)',
            },
            '& td': {
                p: '12px',
                borderBottom: '1px solid var(--border)',
                fontSize: '14px',
            },
            '& tr:hover': {
                background: 'rgba(37, 99, 235, 0.05)',
            }
        }}>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Image</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>CPU %</TableCell>
              <TableCell>Memory</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} align="center">
                    <Typography>Loading containers...</Typography>
                </TableCell>
              </TableRow>
            ) : filteredContainers.map((container) => (
              <TableRow key={container.Id}>
                <TableCell sx={{ fontWeight: 600, color: 'var(--dark)' }}>{container.Names[0].substring(1)}</TableCell>
                <TableCell>{container.Image}</TableCell>
                <TableCell>
                    <Box component="span" sx={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '5px',
                        p: '4px 10px',
                        borderRadius: '20px',
                        fontSize: '12px',
                        fontWeight: 500,
                        ...(container.State === 'running' && { background: 'rgba(16, 185, 129, 0.1)', color: 'var(--success)' }),
                        ...(container.State === 'exited' && { background: 'rgba(239, 68, 68, 0.1)', color: 'var(--danger)' }),
                        ...(container.State === 'paused' && { background: 'rgba(245, 158, 11, 0.1)', color: 'var(--warning)' }),
                    }}>
                        <Box component="span" sx={{ width: 8, height: 8, borderRadius: '50%', background: 'currentColor' }} />
                        {container.State}
                    </Box>
                </TableCell>
                <TableCell>
                  {containerStats[container.Id] ? `${calculateCPUPercent(containerStats[container.Id])}%` : '...'}
                </TableCell>
                <TableCell>
                  {containerStats[container.Id] ? formatMemory(containerStats[container.Id].memory_stats.usage) : '...'}
                </TableCell>
                <TableCell align="right">
                  <ButtonGroup variant="outlined" size="small" sx={{ '& .MuiButton-root': { border: 'none' }}}>
                    <Tooltip title="Start">
                      <span>
                        <IconButton onClick={() => handleAction(api.startContainer, container.Id)} disabled={container.State === 'running' || container.State === 'paused'}>
                          <PlayArrow sx={{ color: 'var(--success)'}} />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Stop">
                      <span>
                        <IconButton onClick={() => handleAction(api.stopContainer, container.Id)} disabled={container.State !== 'running'}>
                          <Stop sx={{ color: 'var(--danger)'}} />
                        </IconButton>
                      </span>
                    </Tooltip>
                     <Tooltip title={container.State === 'paused' ? 'Unpause' : 'Pause'}>
                      <span>
                        <IconButton onClick={() => handleAction(container.State === 'paused' ? api.unpauseContainer : api.pauseContainer, container.Id)} disabled={container.State !== 'running' && container.State !== 'paused'}>
                          <Pause sx={{ color: 'var(--warning)'}} />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Restart">
                      <span>
                        <IconButton onClick={() => handleAction(api.restartContainer, container.Id)} disabled={container.State !== 'running'}>
                          <RestartAlt sx={{ color: 'var(--primary)'}} />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Logs">
                        <IconButton onClick={() => handleLogsOpen(container)}>
                            <Description sx={{ color: 'var(--text-light)' }} />
                        </IconButton>
                    </Tooltip>
                    <Tooltip title="Terminal">
                        <IconButton onClick={() => handleTerminalOpen(container)} disabled={container.State !== 'running'}>
                            <Terminal sx={{ color: 'var(--text-light)' }} />
                        </IconButton>
                    </Tooltip>
                    <Tooltip title="Inspect">
                        <IconButton onClick={() => handleInspectOpen(container)}>
                            <Search sx={{ color: 'var(--text-light)' }} />
                        </IconButton>
                    </Tooltip>
                    <Tooltip title="Remove">
                      <span>
                        <IconButton onClick={() => handleRemoveClick(container)} disabled={container.State === 'running'}>
                          <Delete sx={{ color: 'var(--danger)'}} />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </ButtonGroup>
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
