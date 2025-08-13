import React, { useState, useEffect } from 'react';
import {
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper,
  Button, ButtonGroup, Chip, Typography, Box, IconButton, Tooltip
} from '@mui/material';
import { PlayArrow, Stop, RestartAlt, Refresh } from '@mui/icons-material';
import * as api from '../services/api';
import ContainerInspectDialog from './ContainerInspectDialog';
import LogViewerDialog from './LogViewerDialog';

const ContainerList = () => {
  const [containers, setContainers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [inspectDialogOpen, setInspectDialogOpen] = useState(false);
  const [logsDialogOpen, setLogsDialogOpen] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState(null);

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
    fetchContainers();
  }, []);

  const handleAction = async (action, containerId) => {
    try {
      await action(containerId);
      fetchContainers(); // Refresh the list after an action
    } catch (error) {
      console.error(`Error performing action on container ${containerId}`, error);
      // You might want to show a notification to the user here
    }
  };

  const getStatusChip = (state) => {
    if (state === 'running') {
      return <Chip label={state} color="success" size="small" />;
    }
    if (state === 'exited') {
      return <Chip label={state} color="error" size="small" />;
    }
    return <Chip label={state} color="default" size="small" />;
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
              <TableCell>Status</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} align="center">Loading...</TableCell>
              </TableRow>
            ) : containers.map((container) => (
              <TableRow key={container.Id}>
                <TableCell>{container.Names[0].substring(1)}</TableCell>
                <TableCell>{container.Image}</TableCell>
                <TableCell>{getStatusChip(container.State)}</TableCell>
                <TableCell>{container.Status}</TableCell>
                <TableCell align="right">
                  <ButtonGroup variant="contained" size="small">
                    <Tooltip title="Start">
                      <span>
                        <IconButton
                          color="success"
                          onClick={() => handleAction(api.startContainer, container.Id)}
                          disabled={container.State === 'running'}
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
                    <Tooltip title="Restart">
                      <span>
                        <IconButton
                          color="warning"
                          onClick={() => handleAction(api.restartContainer, container.Id)}
                          disabled={container.State !== 'running'}
                        >
                          <RestartAlt />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </ButtonGroup>
                  <Button sx={{ ml: 1 }} size="small" variant="outlined" onClick={() => handleInspectOpen(container)}>Inspect</Button>
                  <Button sx={{ ml: 1 }} size="small" variant="outlined" onClick={() => handleLogsOpen(container)}>Logs</Button>
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
        </>
      )}
    </Box>
  );
};

export default ContainerList;
