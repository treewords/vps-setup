import React, { useState, useEffect } from 'react';
import {
  Button, ButtonGroup, IconButton, Tooltip, TextField
} from '@mui/material';
import { PlayArrow, Stop, RestartAlt, Refresh, Pause, Delete, Search, Description, Terminal, Add } from '@mui/icons-material';
import * as api from '../services/api';
import { useDocker } from '../context/DockerContext';
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
  if (!stats.precpu_stats || !stats.cpu_stats) return '0.00';
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
  const { containers, containerStats, loading, refresh } = useDocker();
  const [filteredContainers, setFilteredContainers] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [inspectDialogOpen, setInspectDialogOpen] = useState(false);
  const [logsDialogOpen, setLogsDialogOpen] = useState(false);
  const [terminalDialogOpen, setTerminalDialogOpen] = useState(false);
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState(null);
  const [confirmAction, setConfirmAction] = useState(null);

  // --- Search and Filter Logic ---
  useEffect(() => {
    const lowercasedFilter = searchTerm.toLowerCase();
    const filtered = containers.filter(container => {
      return (
        container.Names[0].substring(1).toLowerCase().includes(lowercasedFilter) ||
        container.Image.toLowerCase().includes(lowercasedFilter)
      );
    });
    setFilteredContainers(filtered);
  }, [searchTerm, containers]);

  // --- Handlers ---
  const handleAction = async (action, containerId) => {
    try {
      await action(containerId);
      refresh(); // Refresh the list after an action
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

  const openDialog = (setter, container) => {
      setSelectedContainer(container);
      setter(true);
  };

  const closeDialogs = () => {
      setSelectedContainer(null);
      setInspectDialogOpen(false);
      setLogsDialogOpen(false);
      setTerminalDialogOpen(false);
  };

  // --- Render ---
  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold text-gray-800">Containers</h2>
        <div className="flex gap-2">
            <TextField
                variant="outlined"
                size="small"
                placeholder="Search containers..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                    startAdornment: <Search className="text-gray-500 mr-2" />,
                }}
            />
          <Button variant="contained" onClick={refresh} disabled={loading.containers} startIcon={<Refresh />}>
            Refresh
          </Button>
          <Button variant="contained" color="success" onClick={() => setCreateDialogOpen(true)} startIcon={<Add />}>
            New
          </Button>
        </div>
      </div>
      <CreateContainerDialog open={createDialogOpen} onClose={() => setCreateDialogOpen(false)} onCreated={refresh} />
      <div className="overflow-x-auto">
        <table className="min-w-full bg-white">
          <thead className="bg-gray-100">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Image</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">CPU %</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Memory</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading.containers ? (
              <tr>
                <td colSpan="6" className="text-center py-4">Loading containers...</td>
              </tr>
            ) : filteredContainers.map((container) => (
              <tr key={container.Id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap font-medium text-gray-900">{container.Names[0].substring(1)}</td>
                <td className="px-6 py-4 whitespace-nowrap text-gray-500">{container.Image}</td>
                <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        container.State === 'running' ? 'bg-green-100 text-green-800' :
                        container.State === 'paused' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-red-100 text-red-800'
                    }`}>
                        {container.State}
                    </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                  {containerStats[container.Id] ? `${calculateCPUPercent(containerStats[container.Id])}%` : '...'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                  {containerStats[container.Id] ? formatMemory(containerStats[container.Id].memory_stats.usage) : '...'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <ButtonGroup variant="text" size="small">
                    <Tooltip title="Start">
                      <span>
                        <IconButton onClick={() => handleAction(api.startContainer, container.Id)} disabled={container.State === 'running' || container.State === 'paused'}>
                          <PlayArrow className="text-green-500" />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Stop">
                      <span>
                        <IconButton onClick={() => handleAction(api.stopContainer, container.Id)} disabled={container.State !== 'running'}>
                          <Stop className="text-red-500" />
                        </IconButton>
                      </span>
                    </Tooltip>
                     <Tooltip title={container.State === 'paused' ? 'Unpause' : 'Pause'}>
                      <span>
                        <IconButton onClick={() => handleAction(container.State === 'paused' ? api.unpauseContainer : api.pauseContainer, container.Id)} disabled={container.State !== 'running' && container.State !== 'paused'}>
                          <Pause className="text-yellow-500" />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Restart">
                      <span>
                        <IconButton onClick={() => handleAction(api.restartContainer, container.Id)} disabled={container.State !== 'running'}>
                          <RestartAlt className="text-blue-500" />
                        </IconButton>
                      </span>
                    </Tooltip>
                    <Tooltip title="Logs">
                        <IconButton onClick={() => openDialog(setLogsDialogOpen, container)}>
                            <Description className="text-gray-500" />
                        </IconButton>
                    </Tooltip>
                    <Tooltip title="Terminal">
                        <IconButton onClick={() => openDialog(setTerminalDialogOpen, container)} disabled={container.State !== 'running'}>
                            <Terminal className="text-gray-500" />
                        </IconButton>
                    </Tooltip>
                    <Tooltip title="Inspect">
                        <IconButton onClick={() => openDialog(setInspectDialogOpen, container)}>
                            <Search className="text-gray-500" />
                        </IconButton>
                    </Tooltip>
                    <Tooltip title="Remove">
                      <span>
                        <IconButton onClick={() => handleRemoveClick(container)} disabled={container.State === 'running'}>
                          <Delete className="text-red-500" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  </ButtonGroup>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selectedContainer && (
        <>
          <ContainerInspectDialog
            open={inspectDialogOpen}
            onClose={closeDialogs}
            containerId={selectedContainer.Id}
          />
          <LogViewerDialog
            open={logsDialogOpen}
            onClose={closeDialogs}
            containerId={selectedContainer.Id}
            containerName={selectedContainer.Names[0].substring(1)}
          />
          <TerminalDialog
            open={terminalDialogOpen}
            onClose={closeDialogs}
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
    </div>
  );
};

export default ContainerList;
