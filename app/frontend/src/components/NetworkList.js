import React, { useState } from 'react';
import {
  Button, Chip, IconButton, Tooltip
} from '@mui/material';
import { Delete, Refresh } from '@mui/icons-material';
import * as api from '../services/api';
import ConfirmationDialog from './ConfirmationDialog';
import CreateNetworkDialog from './CreateNetworkDialog';
import NetworkInspectDialog from './NetworkInspectDialog';
import { useDocker } from '../context/DockerContext';
import { useAuth } from '../context/AuthContext';

const NetworkList = () => {
  const { networks, loading, refresh } = useDocker();
  const { user } = useAuth();
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [inspectDialogOpen, setInspectDialogOpen] = useState(false);
  const [selectedNetwork, setSelectedNetwork] = useState(null);
  const [selectedNetworkId, setSelectedNetworkId] = useState(null);
  const [confirmAction, setConfirmAction] = useState(null);

  const handleRemoveClick = (network) => {
    setSelectedNetwork(network);
    setConfirmAction(() => () => handleRemoveNetwork(network.Id));
    setConfirmDialogOpen(true);
  };

  const handleConfirmClose = () => {
    setConfirmDialogOpen(false);
    setSelectedNetwork(null);
    setConfirmAction(null);
  };

  const handleRemoveNetwork = async (id) => {
    try {
      await api.removeNetwork(id);
      refresh();
    } catch (error) {
      console.error("Error removing network", error);
    }
  };

  const handleInspectClick = (networkId) => {
    setSelectedNetworkId(networkId);
    setInspectDialogOpen(true);
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold text-gray-800">Networks</h2>
        <div>
            <Button variant="contained" onClick={() => setCreateDialogOpen(true)} sx={{ mr: 1 }}>
                Create Network
            </Button>
            <Button variant="contained" onClick={refresh} disabled={loading.networks} startIcon={<Refresh />}>
                Refresh
            </Button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full bg-white">
          <thead className="bg-gray-100">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Driver</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scope</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading.networks ? (
              <tr>
                <td colSpan="5" className="text-center py-4">Loading networks...</td>
              </tr>
            ) : networks.map((network) => (
              <tr key={network.Id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap">
                    <span className="cursor-pointer text-blue-600 hover:underline" onClick={() => handleInspectClick(network.Id)}>
                        {network.Name}
                    </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap font-mono text-sm text-gray-500">{network.Id.substring(0, 12)}</td>
                <td className="px-6 py-4 whitespace-nowrap">{network.Driver}</td>
                <td className="px-6 py-4 whitespace-nowrap">{network.Scope}</td>
                <td className="px-6 py-4 whitespace-nowrap text-right">
                  {user?.role === 'Admin' && (
                    <Tooltip title="Remove Network">
                      <span>
                        <IconButton onClick={() => handleRemoveClick(network)}>
                          <Delete className="text-red-500" />
                        </IconButton>
                      </span>
                    </Tooltip>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selectedNetwork && (
        <ConfirmationDialog
          open={confirmDialogOpen}
          onClose={handleConfirmClose}
          onConfirm={() => {
            if (confirmAction) {
              confirmAction();
            }
            handleConfirmClose();
          }}
          title="Remove Network"
          description={`Are you sure you want to remove this network? ${selectedNetwork.Name}`}
        />
      )}
      <CreateNetworkDialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        onNetworkCreated={() => {
            setCreateDialogOpen(false);
            refresh();
        }}
      />
        <NetworkInspectDialog
            open={inspectDialogOpen}
            onClose={() => setInspectDialogOpen(false)}
            networkId={selectedNetworkId}
        />
    </div>
  );
};

export default NetworkList;
