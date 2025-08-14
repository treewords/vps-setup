import React, { useState } from 'react';
import {
  Button, Chip, IconButton, Tooltip
} from '@mui/material';
import { Delete, Refresh, SaveAlt } from '@mui/icons-material';
import * as api from '../services/api';
import ConfirmationDialog from './ConfirmationDialog';
import { useDocker } from '../context/DockerContext';
import { useAuth } from '../context/AuthContext';

const VolumeList = () => {
  const { volumes, loading, refresh } = useDocker();
  const { user } = useAuth();
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [selectedVolume, setSelectedVolume] = useState(null);
  const [confirmAction, setConfirmAction] = useState(null);

  const handleRemoveClick = (volume) => {
    setSelectedVolume(volume);
    setConfirmAction(() => () => handleRemoveVolume(volume.Name));
    setConfirmDialogOpen(true);
  };

  const handleConfirmClose = () => {
    setConfirmDialogOpen(false);
    setSelectedVolume(null);
    setConfirmAction(null);
  };

  const handleRemoveVolume = async (name) => {
    try {
      await api.removeVolume(name);
      refresh();
    } catch (error) {
      console.error("Error removing volume", error);
    }
  };

  const handleBackupVolume = async (name) => {
    try {
      const response = await api.backupVolume(name);
      alert(response.data.message);
    } catch (error) {
        console.error("Error backing up volume", error);
        alert(`Error backing up volume: ${error.response?.data?.message || error.message}`);
    }
    };

  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold text-gray-800">Volumes</h2>
        <Button variant="contained" onClick={refresh} disabled={loading.volumes} startIcon={<Refresh />}>
          Refresh
        </Button>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full bg-white">
          <thead className="bg-gray-100">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Driver</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Mountpoint</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading.volumes ? (
              <tr>
                <td colSpan="4" className="text-center py-4">Loading volumes...</td>
              </tr>
            ) : volumes.map((volume) => (
              <tr key={volume.Name} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap">{volume.Name}</td>
                <td className="px-6 py-4 whitespace-nowrap">{volume.Driver}</td>
                <td className="px-6 py-4 whitespace-nowrap">{volume.Mountpoint}</td>
                <td className="px-6 py-4 whitespace-nowrap text-right">
                  {user?.role === 'Admin' && (
                    <>
                        <Tooltip title="Backup Volume">
                            <span>
                                <IconButton onClick={() => handleBackupVolume(volume.Name)}>
                                    <SaveAlt />
                                </IconButton>
                            </span>
                        </Tooltip>
                        <Tooltip title="Remove Volume">
                            <span>
                                <IconButton onClick={() => handleRemoveClick(volume)}>
                                    <Delete className="text-red-500" />
                                </IconButton>
                            </span>
                        </Tooltip>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selectedVolume && (
        <ConfirmationDialog
          open={confirmDialogOpen}
          onClose={handleConfirmClose}
          onConfirm={() => {
            if (confirmAction) {
              confirmAction();
            }
            handleConfirmClose();
          }}
          title="Remove Volume"
          description={`Are you sure you want to remove this volume? ${selectedVolume.Name}`}
        />
      )}
    </div>
  );
};

export default VolumeList;
