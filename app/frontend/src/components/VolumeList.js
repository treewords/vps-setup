import React, { useState } from 'react';
import {
    Button, IconButton, Tooltip
} from '@mui/material';
import { Delete, Refresh, Add } from '@mui/icons-material';
import * as api from '../services/api';
import ConfirmationDialog from './ConfirmationDialog';
import CreateVolumeDialog from './CreateVolumeDialog';
import { useDocker } from '../context/DockerContext';
import { useAuth } from '../context/AuthContext';

const formatDate = (timestamp) => {
    return new Date(timestamp).toLocaleString();
};

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

    // Placeholder for create volume dialog
    const handleCreateVolume = () => {
        console.log("Create volume dialog should open");
    };

    return (
        <div>
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold text-gray-800">Volumes</h2>
                <div>
                    <Button variant="contained" color="primary" onClick={handleCreateVolume} startIcon={<Add />}>
                        Create Volume
                    </Button>
                    <Button variant="contained" onClick={refresh} disabled={loading.volumes} startIcon={<Refresh />} className="ml-4">
                        Refresh
                    </Button>
                </div>
            </div>
            <div className="overflow-x-auto">
                <table className="min-w-full bg-white">
                    <thead className="bg-gray-100">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Driver</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Mountpoint</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created At</th>
                            <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200">
                        {loading.volumes ? (
                            <tr>
                                <td colSpan="5" className="text-center py-4">Loading volumes...</td>
                            </tr>
                        ) : volumes.map((volume) => (
                            <tr key={volume.Name} className="hover:bg-gray-50">
                                <td className="px-6 py-4 whitespace-nowrap">{volume.Name}</td>
                                <td className="px-6 py-4 whitespace-nowrap">{volume.Driver}</td>
                                <td className="px-6 py-4 whitespace-nowrap font-mono text-sm text-gray-500">{volume.Mountpoint}</td>
                                <td className="px-6 py-4 whitespace-nowrap">{formatDate(volume.CreatedAt)}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-right">
                                    {user?.role === 'Admin' && (
                                        <Tooltip title="Remove Volume">
                                            <span>
                                                <IconButton onClick={() => handleRemoveClick(volume)}>
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
