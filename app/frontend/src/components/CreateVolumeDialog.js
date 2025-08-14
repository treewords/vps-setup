import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, TextField } from '@mui/material';
import * as api from '../services/api';

// Helper to parse key-value pairs from a textarea
const parseKeyValuePairs = (text) => {
    if (!text) return {};
    return text.split('\n').reduce((acc, line) => {
        const [key, ...valueParts] = line.split('=');
        const value = valueParts.join('=');
        if (key && value) {
            acc[key.trim()] = value.trim();
        }
        return acc;
    }, {});
};

const CreateVolumeDialog = ({ open, onClose, onVolumeCreated }) => {
    const [name, setName] = useState('');
    const [driver, setDriver] = useState('local');
    const [driverOpts, setDriverOpts] = useState('');
    const [labels, setLabels] = useState('');

    const handleCreate = async () => {
        const payload = {
            Name: name,
            Driver: driver,
            DriverOpts: parseKeyValuePairs(driverOpts),
            Labels: parseKeyValuePairs(labels),
        };

        try {
            await api.createVolume(payload);
            onVolumeCreated();
        } catch (error) {
            console.error("Error creating volume", error);
            // Optionally, show an error message to the user
        }
        handleClose();
    };

    const handleClose = () => {
        setName('');
        setDriver('local');
        setDriverOpts('');
        setLabels('');
        onClose();
    };

    return (
        <Dialog open={open} onClose={handleClose}>
            <DialogTitle>Create a new Volume</DialogTitle>
            <DialogContent>
                <DialogContentText>
                    Please enter the details for the new volume.
                </DialogContentText>
                <TextField
                    autoFocus
                    margin="dense"
                    id="name"
                    label="Volume Name"
                    type="text"
                    fullWidth
                    required
                    variant="standard"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                />
                <TextField
                    margin="dense"
                    id="driver"
                    label="Driver"
                    type="text"
                    fullWidth
                    variant="standard"
                    value={driver}
                    onChange={(e) => setDriver(e.target.value)}
                />
                <TextField
                    margin="dense"
                    id="driveropts"
                    label="Driver Options (key=value, one per line)"
                    type="text"
                    fullWidth
                    multiline
                    rows={3}
                    variant="standard"
                    value={driverOpts}
                    onChange={(e) => setDriverOpts(e.target.value)}
                />
                <TextField
                    margin="dense"
                    id="labels"
                    label="Labels (key=value, one per line)"
                    type="text"
                    fullWidth
                    multiline
                    rows={3}
                    variant="standard"
                    value={labels}
                    onChange={(e) => setLabels(e.target.value)}
                />
            </DialogContent>
            <DialogActions>
                <Button onClick={handleClose}>Cancel</Button>
                <Button onClick={handleCreate} disabled={!name}>Create</Button>
            </DialogActions>
        </Dialog>
    );
};

export default CreateVolumeDialog;
