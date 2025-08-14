import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, TextField } from '@mui/material';
import * as api from '../services/api';

const CreateNetworkDialog = ({ open, onClose, onNetworkCreated }) => {
    const [networkName, setNetworkName] = useState('');
    const [driver, setDriver] = useState('bridge');

    const handleCreate = async () => {
        try {
            await api.createNetwork({ Name: networkName, Driver: driver });
            onNetworkCreated();
        } catch (error) {
            console.error("Error creating network", error);
            // You might want to show an error to the user here
        }
        handleClose();
    };

    const handleClose = () => {
        setNetworkName('');
        setDriver('bridge');
        onClose();
    };

    return (
        <Dialog open={open} onClose={handleClose}>
            <DialogTitle>Create a new Network</DialogTitle>
            <DialogContent>
                <DialogContentText>
                    Please enter the details for the new network.
                </DialogContentText>
                <TextField
                    autoFocus
                    margin="dense"
                    id="name"
                    label="Network Name"
                    type="text"
                    fullWidth
                    required
                    variant="standard"
                    value={networkName}
                    onChange={(e) => setNetworkName(e.target.value)}
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
            </DialogContent>
            <DialogActions>
                <Button onClick={handleClose}>Cancel</Button>
                <Button onClick={handleCreate} disabled={!networkName}>Create</Button>
            </DialogActions>
        </Dialog>
    );
};

export default CreateNetworkDialog;
