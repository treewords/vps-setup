import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, FormControl, InputLabel, Select, MenuItem } from '@mui/material';

const ConnectContainerDialog = ({ open, onClose, onConnect, containers }) => {
    const [selectedContainer, setSelectedContainer] = useState('');

    const handleConnect = () => {
        if (selectedContainer) {
            onConnect(selectedContainer);
        }
        handleClose();
    };

    const handleClose = () => {
        setSelectedContainer('');
        onClose();
    };

    return (
        <Dialog open={open} onClose={handleClose} fullWidth>
            <DialogTitle>Connect a Container to the Network</DialogTitle>
            <DialogContent>
                <FormControl fullWidth sx={{ mt: 2 }}>
                    <InputLabel id="container-select-label">Container</InputLabel>
                    <Select
                        labelId="container-select-label"
                        id="container-select"
                        value={selectedContainer}
                        label="Container"
                        onChange={(e) => setSelectedContainer(e.target.value)}
                    >
                        {containers.map((container) => (
                            <MenuItem key={container.Id} value={container.Id}>
                                {container.Names[0].substring(1)} ({container.Id.substring(0, 12)})
                            </MenuItem>
                        ))}
                    </Select>
                </FormControl>
            </DialogContent>
            <DialogActions>
                <Button onClick={handleClose}>Cancel</Button>
                <Button onClick={handleConnect} disabled={!selectedContainer}>Connect</Button>
            </DialogActions>
        </Dialog>
    );
};

export default ConnectContainerDialog;
