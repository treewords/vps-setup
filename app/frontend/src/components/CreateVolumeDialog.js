import React, { useState } from 'react';
import {
    Button, Dialog, DialogActions, DialogContent, DialogTitle, TextField
} from '@mui/material';

const CreateVolumeDialog = ({ open, onClose, onCreate }) => {
    const [name, setName] = useState('');
    const [driver, setDriver] = useState('local');

    const handleCreate = () => {
        const config = {
            Name: name,
            Driver: driver,
        };
        onCreate(config);
    };

    return (
        <Dialog open={open} onClose={onClose}>
            <DialogTitle>Create a new Volume</DialogTitle>
            <DialogContent>
                <TextField
                    autoFocus
                    margin="dense"
                    label="Volume Name"
                    type="text"
                    fullWidth
                    variant="standard"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                />
                <TextField
                    margin="dense"
                    label="Driver"
                    type="text"
                    fullWidth
                    variant="standard"
                    value={driver}
                    onChange={(e) => setDriver(e.target.value)}
                />
            </DialogContent>
            <DialogActions>
                <Button onClick={onClose}>Cancel</Button>
                <Button onClick={handleCreate}>Create</Button>
            </DialogActions>
        </Dialog>
    );
};

export default CreateVolumeDialog;
