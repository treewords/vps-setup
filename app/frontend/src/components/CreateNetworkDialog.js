import React, { useState } from 'react';
import {
    Button, Dialog, DialogActions, DialogContent, DialogTitle, TextField,
    FormControl, InputLabel, Select, MenuItem
} from '@mui/material';

const CreateNetworkDialog = ({ open, onClose, onCreate }) => {
    const [name, setName] = useState('');
    const [driver, setDriver] = useState('bridge');
    const [checkDuplicate, setCheckDuplicate] = useState(true);

    const handleCreate = () => {
        const config = {
            Name: name,
            Driver: driver,
            CheckDuplicate: checkDuplicate,
        };
        onCreate(config);
    };

    return (
        <Dialog open={open} onClose={onClose}>
            <DialogTitle>Create a new Network</DialogTitle>
            <DialogContent>
                <TextField
                    autoFocus
                    margin="dense"
                    label="Network Name"
                    type="text"
                    fullWidth
                    variant="standard"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                />
                <FormControl fullWidth margin="dense" variant="standard">
                    <InputLabel>Driver</InputLabel>
                    <Select
                        value={driver}
                        onChange={(e) => setDriver(e.target.value)}
                    >
                        <MenuItem value="bridge">bridge</MenuItem>
                        <MenuItem value="overlay">overlay</MenuItem>
                        <MenuItem value="macvlan">macvlan</MenuItem>
                    </Select>
                </FormControl>
            </DialogContent>
            <DialogActions>
                <Button onClick={onClose}>Cancel</Button>
                <Button onClick={handleCreate}>Create</Button>
            </DialogActions>
        </Dialog>
    );
};

export default CreateNetworkDialog;
