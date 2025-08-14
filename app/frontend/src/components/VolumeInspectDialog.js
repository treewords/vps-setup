import React, { useState, useEffect } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, CircularProgress, Typography } from '@mui/material';
import * as api from '../services/api';

const VolumeInspectDialog = ({ open, onClose, volumeName }) => {
    const [volumeDetails, setVolumeDetails] = useState(null);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (open && volumeName) {
            setLoading(true);
            api.inspectVolume(volumeName)
                .then(response => {
                    setVolumeDetails(response.data);
                })
                .catch(error => {
                    console.error("Error inspecting volume", error);
                    // Optionally, show an error message in the dialog
                })
                .finally(() => {
                    setLoading(false);
                });
        }
    }, [open, volumeName]);

    const handleClose = () => {
        setVolumeDetails(null);
        onClose();
    };

    return (
        <Dialog open={open} onClose={handleClose} fullWidth maxWidth="md">
            <DialogTitle>Inspect Volume</DialogTitle>
            <DialogContent>
                {loading ? (
                    <CircularProgress />
                ) : volumeDetails ? (
                    <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        {JSON.stringify(volumeDetails, null, 2)}
                    </pre>
                ) : (
                    <Typography>Could not load volume details.</Typography>
                )}
            </DialogContent>
            <DialogActions>
                <Button onClick={handleClose}>Close</Button>
            </DialogActions>
        </Dialog>
    );
};

export default VolumeInspectDialog;
