import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, TextField } from '@mui/material';
import * as api from '../services/api';

const ImageActions = ({ onActionComplete }) => {
    const [pullDialogOpen, setPullDialogOpen] = useState(false);
    const [buildDialogOpen, setBuildDialogOpen] = useState(false);
    const [pullImageName, setPullImageName] = useState('');
    const [buildRemoteUrl, setBuildRemoteUrl] = useState('');
    const [buildTag, setBuildTag] = useState('');

    const handlePullClick = () => {
        setPullDialogOpen(true);
    };

    const handleBuildClick = () => {
        setBuildDialogOpen(true);
    };

    const handleClose = () => {
        setPullDialogOpen(false);
        setBuildDialogOpen(false);
        setPullImageName('');
        setBuildRemoteUrl('');
        setBuildTag('');
    };

    const handlePullImage = async () => {
        try {
            const response = await api.pullImage(pullImageName);
            alert(response.data.message);
            onActionComplete();
        } catch (error) {
            console.error("Error pulling image", error);
            alert(`Error: ${error.response?.data?.message || error.message}`);
        }
        handleClose();
    };

    const handleBuildImage = async () => {
        try {
            const response = await api.buildImage(buildRemoteUrl, buildTag);
            alert(response.data.message);
            onActionComplete();
        } catch (error) {
            console.error("Error building image", error);
            alert(`Error: ${error.response?.data?.message || error.message}`);
        }
        handleClose();
    };

    return (
        <div>
            <Button variant="contained" onClick={handlePullClick} sx={{ mr: 1 }}>
                Pull Image
            </Button>
            <Button variant="contained" onClick={handleBuildClick}>
                Build Image
            </Button>

            {/* Pull Image Dialog */}
            <Dialog open={pullDialogOpen} onClose={handleClose}>
                <DialogTitle>Pull Image</DialogTitle>
                <DialogContent>
                    <DialogContentText>
                        Enter the name of the image to pull from Docker Hub (e.g., "ubuntu:latest").
                    </DialogContentText>
                    <TextField
                        autoFocus
                        margin="dense"
                        id="name"
                        label="Image Name"
                        type="text"
                        fullWidth
                        variant="standard"
                        value={pullImageName}
                        onChange={(e) => setPullImageName(e.target.value)}
                    />
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleClose}>Cancel</Button>
                    <Button onClick={handlePullImage}>Pull</Button>
                </DialogActions>
            </Dialog>

            {/* Build Image Dialog */}
            <Dialog open={buildDialogOpen} onClose={handleClose}>
                <DialogTitle>Build Image</DialogTitle>
                <DialogContent>
                    <DialogContentText>
                        Enter the URL of a remote git repository containing a Dockerfile.
                    </DialogContentText>
                    <TextField
                        autoFocus
                        margin="dense"
                        id="remote"
                        label="Remote Git URL"
                        type="text"
                        fullWidth
                        variant="standard"
                        value={buildRemoteUrl}
                        onChange={(e) => setBuildRemoteUrl(e.target.value)}
                    />
                    <TextField
                        margin="dense"
                        id="tag"
                        label="Tag (optional)"
                        type="text"
                        fullWidth
                        variant="standard"
                        value={buildTag}
                        onChange={(e) => setBuildTag(e.target.value)}
                    />
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleClose}>Cancel</Button>
                    <Button onClick={handleBuildImage}>Build</Button>
                </DialogActions>
            </Dialog>
        </div>
    );
};

export default ImageActions;
