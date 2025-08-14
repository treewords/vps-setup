import React, { useState, useEffect, useCallback } from 'react';
import {
    Button, Dialog, DialogActions, DialogContent, DialogTitle, CircularProgress, Typography,
    List, ListItem, ListItemText, IconButton, Divider, Box
} from '@mui/material';
import { Link as LinkIcon, LinkOff as LinkOffIcon } from '@mui/icons-material';
import * as api from '../services/api';
import { useDocker } from '../context/DockerContext';
import ConnectContainerDialog from './ConnectContainerDialog';

const NetworkInspectDialog = ({ open, onClose, networkId }) => {
    const { containers } = useDocker();
    const [networkDetails, setNetworkDetails] = useState(null);
    const [loading, setLoading] = useState(false);
    const [connectDialogOpen, setConnectDialogOpen] = useState(false);

    const fetchNetworkDetails = useCallback(() => {
        if (networkId) {
            setLoading(true);
            api.inspectNetwork(networkId)
                .then(response => {
                    setNetworkDetails(response.data);
                })
                .catch(error => {
                    console.error("Error inspecting network", error);
                })
                .finally(() => {
                    setLoading(false);
                });
        }
    }, [networkId]);

    useEffect(() => {
        if (open) {
            fetchNetworkDetails();
        }
    }, [open, fetchNetworkDetails]);

    const handleDisconnect = async (containerId) => {
        try {
            await api.disconnectFromNetwork(networkId, containerId);
            fetchNetworkDetails(); // Refresh details
        } catch (error) {
            console.error("Error disconnecting container", error);
        }
    };

    const handleConnect = async (containerId) => {
        try {
            await api.connectToNetwork(networkId, containerId);
            fetchNetworkDetails(); // Refresh details
        } catch (error) {
            console.error("Error connecting container", error);
        }
        setConnectDialogOpen(false);
    };

    const handleClose = () => {
        setNetworkDetails(null);
        onClose();
    };

    return (
        <>
            <Dialog open={open} onClose={handleClose} fullWidth maxWidth="md">
                <DialogTitle>Inspect Network: {networkDetails?.Name}</DialogTitle>
                <DialogContent>
                    {loading ? (
                        <CircularProgress />
                    ) : networkDetails ? (
                        <Box>
                            <Typography variant="h6" gutterBottom>Details</Typography>
                            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: '200px', overflowY: 'auto', backgroundColor: '#f5f5f5', padding: '10px', borderRadius: '4px' }}>
                                {JSON.stringify({ ...networkDetails, Containers: undefined }, null, 2)}
                            </pre>

                            <Divider sx={{ my: 2 }} />

                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <Typography variant="h6" gutterBottom>Connected Containers</Typography>
                                <Button
                                    variant="outlined"
                                    startIcon={<LinkIcon />}
                                    onClick={() => setConnectDialogOpen(true)}
                                >
                                    Connect Container
                                </Button>
                            </Box>
                            <List>
                                {Object.keys(networkDetails.Containers).length > 0 ? (
                                    Object.entries(networkDetails.Containers).map(([id, container]) => (
                                        <ListItem
                                            key={id}
                                            secondaryAction={
                                                <IconButton edge="end" aria-label="disconnect" onClick={() => handleDisconnect(id)}>
                                                    <LinkOffIcon />
                                                </IconButton>
                                            }
                                        >
                                            <ListItemText primary={container.Name} secondary={id} />
                                        </ListItem>
                                    ))
                                ) : (
                                    <Typography sx={{ p: 2 }}>No containers connected.</Typography>
                                )}
                            </List>
                        </Box>
                    ) : (
                        <Typography>Could not load network details.</Typography>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleClose}>Close</Button>
                </DialogActions>
            </Dialog>
            <ConnectContainerDialog
                open={connectDialogOpen}
                onClose={() => setConnectDialogOpen(false)}
                onConnect={handleConnect}
                containers={containers.filter(c => !networkDetails?.Containers?.[c.Id])}
            />
        </>
    );
};

export default NetworkInspectDialog;
