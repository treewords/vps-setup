import React, { useState, useEffect } from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions, Button,
  CircularProgress, Box, Typography
} from '@mui/material';
import * as api from '../services/api';

const ContainerInspectDialog = ({ open, onClose, containerId }) => {
  const [inspectionData, setInspectionData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (open && containerId) {
      const fetchInspectionData = async () => {
        setLoading(true);
        setError('');
        setInspectionData(null);
        try {
          const response = await api.inspectContainer(containerId);
          setInspectionData(response.data);
        } catch (err) {
          console.error("Error inspecting container", err);
          setError(err.message || 'Failed to fetch container details.');
        } finally {
          setLoading(false);
        }
      };
      fetchInspectionData();
    }
  }, [open, containerId]);

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>Inspect Container</DialogTitle>
      <DialogContent>
        {loading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', my: 4 }}>
            <CircularProgress />
          </Box>
        )}
        {error && (
          <Typography color="error" sx={{ my: 2 }}>
            {error}
          </Typography>
        )}
        {inspectionData && (
          <Box component="pre" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', backgroundColor: '#222', p: 2, borderRadius: 1 }}>
            {JSON.stringify(inspectionData, null, 2)}
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ContainerInspectDialog;
