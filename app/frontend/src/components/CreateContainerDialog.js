import React, { useState, useEffect } from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions, Button, TextField,
  Box, IconButton, Autocomplete
} from '@mui/material';
import { AddCircleOutline, RemoveCircleOutline } from '@mui/icons-material';
import * as api from '../services/api';

const CreateContainerDialog = ({ open, onClose, onCreated }) => {
  const [image, setImage] = useState('');
  const [name, setName] = useState('');
  const [ports, setPorts] = useState([{ host: '', container: '' }]);
  const [envs, setEnvs] = useState([{ key: '', value: '' }]);
  const [volumes, setVolumes] = useState([{ host: '', container: '' }]);

  const [availableImages, setAvailableImages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (open) {
      const fetchImages = async () => {
        try {
          const response = await api.getImages();
          const imageNames = response.data.flatMap(img => img.RepoTags || []);
          setAvailableImages(imageNames);
        } catch (err) {
          console.error("Failed to fetch images", err);
        }
      };
      fetchImages();
    }
  }, [open]);

  const handleAddField = (setter, field) => setter(prev => [...prev, field]);
  const handleRemoveField = (setter, index) => setter(prev => prev.filter((_, i) => i !== index));
  const handleFieldChange = (setter, index, event) => {
    const { name, value } = event.target;
    setter(prev => {
      const newFields = [...prev];
      newFields[index][name] = value;
      return newFields;
    });
  };

  const handleSubmit = async () => {
    setLoading(true);
    setError('');

    const formatPorts = () => {
        const portBindings = {};
        ports.forEach(p => {
            if (p.container && p.host) {
                portBindings[`${p.container}/tcp`] = [{ HostPort: p.host }];
            }
        });
        return portBindings;
    };

    const exposedPorts = {};
    ports.forEach(p => {
        if (p.container) {
            exposedPorts[`${p.container}/tcp`] = {};
        }
    });

    const config = {
      Image: image,
      name: name,
      ExposedPorts: exposedPorts,
      Env: envs.filter(e => e.key).map(e => `${e.key}=${e.value}`),
      HostConfig: {
        PortBindings: formatPorts(),
        Binds: volumes.filter(v => v.host && v.container).map(v => `${v.host}:${v.container}`),
      },
    };

    try {
      await api.createContainer(config);
      onCreated();
      onClose();
    } catch (err) {
      console.error("Error creating container", err);
      setError(err.response?.data?.message || 'Failed to create container.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle className="bg-gray-100">Create New Container</DialogTitle>
      <DialogContent className="divide-y divide-gray-200">
        <div className="py-4">
            <Autocomplete
            freeSolo
            options={availableImages}
            value={image}
            onChange={(event, newValue) => setImage(newValue)}
            renderInput={(params) => (
                <TextField {...params} label="Image" margin="normal" required fullWidth />
            )}
            />
            <TextField label="Container Name" value={name} onChange={e => setName(e.target.value)} fullWidth margin="normal" />
        </div>

        <div className="py-4">
          <h3 className="text-lg font-medium text-gray-900">Port Mappings</h3>
          {ports.map((p, i) => (
            <div key={i} className="flex items-center gap-2 mt-2">
              <TextField label="Host Port" name="host" value={p.host} onChange={e => handleFieldChange(setPorts, i, e)} />
              <TextField label="Container Port" name="container" value={p.container} onChange={e => handleFieldChange(setPorts, i, e)} />
              <IconButton onClick={() => handleRemoveField(setPorts, i)}><RemoveCircleOutline /></IconButton>
            </div>
          ))}
          <Button startIcon={<AddCircleOutline />} onClick={() => handleAddField(setPorts, { host: '', container: '' })} className="mt-2">Add Port</Button>
        </div>

        <div className="py-4">
          <h3 className="text-lg font-medium text-gray-900">Environment Variables</h3>
          {envs.map((e, i) => (
            <div key={i} className="flex items-center gap-2 mt-2">
              <TextField label="Key" name="key" value={e.key} onChange={e => handleFieldChange(setEnvs, i, e)} />
              <TextField label="Value" name="value" value={e.value} onChange={e => handleFieldChange(setEnvs, i, e)} />
              <IconButton onClick={() => handleRemoveField(setEnvs, i)}><RemoveCircleOutline /></IconButton>
            </div>
          ))}
          <Button startIcon={<AddCircleOutline />} onClick={() => handleAddField(setEnvs, { key: '', value: '' })} className="mt-2">Add Variable</Button>
        </div>

        <div className="py-4">
          <h3 className="text-lg font-medium text-gray-900">Volume Mounts</h3>
          {volumes.map((v, i) => (
            <div key={i} className="flex items-center gap-2 mt-2">
              <TextField label="Host Path" name="host" value={v.host} onChange={e => handleFieldChange(setVolumes, i, e)} fullWidth />
              <TextField label="Container Path" name="container" value={v.container} onChange={e => handleFieldChange(setVolumes, i, e)} fullWidth />
              <IconButton onClick={() => handleRemoveField(setVolumes, i)}><RemoveCircleOutline /></IconButton>
            </div>
          ))}
          <Button startIcon={<AddCircleOutline />} onClick={() => handleAddField(setVolumes, { host: '', container: '' })} className="mt-2">Add Volume</Button>
        </div>

        {error && <p className="text-red-500 mt-4">{error}</p>}
      </DialogContent>
      <DialogActions className="p-4 bg-gray-50">
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" disabled={loading}>
          {loading ? 'Creating...' : 'Create and Start'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default CreateContainerDialog;
