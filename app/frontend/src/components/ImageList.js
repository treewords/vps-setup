import React, { useState } from 'react';
import {
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Button, Chip, Typography, Box, IconButton, Tooltip
} from '@mui/material';
import { Delete, Refresh } from '@mui/icons-material';
import * as api from '../services/api';
import ConfirmationDialog from './ConfirmationDialog';
import { useDocker } from '../context/DockerContext';

const formatSize = (bytes) => {
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${['B', 'KB', 'MB', 'GB'][i]}`;
};

const formatDate = (timestamp) => {
    return new Date(timestamp * 1000).toLocaleString();
};

const ImageList = () => {
  const { images, loading, refresh } = useDocker();
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [selectedImage, setSelectedImage] = useState(null);
  const [confirmAction, setConfirmAction] = useState(null);

  const handleRemoveClick = (image) => {
    setSelectedImage(image);
    setConfirmAction(() => () => handleRemoveImage(image.Id));
    setConfirmDialogOpen(true);
  };

  const handleConfirmClose = () => {
    setConfirmDialogOpen(false);
    setSelectedImage(null);
    setConfirmAction(null);
  };

  const handleRemoveImage = async (id) => {
    try {
      await api.removeImage(id);
      refresh();
    } catch (error) {
      console.error("Error removing image", error);
      // You might want to show a notification to the user here
    }
  };

  return (
    <Box>
       <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h5" sx={{ fontWeight: 600, color: 'var(--dark)' }}>
          Images
        </Typography>
        <Button variant="contained" onClick={refresh} disabled={loading.images} startIcon={<Refresh />} sx={{ borderRadius: '8px', textTransform: 'none', background: 'var(--primary)', '&:hover': { background: 'var(--primary-dark)' } }}>
            Refresh
          </Button>
      </Box>
      <TableContainer>
        <Table sx={{
            width: '100%',
            borderCollapse: 'collapse',
            '& th': {
                textAlign: 'left',
                p: '12px',
                background: 'var(--light)',
                color: 'var(--text-light)',
                fontSize: '12px',
                fontWeight: 600,
                textTransform: 'uppercase',
                borderBottom: '2px solid var(--border)',
            },
            '& td': {
                p: '12px',
                borderBottom: '1px solid var(--border)',
                fontSize: '14px',
            },
            '& tr:hover': {
                background: 'rgba(37, 99, 235, 0.05)',
            }
        }}>
          <TableHead>
            <TableRow>
              <TableCell>Tags</TableCell>
              <TableCell>ID</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Size</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} align="center">
                    <Typography>Loading images...</Typography>
                </TableCell>
              </TableRow>
            ) : images.map((image) => (
              <TableRow key={image.Id}>
                <TableCell>
                  {image.RepoTags && image.RepoTags.length > 0 ?
                    image.RepoTags.map(tag => <Chip key={tag} label={tag} size="small" sx={{ mr: 0.5, mb: 0.5 }} />) :
                    <Chip label="<none>:<none>" size="small" variant="outlined" />}
                </TableCell>
                <TableCell><code>{image.Id.substring(7, 19)}</code></TableCell>
                <TableCell>{formatDate(image.Created)}</TableCell>
                <TableCell>{formatSize(image.Size)}</TableCell>
                <TableCell align="right">
                    <Tooltip title="Remove Image">
                        <span>
                            <IconButton onClick={() => handleRemoveClick(image)}>
                                <Delete sx={{ color: 'var(--danger)'}} />
                            </IconButton>
                        </span>
                    </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      {selectedImage && (
          <ConfirmationDialog
            open={confirmDialogOpen}
            onClose={handleConfirmClose}
            onConfirm={() => {
              if (confirmAction) {
                confirmAction();
              }
              handleConfirmClose();
            }}
            title="Remove Image"
            description={`Are you sure you want to remove this image? ${selectedImage.RepoTags ? selectedImage.RepoTags[0] : selectedImage.Id.substring(7,19)}`}
          />
      )}
    </Box>
  );
};

export default ImageList;
