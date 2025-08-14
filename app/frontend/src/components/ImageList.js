import React, { useState } from 'react';
import {
  Button, Chip, IconButton, Tooltip
} from '@mui/material';
import { Delete, Refresh, Label } from '@mui/icons-material';
import * as api from '../services/api';
import ConfirmationDialog from './ConfirmationDialog';
import ImageActions from './ImageActions';
import { useDocker } from '../context/DockerContext';
import { useAuth } from '../context/AuthContext';
import { Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, TextField } from '@mui/material';

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
  const { user } = useAuth();
  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [tagDialogOpen, setTagDialogOpen] = useState(false);
  const [selectedImage, setSelectedImage] = useState(null);
  const [confirmAction, setConfirmAction] = useState(null);
  const [newRepo, setNewRepo] = useState('');
  const [newTag, setNewTag] = useState('');

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
    }
  };

  const handleTagClick = (image) => {
    setSelectedImage(image);
    setTagDialogOpen(true);
  };

  const handleTagDialogClose = () => {
    setTagDialogOpen(false);
    setSelectedImage(null);
    setNewRepo('');
    setNewTag('');
    };

    const handleTagImage = async () => {
        if (!selectedImage) return;
        try {
            await api.tagImage(selectedImage.Id, newRepo, newTag);
            refresh();
        } catch (error) {
            console.error("Error tagging image", error);
        }
        handleTagDialogClose();
    };

  return (
    <div>
       <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold text-gray-800">Images</h2>
        <div>
            <ImageActions onActionComplete={refresh} />
            <Button variant="contained" onClick={refresh} disabled={loading.images} startIcon={<Refresh />} sx={{ ml: 1 }}>
                Refresh
            </Button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full bg-white">
            <thead className="bg-gray-100">
                <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Tags</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Size</th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
                {loading.images ? (
                <tr>
                    <td colSpan="5" className="text-center py-4">Loading images...</td>
                </tr>
                ) : images.map((image) => (
                <tr key={image.Id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                    {image.RepoTags && image.RepoTags.length > 0 ?
                        image.RepoTags.map(tag => <Chip key={tag} label={tag} size="small" className="mr-1 mb-1" />) :
                        <Chip label="<none>:<none>" size="small" variant="outlined" />}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap font-mono text-sm text-gray-500">{image.Id.substring(7, 19)}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-gray-500">{formatDate(image.Created)}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-gray-500">{formatSize(image.Size)}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                        {user?.role === 'Admin' && (
                            <>
                                <Tooltip title="Tag Image">
                                    <span>
                                        <IconButton onClick={() => handleTagClick(image)}>
                                            <Label />
                                        </IconButton>
                                    </span>
                                </Tooltip>
                                <Tooltip title="Remove Image">
                                    <span>
                                        <IconButton onClick={() => handleRemoveClick(image)}>
                                            <Delete className="text-red-500" />
                                        </IconButton>
                                    </span>
                                </Tooltip>
                            </>
                        )}
                    </td>
                </tr>
                ))}
            </tbody>
        </table>
      </div>
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
        <Dialog open={tagDialogOpen} onClose={handleTagDialogClose}>
            <DialogTitle>Tag Image</DialogTitle>
            <DialogContent>
                <DialogContentText>
                    Enter a new repository and tag for the image.
                </DialogContentText>
                <TextField
                    autoFocus
                    margin="dense"
                    id="repo"
                    label="Repository"
                    type="text"
                    fullWidth
                    variant="standard"
                    value={newRepo}
                    onChange={(e) => setNewRepo(e.target.value)}
                />
                <TextField
                    margin="dense"
                    id="tag"
                    label="Tag"
                    type="text"
                    fullWidth
                    variant="standard"
                    value={newTag}
                    onChange={(e) => setNewTag(e.target.value)}
                />
            </DialogContent>
            <DialogActions>
                <Button onClick={handleTagDialogClose}>Cancel</Button>
                <Button onClick={handleTagImage}>Tag</Button>
            </DialogActions>
        </Dialog>
    </div>
  );
};

export default ImageList;
