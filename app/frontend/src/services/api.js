import axios from 'axios';

const apiClient = axios.create({
  baseURL: '/api', // Proxied by the dev server, and by Nginx in production
});

export const getContainers = () => {
  return apiClient.get('/containers');
};

export const inspectContainer = (id) => {
  return apiClient.get(`/containers/${id}`);
};

export const getContainerLogs = (id) => {
    return apiClient.get(`/containers/${id}/logs`, { responseType: 'text' });
};

export const startContainer = (id) => {
  return apiClient.post(`/containers/${id}/start`);
};

export const stopContainer = (id) => {
  return apiClient.post(`/containers/${id}/stop`);
};

export const restartContainer = (id) => {
  return apiClient.post(`/containers/${id}/restart`);
};

export const pauseContainer = (id) => {
  return apiClient.post(`/containers/${id}/pause`);
};

export const unpauseContainer = (id) => {
  return apiClient.post(`/containers/${id}/unpause`);
};

export const removeContainer = (id, force = false) => {
  return apiClient.delete(`/containers/${id}?force=${force}`);
};

export const getSystemInfo = () => {
  return apiClient.get('/system');
};

export const getImages = () => {
  return apiClient.get('/images');
};

export const removeImage = (id, force = false) => {
    return apiClient.delete(`/images/${id}?force=${force}`);
};
