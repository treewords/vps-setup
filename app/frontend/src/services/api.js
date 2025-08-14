import axios from 'axios';

const apiClient = axios.create({
  baseURL: '/api',
});

apiClient.interceptors.request.use((config) => {
    const accessToken = localStorage.getItem('dockerManagerAccessToken');
    if (accessToken) {
        config.headers.Authorization = `Bearer ${accessToken}`;
    }
    return config;
}, (error) => {
    return Promise.reject(error);
});

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const refreshToken = localStorage.getItem('dockerManagerRefreshToken');
        const { data } = await apiClient.post('/auth/refresh', { token: refreshToken });
        localStorage.setItem('dockerManagerAccessToken', data.accessToken);
        apiClient.defaults.headers.common['Authorization'] = 'Bearer ' + data.accessToken;
        return apiClient(originalRequest);
      } catch (refreshError) {
        // Logout user if refresh token is invalid
        localStorage.removeItem('dockerManagerAccessToken');
        localStorage.removeItem('dockerManagerRefreshToken');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    return Promise.reject(error);
  }
);


export const login = (username, password) => {
    return apiClient.post('/auth/login', { username, password });
};

export const register = (username, password) => {
    return apiClient.post('/auth/register', { username, password });
};

export const logout = (refreshToken) => {
    return apiClient.post('/auth/logout', { token: refreshToken });
}

export const getSystemInfo = () => {
  return apiClient.get('/system');
};

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

export const createContainer = (config) => {
    return apiClient.post('/containers/create', config);
};

export const getImages = () => {
  return apiClient.get('/images');
};

export const removeImage = (id, force = false) => {
    return apiClient.delete(`/images/${id}?force=${force}`);
};

export const pullImage = (imageName) => {
    return apiClient.post('/images/pull', { imageName });
};

export const buildImage = (remote, tag) => {
    return apiClient.post('/images/build', { remote, t: tag });
};

export const tagImage = (id, repo, tag) => {
    return apiClient.post(`/images/${id}/tag`, { repo, tag });
};

// --- Network API Calls ---
export const getNetworks = () => {
    return apiClient.get('/networks');
};

export const inspectNetwork = (id) => {
    return apiClient.get(`/networks/${id}`);
};

export const createNetwork = (config) => {
    return apiClient.post('/networks/create', config);
};

export const removeNetwork = (id) => {
    return apiClient.delete(`/networks/${id}`);
};

export const connectToNetwork = (id, containerId) => {
    return apiClient.post(`/networks/${id}/connect`, { containerId });
};

export const disconnectFromNetwork = (id, containerId) => {
    return apiClient.post(`/networks/${id}/disconnect`, { containerId });
};

// --- Volume API Calls ---
export const getVolumes = () => {
    return apiClient.get('/volumes');
};

export const inspectVolume = (name) => {
    return apiClient.get(`/volumes/${name}`);
};

export const createVolume = (config) => {
    return apiClient.post('/volumes/create', config);
};

export const removeVolume = (name) => {
    return apiClient.delete(`/volumes/${name}`);
};

export const backupVolume = (name) => {
    return apiClient.post(`/volumes/${name}/backup`);
};
