import React, { createContext, useState, useEffect, useRef, useContext, useCallback } from 'react';
import * as api from '../services/api';

const DockerContext = createContext(null);

export const useDocker = () => useContext(DockerContext);

export const DockerProvider = ({ children }) => {
  const [containers, setContainers] = useState([]);
  const [images, setImages] = useState([]);
  const [networks, setNetworks] = useState([]);
  const [volumes, setVolumes] = useState([]);
  const [systemInfo, setSystemInfo] = useState(null);
  const [containerStats, setContainerStats] = useState({});
  const [systemStats, setSystemStats] = useState(null);
  const [loading, setLoading] = useState({
    containers: true,
    images: true,
    networks: true,
    volumes: true,
    systemInfo: true,
  });
  const ws = useRef(null);

  const fetchContainers = useCallback(async () => {
    setLoading(prev => ({ ...prev, containers: true }));
    try {
      const response = await api.getContainers();
      setContainers(response.data);
    } catch (error) {
      console.error("Error fetching containers", error);
    } finally {
      setLoading(prev => ({ ...prev, containers: false }));
    }
  }, []);

  const fetchImages = useCallback(async () => {
    setLoading(prev => ({ ...prev, images: true }));
    try {
      const response = await api.getImages();
      setImages(response.data);
    } catch (error) {
      console.error("Error fetching images", error);
    } finally {
      setLoading(prev => ({ ...prev, images: false }));
    }
  }, []);

  const fetchNetworks = useCallback(async () => {
    setLoading(prev => ({ ...prev, networks: true }));
    try {
      const response = await api.getNetworks();
      setNetworks(response.data);
    } catch (error) {
      console.error("Error fetching networks", error);
    } finally {
      setLoading(prev => ({ ...prev, networks: false }));
    }
  }, []);

  const fetchVolumes = useCallback(async () => {
    setLoading(prev => ({ ...prev, volumes: true }));
    try {
      const response = await api.getVolumes();
      setVolumes(response.data.Volumes);
    } catch (error) {
      console.error("Error fetching volumes", error);
    } finally {
      setLoading(prev => ({ ...prev, volumes: false }));
    }
  }, []);

  const fetchSystemInfo = useCallback(async () => {
    setLoading(prev => ({ ...prev, systemInfo: true }));
    try {
      const response = await api.getSystemInfo();
      setSystemInfo(response.data);
    } catch (error) {
      console.error("Error fetching system info", error);
    } finally {
      setLoading(prev => ({ ...prev, systemInfo: false }));
    }
  }, []);

  const refreshAll = useCallback(() => {
    fetchContainers();
    fetchImages();
    fetchNetworks();
    fetchVolumes();
    fetchSystemInfo();
  }, [fetchContainers, fetchImages, fetchNetworks, fetchVolumes, fetchSystemInfo]);

  useEffect(() => {
    refreshAll();

    // WebSocket for live stats
    const isProduction = process.env.NODE_ENV === 'production';
    const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const wsHost = isProduction ? window.location.host : 'localhost:3001';
    const wsUrl = `${wsProtocol}://${wsHost}/ws`;

    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      console.log('Docker data WebSocket connected');
      ws.current.send(JSON.stringify({ type: 'stats' }));
      ws.current.send(JSON.stringify({ type: 'get_system_stats' }));
    };

    ws.current.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'stats_data') {
        setContainerStats(prevStats => ({
          ...prevStats,
          [message.id]: message.stats,
        }));
      }
      if (message.type === 'system_stats_data') {
        setSystemStats(message.stats);
      }
    };

    ws.current.onclose = () => {
      console.log('Docker data WebSocket disconnected');
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [refreshAll]);

  const value = {
    containers,
    images,
    networks,
    volumes,
    systemInfo,
    containerStats,
    systemStats,
    loading,
    refresh: refreshAll,
  };

  return (
    <DockerContext.Provider value={value}>
      {children}
    </DockerContext.Provider>
  );
};
