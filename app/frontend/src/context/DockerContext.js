import React, { createContext, useState, useEffect, useRef, useContext } from 'react';
import * as api from '../services/api';

const DockerContext = createContext(null);

export const useDocker = () => useContext(DockerContext);

export const DockerProvider = ({ children }) => {
  const [containers, setContainers] = useState([]);
  const [images, setImages] = useState([]);
  const [systemInfo, setSystemInfo] = useState(null);
  const [containerStats, setContainerStats] = useState({});
  const [systemStats, setSystemStats] = useState(null);
  const [loading, setLoading] = useState({
    containers: true,
    images: true,
    system: true,
  });
  const ws = useRef(null);

  const fetchAll = async () => {
    try {
      setLoading(prev => ({ ...prev, containers: true, images: true, system: true }));
      const [containersRes, imagesRes, systemRes] = await Promise.all([
        api.getContainers(),
        api.getImages(),
        api.getSystemInfo(),
      ]);
      setContainers(containersRes.data);
      setImages(imagesRes.data);
      setSystemInfo(systemRes.data);
    } catch (error) {
      console.error("Error fetching initial data", error);
    } finally {
        setLoading(prev => ({ ...prev, containers: false, images: false, system: false }));
    }
  };

  useEffect(() => {
    fetchAll(); // Initial fetch

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
      // Optional: implement reconnect logic
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  const value = {
    containers,
    images,
    systemInfo,
    containerStats,
    systemStats,
    loading,
    refresh: fetchAll,
  };

  return (
    <DockerContext.Provider value={value}>
      {children}
    </DockerContext.Provider>
  );
};
