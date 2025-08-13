import React, { useState, useEffect } from 'react';
import { createTheme, ThemeProvider } from '@mui/material';
import Header from './components/Header';
import SystemMonitor from './components/SystemMonitor';
import ContainerStatsGrid from './components/ContainerStatsGrid';
import ContainerList from './components/ContainerList';
import * as api from './services/api';

const theme = createTheme({
    // Keep a default theme for MUI components that are not custom-styled
});

function App() {
  const [staticInfo, setStaticInfo] = useState(null);

  useEffect(() => {
    const fetchStaticInfo = async () => {
      try {
        const response = await api.getSystemInfo();
        setStaticInfo(response.data);
      } catch (error) {
        console.error("Error fetching system info", error);
      }
    };
    fetchStaticInfo();
  }, []);

  return (
    <ThemeProvider theme={theme}>
      <div className="container">
          <Header staticInfo={staticInfo} />
          <ContainerStatsGrid />
          <div className="container-section">
            <ContainerList />
          </div>
          <SystemMonitor />
      </div>
    </ThemeProvider>
  );
}

export default App;
