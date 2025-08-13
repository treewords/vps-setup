import React, { useState, useEffect } from 'react';
import { Box, Tabs, Tab } from '@mui/material';
import Header from '../components/Header';
import SystemMonitor from '../components/SystemMonitor';
import ContainerStatsGrid from '../components/ContainerStatsGrid';
import ContainerList from '../components/ContainerList';
import ImageList from '../components/ImageList';
import * as api from '../services/api';

function TabPanel(props) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ pt: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

const Dashboard = () => {
  const [staticInfo, setStaticInfo] = useState(null);
  const [currentTab, setCurrentTab] = useState(0);

  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
  };

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
    <div className="container">
        <Header staticInfo={staticInfo} />

        <Box sx={{ borderBottom: 1, borderColor: 'divider', background: 'rgba(255, 255, 255, 0.95)', borderRadius: '16px 16px 0 0' }}>
          <Tabs value={currentTab} onChange={handleTabChange} aria-label="basic tabs example">
            <Tab label="Containers" />
            <Tab label="Images" />
          </Tabs>
        </Box>

        <div className="container-section">
          <TabPanel value={currentTab} index={0}>
              <ContainerStatsGrid />
              <ContainerList />
              <SystemMonitor />
          </TabPanel>
          <TabPanel value={currentTab} index={1}>
              <ImageList />
          </TabPanel>
        </div>
    </div>
  );
};

export default Dashboard;
