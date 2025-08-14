import React, { useState } from 'react';
import { Box, Tabs, Tab } from '@mui/material';
import Header from '../components/Header';
import SystemMonitor from '../components/SystemMonitor';
import ContainerStatsGrid from '../components/ContainerStatsGrid';
import ContainerList from '../components/ContainerList';
import ImageList from '../components/ImageList';
import NetworkList from '../components/NetworkList';
import VolumeList from '../components/VolumeList';
import { useDocker } from '../context/DockerContext';

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
        <div className="pt-6">
          {children}
        </div>
      )}
    </div>
  );
}

const Dashboard = () => {
  const { systemInfo } = useDocker();
  const [currentTab, setCurrentTab] = useState(0);

  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
  };

  return (
    <div className="max-w-7xl mx-auto p-5">
        <Header staticInfo={systemInfo} />
        <ContainerStatsGrid />

        <div className="bg-white bg-opacity-95 backdrop-blur-sm rounded-2xl shadow-lg mt-8">
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
                <Tabs value={currentTab} onChange={handleTabChange} aria-label="dashboard tabs">
                <Tab label="Containers" />
                <Tab label="Images" />
                <Tab label="Networks" />
                <Tab label="Volumes" />
                </Tabs>
            </Box>
            <div className="p-6">
                <TabPanel value={currentTab} index={0}>
                    <ContainerList />
                </TabPanel>
                <TabPanel value={currentTab} index={1}>
                    <ImageList />
                </TabPanel>
                <TabPanel value={currentTab} index={2}>
                    <NetworkList />
                </TabPanel>
                <TabPanel value={currentTab} index={3}>
                    <VolumeList />
                </TabPanel>
            </div>
        </div>

        <SystemMonitor />
    </div>
  );
};

export default Dashboard;
