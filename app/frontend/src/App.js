import React from 'react';
import ContainerList from './components/ContainerList';
import SystemMonitor from './components/SystemMonitor';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
  },
});

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Docker Manager
          </Typography>
        </Toolbar>
      </AppBar>
      <Container sx={{ mt: 4, maxWidth: 'xl' }}>
        <SystemMonitor />
        <ContainerList />
      </Container>
    </ThemeProvider>
  );
}

export default App;
