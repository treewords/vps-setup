import React, { useState, useMemo, createContext } from 'react';
import { createTheme, ThemeProvider as MuiThemeProvider, CssBaseline } from '@mui/material';

export const ThemeContext = createContext({
  toggleColorMode: () => {},
});

const getDesignTokens = (mode) => ({
  palette: {
    mode,
    ...(mode === 'light'
      ? {
          // palette values for light mode
          primary: { main: '#2563eb' },
          background: {
            default: '#f3f4f6',
            paper: 'rgba(255, 255, 255, 0.95)',
          },
        }
      : {
          // palette values for dark mode
          primary: { main: '#3b82f6' },
          background: {
            default: '#111827',
            paper: '#1f2937',
          },
        }),
  },
});


export const CustomThemeProvider = ({ children }) => {
  const [mode, setMode] = useState('light');

  const colorMode = useMemo(
    () => ({
      toggleColorMode: () => {
        setMode((prevMode) => (prevMode === 'light' ? 'dark' : 'light'));
      },
    }),
    [],
  );

  const theme = useMemo(() => createTheme(getDesignTokens(mode)), [mode]);

  return (
    <ThemeContext.Provider value={colorMode}>
      <MuiThemeProvider theme={theme}>
        <CssBaseline />
        {children}
      </MuiThemeProvider>
    </ThemeContext.Provider>
  );
};
