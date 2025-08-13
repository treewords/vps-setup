import React, { useContext } from 'react';
import { useTheme, IconButton } from '@mui/material';
import { Logout, Brightness4, Brightness7 } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { ThemeContext } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';

const formatUptime = (seconds) => {
    if (!seconds) return '--';
    const days = Math.floor(seconds / (3600 * 24));
    seconds -= days * 3600 * 24;
    const hrs = Math.floor(seconds / 3600);
    seconds -= hrs * 3600;
    const mnts = Math.floor(seconds / 60);
    return `${days}d ${hrs}h ${mnts}m`;
};

const InfoItem = ({ label, value }) => (
    <div className="text-center">
        <span className="text-xs text-gray-500 uppercase">{label}</span>
        <span className="block text-lg font-semibold text-gray-800">{value}</span>
    </div>
);

const Header = ({ staticInfo }) => {
  const theme = useTheme();
  const colorMode = useContext(ThemeContext);
  const { logout } = useAuth();

  return (
    <header className="bg-white bg-opacity-95 backdrop-blur-sm rounded-2xl p-5 shadow-lg flex justify-between items-center mb-8">
        <div className="flex items-center gap-4">
            <div className="w-12 h-12 flex items-center justify-center rounded-xl bg-gradient-to-br from-blue-600 to-blue-800 text-white text-2xl">
                🐳
            </div>
            <h1 className="text-2xl font-bold text-gray-800">
                Docker Manager
            </h1>
        </div>
        <div className="flex items-center gap-5">
            <InfoItem label="Server" value={staticInfo?.os || '...'} />
            <InfoItem label="Uptime" value={formatUptime(staticInfo?.uptime)} />
            <InfoItem label="Docker" value={`v${staticInfo?.dockerVersion || '...'}`} />
            <IconButton onClick={colorMode.toggleColorMode} color="inherit" title="Toggle theme">
                {theme.palette.mode === 'dark' ? <Brightness7 /> : <Brightness4 />}
            </IconButton>
            <IconButton onClick={logout} title="Logout">
                <Logout />
            </IconButton>
        </div>
    </header>
  );
};

export default Header;
