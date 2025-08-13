import React, { useState, useEffect } from 'react';
import { useDocker } from '../context/DockerContext';

const StatCard = ({ title, value, icon, colorClass }) => (
    <div className={`bg-white bg-opacity-95 backdrop-blur-sm rounded-xl p-5 shadow-lg relative overflow-hidden border-t-4 ${colorClass}`}>
        <div className="flex justify-between items-center mb-2">
             <div className="text-4xl font-bold text-gray-800">{value}</div>
             <div className={`text-3xl ${colorClass}-text`}>
                {icon}
             </div>
        </div>
        <div className="text-sm text-gray-600">{title}</div>
    </div>
);

const ContainerStatsGrid = () => {
  const { containers } = useDocker();
  const [stats, setStats] = useState({ total: 0, running: 0, paused: 0, stopped: 0 });

  useEffect(() => {
    if (containers) {
      const running = containers.filter(c => c.State === 'running').length;
      const paused = containers.filter(c => c.State === 'paused').length;
      const stopped = containers.filter(c => c.State === 'exited').length;
      setStats({ total: containers.length, running, paused, stopped });
    }
  }, [containers]);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-6 mb-8">
        <StatCard title="Total Containers" value={stats.total} icon="📦" colorClass="border-blue-500" />
        <StatCard title="Running" value={stats.running} icon="✅" colorClass="border-green-500" />
        <StatCard title="Paused" value={stats.paused} icon="⏸️" colorClass="border-yellow-500" />
        <StatCard title="Stopped" value={stats.stopped} icon="⏹️" colorClass="border-red-500" />
    </div>
  );
};

export default ContainerStatsGrid;
