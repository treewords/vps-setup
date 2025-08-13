import React from 'react';
import { useDocker } from '../context/DockerContext';

const ResourceCard = ({ title, value, progress, icon }) => {

    const getProgressColor = (value) => {
        if (value > 80) return 'bg-red-500';
        if (value > 60) return 'bg-yellow-500';
        return 'bg-green-500';
    };

    return (
        <div className="bg-white bg-opacity-95 backdrop-blur-sm rounded-xl p-5 shadow-lg">
            <div className="flex justify-between items-center mb-4">
                <div className="flex items-center gap-2 text-gray-800 font-semibold">
                    <span>{icon}</span>
                    <span>{title}</span>
                </div>
                <div className="text-2xl font-bold text-blue-600">{value}</div>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2.5">
                <div
                    className={`h-2.5 rounded-full transition-all duration-500 ${getProgressColor(progress)}`}
                    style={{ width: `${progress}%` }}
                ></div>
            </div>
        </div>
    );
};


const SystemMonitor = () => {
  const { systemStats } = useDocker();

  const cpuUsage = systemStats?.cpu || 0;
  const memUsage = systemStats ? (systemStats.memory.used / systemStats.memory.total) * 100 : 0;
  const diskUsage = systemStats ? (systemStats.disk.used / systemStats.disk.total) * 100 : 0;

  return (
    <div className="mt-8">
        <h2 className="text-xl font-semibold text-white mb-4">System Overview</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <ResourceCard title="CPU Usage" icon="🖥️" value={`${cpuUsage.toFixed(1)}%`} progress={cpuUsage} />
            <ResourceCard title="Memory Usage" icon="💾" value={`${memUsage.toFixed(1)}%`} progress={memUsage} />
            <ResourceCard title="Disk Usage" icon="💿" value={`${diskUsage.toFixed(1)}%`} progress={diskUsage} />
        </div>
    </div>
  );
};

export default SystemMonitor;
