import React from 'react';
import { Activity, Cloud } from 'lucide-react';

interface TopbarProps {
  currentTab: string;
  backendHealthy: boolean;
}

export const Topbar: React.FC<TopbarProps> = ({ currentTab, backendHealthy }) => {
  return (
    <header className="h-16 border-b border-surface-border bg-surface/50 backdrop-blur px-6 flex items-center justify-between">
      <div className="flex items-center space-x-3">
        <h2 className="text-lg font-semibold text-white">{currentTab}</h2>
        <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 flex items-center gap-1.5">
          <Cloud className="w-3 h-3" />
          Synthetic Azure Telemetry
        </span>
      </div>

      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 text-xs">
          <span
            className={`w-2 h-2 rounded-full ${
              backendHealthy ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'
            }`}
          />
          <span className="text-gray-400 flex items-center gap-1">
            <Activity className="w-3.5 h-3.5" />
            Backend: {backendHealthy ? 'Connected' : 'Offline'}
          </span>
        </div>
      </div>
    </header>
  );
};
