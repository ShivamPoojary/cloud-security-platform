import React from 'react';
import {
  LayoutDashboard,
  Radio,
  AlertTriangle,
  GitFork,
  Clock,
  Grid,
  ShieldCheck,
  PlaySquare,
  Shield,
  Brain,
} from 'lucide-react';

export type NavItem =
  | 'Dashboard'
  | 'Live Monitor'
  | 'UEBA & ML'
  | 'Detection Rules'
  | 'Incidents'
  | 'Attack Graph'
  | 'Timeline'
  | 'MITRE ATT&CK'
  | 'Playbooks';

interface SidebarProps {
  currentTab: NavItem;
  onSelectTab: (tab: NavItem) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const menuItems: { name: NavItem; icon: React.ReactNode }[] = [
    { name: 'Dashboard', icon: <LayoutDashboard className="w-5 h-5" /> },
    { name: 'Live Monitor', icon: <Radio className="w-5 h-5" /> },
    { name: 'UEBA & ML', icon: <Brain className="w-5 h-5" /> },
    { name: 'Detection Rules', icon: <ShieldCheck className="w-5 h-5" /> },
    { name: 'Incidents', icon: <AlertTriangle className="w-5 h-5" /> },
    { name: 'Attack Graph', icon: <GitFork className="w-5 h-5" /> },
    { name: 'Timeline', icon: <Clock className="w-5 h-5" /> },
    { name: 'MITRE ATT&CK', icon: <Grid className="w-5 h-5" /> },
    { name: 'Playbooks', icon: <PlaySquare className="w-5 h-5" /> },
  ];

  return (
    <aside className="w-64 bg-surface border-r border-surface-border flex flex-col h-screen select-none">
      <div className="p-5 border-b border-surface-border flex items-center space-x-3">
        <div className="p-2 bg-blue-600/20 text-blue-400 rounded-lg">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <h1 className="font-bold text-sm tracking-wide text-white">CloudSec SIEM</h1>
          <p className="text-xs text-gray-400">Threat Detection</p>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {menuItems.map((item) => {
          const isActive = currentTab === item.name;
          return (
            <button
              key={item.name}
              onClick={() => onSelectTab(item.name)}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
              }`}
            >
              {item.icon}
              <span>{item.name}</span>
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-surface-border text-xs text-gray-500">
        <p>Phase 1 Foundation</p>
        <p className="mt-1 text-gray-400 font-mono">v0.1.0-alpha</p>
      </div>
    </aside>
  );
};
