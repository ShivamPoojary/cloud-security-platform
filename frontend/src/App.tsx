import React, { useState, useEffect } from 'react';
import { Sidebar, NavItem } from './components/Sidebar';
import { Topbar } from './components/Topbar';
import { Dashboard } from './pages/Dashboard';
import { LiveMonitor } from './pages/LiveMonitor';
import { DetectionRules } from './pages/DetectionRules';
import { UEBA } from './pages/UEBA';
import { PlaceholderView } from './pages/PlaceholderView';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavItem>('Dashboard');
  const [backendHealthy, setBackendHealthy] = useState<boolean>(false);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('/health');
        if (res.ok) {
          const data = await res.json();
          setBackendHealthy(data.status === 'ok');
        } else {
          setBackendHealthy(false);
        }
      } catch {
        setBackendHealthy(false);
      }
    };

    checkHealth();
    const timer = setInterval(checkHealth, 5000);
    return () => clearInterval(timer);
  }, []);

  const renderContent = () => {
    switch (currentTab) {
      case 'Dashboard':
        return <Dashboard />;
      case 'Live Monitor':
        return <LiveMonitor />;
      case 'UEBA & ML':
        return <UEBA />;
      case 'Detection Rules':
        return <DetectionRules />;
      case 'Incidents':
        return (
          <PlaceholderView
            title="Incident Management & Triage"
            phase="Phase 4"
            description="SOC incident lifecycle management, severity assessment, evidence locker, and analyst notes."
          />
        );
      case 'Attack Graph':
        return (
          <PlaceholderView
            title="Interactive Attack Graph"
            phase="Phase 4"
            description="Node-and-edge visualization of entity compromises (Principals, IPs, Azure Resources) using React Flow."
          />
        );
      case 'Timeline':
        return (
          <PlaceholderView
            title="Attack Timeline Reconstruction"
            phase="Phase 4"
            description="Interactive chronological timeline player to scrub through multi-stage kill-chain events."
          />
        );
      case 'MITRE ATT&CK':
        return (
          <PlaceholderView
            title="MITRE ATT&CK Matrix Heatmap"
            phase="Phase 4"
            description="Dynamic matrix covering Tactics and Techniques with frequency heatmaps and incident drill-downs."
          />
        );
      case 'Playbooks':
        return (
          <PlaceholderView
            title="SOAR Playbooks & Containment"
            phase="Phase 5"
            description="Automated containment workflows (Revoke Entra ID user session, isolate VM) with dry-run verification."
          />
        );
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="flex h-screen bg-background overflow-hidden text-gray-100">
      <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Topbar currentTab={currentTab} backendHealthy={backendHealthy} />
        <main className="flex-1 overflow-y-auto">{renderContent()}</main>
      </div>
    </div>
  );
};

export default App;
