import React, { useState, useEffect } from 'react';
import {
  Server,
  Database,
  Flame,
  AlertOctagon,
  ShieldAlert,
  Play,
  CheckCircle2,
  RefreshCw,
  Brain,
} from 'lucide-react';
import { StatCard } from '../components/StatCard';

interface HealthStatus {
  status: string;
  service: string;
  version?: string;
  database?: string;
  redis?: string;
}

interface MLMetrics {
  total_anomalies: number;
  high_risk_anomalies: number;
  anomalous_principals: number;
  avg_anomaly_score: number;
  model_version: string;
}

export const Dashboard: React.FC = () => {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [eventsCount, setEventsCount] = useState<number>(0);
  const [criticalIncidents] = useState<number>(0);
  const [riskLevel] = useState<string>('Low (0.0)');
  const [triggerStatus, setTriggerStatus] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const [detectionsCount, setDetectionsCount] = useState<number>(0);
  const [mlMetrics, setMlMetrics] = useState<MLMetrics | null>(null);

  const fetchHealth = async () => {
    try {
      const [healthRes, eventsRes, detectionsRes, mlRes] = await Promise.all([
        fetch('/api/v1/health'),
        fetch('/api/v1/events?limit=1'),
        fetch('/api/v1/detections?limit=1'),
        fetch('/api/v1/ml/metrics'),
      ]);

      if (healthRes.ok) {
        const data = await healthRes.json();
        setHealth(data);
      } else {
        const rootRes = await fetch('/health');
        if (rootRes.ok) {
          const rootData = await rootRes.json();
          setHealth(rootData);
        }
      }

      if (eventsRes.ok) {
        const evData = await eventsRes.json();
        setEventsCount(evData.total || 0);
      }

      if (detectionsRes.ok) {
        const detData = await detectionsRes.json();
        setDetectionsCount(detData.total || 0);
      }

      if (mlRes.ok) {
        const mlData = await mlRes.json();
        setMlMetrics(mlData);
      }
    } catch (e) {
      console.error('Failed to probe health and metrics', e);
      setHealth(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleTriggerScenario = async (scenario: string) => {
    setIsSubmitting(true);
    setTriggerStatus(null);
    try {
      const res = await fetch('/api/v1/ingest/synthetic/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_name: scenario }),
      });
      if (res.ok) {
        const data = await res.json();
        setEventsCount((prev) => prev + data.events_count);
        setTriggerStatus(
          `Triggered ${scenario}: Generated ${data.events_count} events (ID: ${data.execution_id})`
        );
      } else {
        setTriggerStatus(`Error triggering ${scenario}: HTTP ${res.status}`);
      }
    } catch (err: any) {
      setTriggerStatus(`Failed to trigger: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Top Banner / System Notice */}
      <div className="flex flex-col md:flex-row md:items-center justify-between p-4 bg-surface border border-surface-border rounded-xl gap-4">
        <div>
          <h3 className="font-semibold text-white">Security Operation Center Overview</h3>
          <p className="text-xs text-gray-400 mt-0.5">
            Cloud Security Platform telemetry monitoring & threat assessment engine.
          </p>
        </div>
        <button
          onClick={fetchHealth}
          className="flex items-center space-x-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-medium border border-gray-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Status</span>
        </button>
      </div>

      {/* 5 Core Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-5">
        <StatCard
          label="Platform Status"
          value={health?.status === 'ok' ? 'HEALTHY' : 'DEGRADED'}
          variant={health?.status === 'ok' ? 'success' : 'danger'}
          icon={<Server className="w-5 h-5" />}
          subtitle={`DB: ${health?.database || 'checking'} | Redis: ${health?.redis || 'checking'}`}
        />
        <StatCard
          label="Events Received"
          value={eventsCount}
          icon={<Database className="w-5 h-5" />}
          subtitle="Processed in Phase 1 session"
        />
        <StatCard
          label="Threat Detections"
          value={detectionsCount}
          variant={detectionsCount > 0 ? 'warning' : 'default'}
          icon={<Flame className="w-5 h-5" />}
          subtitle="Triggered by detection rules"
        />
        <StatCard
          label="Critical Incidents"
          value={criticalIncidents}
          variant="danger"
          icon={<AlertOctagon className="w-5 h-5" />}
          subtitle="SLA < 15 mins"
        />
        <StatCard
          label="Current Risk Level"
          value={riskLevel}
          variant="default"
          icon={<ShieldAlert className="w-5 h-5" />}
          subtitle="Composite risk score"
        />
      </div>

      {/* UEBA & Machine Learning Intelligence Row */}
      <div className="bg-surface border border-surface-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-surface-border pb-3">
          <div className="flex items-center space-x-2">
            <Brain className="w-4 h-4 text-indigo-400" />
            <h4 className="text-sm font-semibold text-white">
              UEBA &amp; Machine Learning Intelligence
            </h4>
          </div>
          <span className="text-[11px] font-mono text-indigo-300 bg-indigo-950/60 px-2.5 py-0.5 rounded border border-indigo-800/60">
            Model: {mlMetrics?.model_version || 'ueba-isolation-forest-v1'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-3 bg-gray-900/60 border border-gray-800 rounded-lg">
            <span className="text-[11px] text-gray-400">Total ML Anomalies</span>
            <div className="text-xl font-bold text-white mt-1">
              {mlMetrics?.total_anomalies ?? 0}
            </div>
          </div>
          <div className="p-3 bg-gray-900/60 border border-gray-800 rounded-lg">
            <span className="text-[11px] text-gray-400">High-Risk Anomalies (Score &ge; 80)</span>
            <div className="text-xl font-bold text-red-400 mt-1">
              {mlMetrics?.high_risk_anomalies ?? 0}
            </div>
          </div>
          <div className="p-3 bg-gray-900/60 border border-gray-800 rounded-lg">
            <span className="text-[11px] text-gray-400">Anomalous Identities</span>
            <div className="text-xl font-bold text-indigo-400 mt-1">
              {mlMetrics?.anomalous_principals ?? 0}
            </div>
          </div>
          <div className="p-3 bg-gray-900/60 border border-gray-800 rounded-lg">
            <span className="text-[11px] text-gray-400">Average Anomaly Score</span>
            <div className="text-xl font-bold text-white mt-1">
              {mlMetrics?.avg_anomaly_score ?? 0.0}{' '}
              <span className="text-xs text-gray-500 font-normal">/ 100</span>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Synthetic Telemetry Injection Panel */}
      <div className="bg-surface border border-surface-border rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-surface-border pb-4">
          <div>
            <h4 className="text-sm font-semibold text-white">
              Synthetic Azure Telemetry Generator (Zero-Cloud-Cost)
            </h4>
            <p className="text-xs text-gray-400 mt-1">
              Trigger high-fidelity Azure cloud security attack vectors to test ingestion and storage.
            </p>
          </div>
          <span className="text-xs font-mono text-blue-400 bg-blue-500/10 px-2.5 py-1 rounded-md border border-blue-500/20">
            Phase 1 Testing Suite
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <button
            disabled={isSubmitting}
            onClick={() => handleTriggerScenario('credential_compromise')}
            className="p-4 bg-gray-900/60 hover:bg-gray-800/80 border border-gray-700/60 rounded-xl text-left transition space-y-2 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-red-400">Scenario 1</span>
              <Play className="w-4 h-4 text-gray-500 group-hover:text-red-400 transition" />
            </div>
            <div className="text-sm font-medium text-gray-200">Credential Compromise</div>
            <div className="text-xs text-gray-500 leading-relaxed">
              Brute force / Credential stuffing → MFA fatigue push → Role assignment escalation (Owner).
            </div>
          </button>

          <button
            disabled={isSubmitting}
            onClick={() => handleTriggerScenario('keyvault_exfiltration')}
            className="p-4 bg-gray-900/60 hover:bg-gray-800/80 border border-gray-700/60 rounded-xl text-left transition space-y-2 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-amber-400">Scenario 2</span>
              <Play className="w-4 h-4 text-gray-500 group-hover:text-amber-400 transition" />
            </div>
            <div className="text-sm font-medium text-gray-200">Key Vault Exfiltration</div>
            <div className="text-xs text-gray-500 leading-relaxed">
              Compromised Service Principal → Key Vault discovery → Mass secret retrieval (16 secrets).
            </div>
          </button>

          <button
            disabled={isSubmitting}
            onClick={() => handleTriggerScenario('ransomware')}
            className="p-4 bg-gray-900/60 hover:bg-gray-800/80 border border-gray-700/60 rounded-xl text-left transition space-y-2 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-purple-400">Scenario 3</span>
              <Play className="w-4 h-4 text-gray-500 group-hover:text-purple-400 transition" />
            </div>
            <div className="text-sm font-medium text-gray-200">Ransomware & Evasion</div>
            <div className="text-xs text-gray-500 leading-relaxed">
              Disable Microsoft Defender for Cloud → Mass storage container deletions.
            </div>
          </button>
        </div>

        {triggerStatus && (
          <div className="p-3 bg-blue-950/40 border border-blue-800/50 rounded-lg flex items-center space-x-2 text-xs text-blue-200">
            <CheckCircle2 className="w-4 h-4 text-blue-400 flex-shrink-0" />
            <span className="font-mono">{triggerStatus}</span>
          </div>
        )}
      </div>
    </div>
  );
};
