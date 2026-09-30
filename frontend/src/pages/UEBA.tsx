import React, { useState, useEffect } from 'react';
import {
  Brain,
  RefreshCw,
  AlertTriangle,
  User,
  Globe,
  Activity,
  X,
  ChevronRight,
  TrendingUp,
  ShieldAlert,
} from 'lucide-react';

interface DeviationItem {
  observed: number;
  baseline_mean: number;
  baseline_std: number;
  z_score: number;
  robust_z?: number;
  ratio_to_baseline?: number;
}

interface MLAnomaly {
  id: string;
  event_id: string;
  model_version: string;
  anomaly_score: number;
  confidence: number;
  is_anomalous: boolean;
  severity: string;
  reasons: string[];
  summary: string;
  top_deviations: Record<string, DeviationItem>;
  principal_id?: string;
  principal_name?: string;
  caller_ip?: string;
  event_name?: string;
  event_category?: string;
  geo_country?: string;
  feature_contributions?: Record<string, any>;
  created_at: string;
}

interface MLMetrics {
  total_anomalies: number;
  high_risk_anomalies: number;
  anomalous_principals: number;
  avg_anomaly_score: number;
  model_version: string;
  active_features_count: number;
}

export const UEBA: React.FC = () => {
  const [anomalies, setAnomalies] = useState<MLAnomaly[]>([]);
  const [metrics, setMetrics] = useState<MLMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  // Filters
  const [searchPrincipal, setSearchPrincipal] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [minScore, setMinScore] = useState<number>(0);

  // Detail drawer
  const [selectedAnomaly, setSelectedAnomaly] = useState<MLAnomaly | null>(null);
  const [showRawJson, setShowRawJson] = useState<boolean>(false);

  const fetchData = async () => {
    try {
      let url = `/api/v1/ml/anomalies?limit=50&min_score=${minScore}`;
      if (searchPrincipal.trim()) {
        url += `&principal=${encodeURIComponent(searchPrincipal.trim())}`;
      }
      if (severityFilter !== 'all') {
        url += `&severity=${severityFilter}`;
      }

      const [anomRes, metricsRes] = await Promise.all([
        fetch(url),
        fetch('/api/v1/ml/metrics'),
      ]);

      if (anomRes.ok) {
        const data = await anomRes.json();
        setAnomalies(data.items || []);
      }

      if (metricsRes.ok) {
        const mdata = await metricsRes.json();
        setMetrics(mdata);
      }
    } catch (err) {
      console.error('Failed to fetch UEBA data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    if (!autoRefresh) return;
    const interval = setInterval(fetchData, 6000);
    return () => clearInterval(interval);
  }, [autoRefresh, searchPrincipal, severityFilter, minScore]);

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-400 bg-red-950/60 border-red-800';
    if (score >= 65) return 'text-orange-400 bg-orange-950/60 border-orange-800';
    if (score >= 50) return 'text-yellow-400 bg-yellow-950/60 border-yellow-800';
    return 'text-blue-400 bg-blue-950/60 border-blue-800';
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-900/40 text-red-400 border border-red-700/60">CRITICAL</span>;
      case 'high':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-orange-900/40 text-orange-400 border border-orange-700/60">HIGH</span>;
      case 'medium':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-yellow-900/40 text-yellow-400 border border-yellow-700/60">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-blue-900/40 text-blue-400 border border-blue-700/60">LOW</span>;
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between p-5 bg-surface border border-surface-border rounded-xl gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Brain className="w-5 h-5 text-indigo-400" />
            <h2 className="text-lg font-bold text-white tracking-wide">
              User & Entity Behavior Analytics (UEBA)
            </h2>
            <span className="text-[11px] px-2 py-0.5 rounded bg-indigo-900/40 text-indigo-300 border border-indigo-700/60 font-mono">
              {metrics?.model_version || 'ueba-isolation-forest-v1'}
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Unsupervised machine learning anomaly detection and explainable behavioral deviations powered by Isolation Forest.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <label className="flex items-center space-x-2 text-xs text-gray-300 cursor-pointer bg-gray-800/80 px-3 py-1.5 rounded-lg border border-gray-700">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded bg-gray-900 border-gray-700 text-indigo-500 focus:ring-0"
            />
            <span>Auto Refresh</span>
          </label>
          <button
            onClick={fetchData}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-medium border border-gray-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 bg-surface border border-surface-border rounded-xl">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Total Flagged Anomalies</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2">
            {metrics?.total_anomalies ?? 0}
          </div>
          <div className="text-[11px] text-gray-400 mt-1">Actionable outliers flagged by ML</div>
        </div>

        <div className="p-4 bg-surface border border-surface-border rounded-xl">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>High-Risk Anomalies</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400 mt-2">
            {metrics?.high_risk_anomalies ?? 0}
          </div>
          <div className="text-[11px] text-gray-400 mt-1">Score &ge; 80 / Critical priority</div>
        </div>

        <div className="p-4 bg-surface border border-surface-border rounded-xl">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Anomalous Identities</span>
            <User className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2">
            {metrics?.anomalous_principals ?? 0}
          </div>
          <div className="text-[11px] text-gray-400 mt-1">Users &amp; Service Principals</div>
        </div>

        <div className="p-4 bg-surface border border-surface-border rounded-xl">
          <div className="flex items-center justify-between text-gray-400 text-xs">
            <span>Mean Anomaly Score</span>
            <TrendingUp className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white mt-2">
            {metrics?.avg_anomaly_score ?? 0.0}
            <span className="text-xs text-gray-400 font-normal"> / 100</span>
          </div>
          <div className="text-[11px] text-gray-400 mt-1">Across evaluated telemetry</div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center gap-3 p-4 bg-surface border border-surface-border rounded-xl">
        <div className="flex-1 min-w-[200px]">
          <input
            type="text"
            placeholder="Filter by principal email or ID..."
            value={searchPrincipal}
            onChange={(e) => setSearchPrincipal(e.target.value)}
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-indigo-500"
          />
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-gray-400">Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-gray-900 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-gray-400">Min Score:</span>
          <input
            type="number"
            min="0"
            max="100"
            value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
            className="w-16 bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-xs text-white text-center focus:outline-none focus:border-indigo-500"
          />
        </div>

        {(searchPrincipal || severityFilter !== 'all' || minScore > 0) && (
          <button
            onClick={() => {
              setSearchPrincipal('');
              setSeverityFilter('all');
              setMinScore(0);
            }}
            className="px-2.5 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-400 text-xs rounded-lg border border-gray-700"
          >
            Reset Filters
          </button>
        )}
      </div>

      {/* Anomalies Table */}
      <div className="bg-surface border border-surface-border rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-surface-border flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-indigo-400" />
            <h3 className="font-semibold text-sm text-white">Evaluated Telemetry &amp; Anomaly Feed</h3>
          </div>
          <span className="text-xs text-gray-400">Showing {anomalies.length} records</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-gray-900/60 text-gray-400 uppercase text-[10px] tracking-wider border-b border-surface-border">
              <tr>
                <th className="py-3 px-4">Principal Identity</th>
                <th className="py-3 px-4">Anomaly Score</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Primary Explanation / Reasons</th>
                <th className="py-3 px-4">Event Trigger &amp; Source</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border text-gray-300">
              {anomalies.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-gray-500">
                    No ML anomaly scores found matching current filters.
                  </td>
                </tr>
              ) : (
                anomalies.map((a) => (
                  <tr key={a.id} className="hover:bg-gray-800/40 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-medium text-white">
                        {a.principal_name || a.principal_id || 'System / Anonymous'}
                      </div>
                      <div className="text-[10px] text-gray-500 font-mono">
                        {a.principal_id || 'N/A'}
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold border ${getScoreColor(
                          a.anomaly_score
                        )}`}
                      >
                        {a.anomaly_score.toFixed(1)}
                      </span>
                    </td>

                    <td className="py-3 px-4">{getSeverityBadge(a.severity)}</td>

                    <td className="py-3 px-4 max-w-xs truncate">
                      <div className="text-gray-200 truncate">
                        {a.summary || (a.reasons && a.reasons[0]) || 'Baseline normal profile'}
                      </div>
                      {a.reasons && a.reasons.length > 1 && (
                        <div className="text-[10px] text-indigo-400 mt-0.5">
                          +{a.reasons.length - 1} additional deviation(s)
                        </div>
                      )}
                    </td>

                    <td className="py-3 px-4">
                      <div className="text-gray-200">{a.event_name || 'Generic Event'}</div>
                      <div className="text-[10px] text-gray-500 flex items-center space-x-1 mt-0.5">
                        <Globe className="w-3 h-3" />
                        <span>
                          {a.caller_ip || 'N/A'} ({a.geo_country || 'Unknown'})
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-gray-400 font-mono text-[11px]">
                      {new Date(a.created_at).toLocaleTimeString()}
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedAnomaly(a)}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 bg-indigo-900/30 hover:bg-indigo-900/60 text-indigo-300 rounded border border-indigo-700/50 text-[11px] font-medium transition"
                      >
                        <span>Inspect</span>
                        <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Anomaly Inspection Drawer */}
      {selectedAnomaly && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-surface border-l border-surface-border h-full flex flex-col p-6 overflow-y-auto space-y-6">
            {/* Drawer Header */}
            <div className="flex items-center justify-between border-b border-surface-border pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <Brain className="w-5 h-5 text-indigo-400" />
                  <h3 className="font-bold text-white text-base">UEBA Anomaly Inspection</h3>
                </div>
                <p className="text-xs text-gray-400 font-mono mt-0.5">
                  ID: {selectedAnomaly.id}
                </p>
              </div>
              <button
                onClick={() => setSelectedAnomaly(null)}
                className="p-1 text-gray-400 hover:text-white rounded-lg hover:bg-gray-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Score & Risk Banner */}
            <div className="grid grid-cols-3 gap-3 p-4 bg-gray-900/60 border border-gray-800 rounded-xl">
              <div>
                <span className="text-[10px] text-gray-400 uppercase tracking-wider">
                  Anomaly Score
                </span>
                <div className="text-2xl font-black text-white font-mono mt-0.5">
                  {selectedAnomaly.anomaly_score.toFixed(1)}
                  <span className="text-xs text-gray-500 font-normal"> / 100</span>
                </div>
              </div>

              <div>
                <span className="text-[10px] text-gray-400 uppercase tracking-wider">
                  Severity Status
                </span>
                <div className="mt-1">{getSeverityBadge(selectedAnomaly.severity)}</div>
              </div>

              <div>
                <span className="text-[10px] text-gray-400 uppercase tracking-wider">
                  Model Confidence
                </span>
                <div className="text-2xl font-bold text-indigo-400 font-mono mt-0.5">
                  {(selectedAnomaly.confidence * 100).toFixed(0)}%
                </div>
              </div>
            </div>

            {/* Principal & Context */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                Identity &amp; Context
              </h4>
              <div className="p-3.5 bg-gray-900/40 border border-gray-800 rounded-lg text-xs space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-gray-400">Principal Name:</span>
                  <span className="text-white font-medium">
                    {selectedAnomaly.principal_name || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Principal ID:</span>
                  <span className="text-gray-300 font-mono">
                    {selectedAnomaly.principal_id || 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Trigger Event:</span>
                  <span className="text-gray-200">{selectedAnomaly.event_name || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Caller IP / Geo:</span>
                  <span className="text-gray-300">
                    {selectedAnomaly.caller_ip || 'N/A'} ({selectedAnomaly.geo_country || 'Unknown'})
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Model Version:</span>
                  <span className="text-indigo-300 font-mono">{selectedAnomaly.model_version}</span>
                </div>
              </div>
            </div>

            {/* Explainable Reasons */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center space-x-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
                <span>Explainable Anomaly Reasons</span>
              </h4>
              <div className="space-y-2">
                {selectedAnomaly.reasons && selectedAnomaly.reasons.length > 0 ? (
                  selectedAnomaly.reasons.map((r, i) => (
                    <div
                      key={i}
                      className="p-3 bg-orange-950/20 border border-orange-800/40 rounded-lg text-xs text-orange-200 flex items-start space-x-2"
                    >
                      <span className="font-bold text-orange-400 mt-0.5">•</span>
                      <span>{r}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-gray-500 italic">No elevated deviations identified.</p>
                )}
              </div>
            </div>

            {/* Top Behavioral Deviations */}
            {selectedAnomaly.top_deviations && Object.keys(selectedAnomaly.top_deviations).length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                  Top Statistical Deviations
                </h4>
                <div className="border border-gray-800 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-gray-900 text-gray-400 text-[10px] uppercase">
                      <tr>
                        <th className="py-2 px-3">Feature</th>
                        <th className="py-2 px-3">Observed</th>
                        <th className="py-2 px-3">Baseline Mean</th>
                        <th className="py-2 px-3">Z-Score</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800 text-gray-300">
                      {Object.entries(selectedAnomaly.top_deviations).map(([fname, dev]) => (
                        <tr key={fname} className="hover:bg-gray-800/30">
                          <td className="py-2 px-3 font-mono text-[11px] text-gray-200">
                            {fname}
                          </td>
                          <td className="py-2 px-3 font-mono text-white">
                            {dev.observed}
                          </td>
                          <td className="py-2 px-3 font-mono text-gray-400">
                            {dev.baseline_mean}
                          </td>
                          <td className="py-2 px-3 font-mono font-bold text-orange-400">
                            +{dev.z_score}σ
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Raw JSON Feature Contributions */}
            <div className="space-y-2 pt-2 border-t border-surface-border">
              <button
                onClick={() => setShowRawJson(!showRawJson)}
                className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center space-x-1"
              >
                <span>{showRawJson ? 'Hide' : 'View'} Raw Feature Contributions JSON</span>
              </button>
              {showRawJson && (
                <pre className="p-3 bg-black/60 border border-gray-800 rounded-lg text-[10px] font-mono text-gray-300 overflow-x-auto max-h-60">
                  {JSON.stringify(selectedAnomaly.feature_contributions, null, 2)}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
