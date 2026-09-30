import React, { useState, useEffect } from 'react';
import {
  Radio,
  RefreshCw,
  AlertTriangle,
  Clock,
  User,
  Globe,
  Database,
  ShieldAlert,
} from 'lucide-react';

interface NormalizedEvent {
  id: string;
  event_id: string;
  timestamp: string;
  source: string;
  event_category: string;
  event_name: string;
  principal_name?: string;
  caller_ip?: string;
  target_resource_name?: string;
  action_status: string;
  geo_country?: string;
}

interface ThreatDetection {
  id: string;
  rule_code: string;
  rule_title: string;
  severity: string;
  alert_summary: string;
  principal_name?: string;
  caller_ip?: string;
  detected_at: string;
}

export const LiveMonitor: React.FC = () => {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [detections, setDetections] = useState<ThreatDetection[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [totalDetections, setTotalDetections] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  const fetchData = async () => {
    try {
      const [eventsRes, detectionsRes] = await Promise.all([
        fetch('/api/v1/events?limit=30'),
        fetch('/api/v1/detections?limit=15'),
      ]);

      if (eventsRes.ok) {
        const eventsData = await eventsRes.json();
        setEvents(eventsData.items || []);
        setTotalEvents(eventsData.total || 0);
      }

      if (detectionsRes.ok) {
        const detectionsData = await detectionsRes.json();
        setDetections(detectionsData.items || []);
        setTotalDetections(detectionsData.total || 0);
      }
    } catch (err) {
      console.error('Failed to fetch live monitor telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    if (!autoRefresh) return;
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const getSeverityBadge = (sev: string) => {
    const s = sev.toUpperCase();
    if (s === 'CRITICAL') return 'bg-red-500/20 text-red-400 border-red-500/30';
    if (s === 'HIGH') return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    if (s === 'MEDIUM') return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Top Header & Telemetry Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between p-4 bg-surface border border-surface-border rounded-xl gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Radio className="w-5 h-5 text-blue-400 animate-pulse" />
            <h3 className="font-semibold text-white">Live Telemetry & Alert Stream</h3>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Real-time feed of normalized Azure security events and rule-based detections.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <label className="flex items-center space-x-2 text-xs text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded bg-gray-900 border-gray-700 text-blue-500 focus:ring-0"
            />
            <span>Auto-poll (4s)</span>
          </label>

          <button
            onClick={fetchData}
            className="flex items-center space-x-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-medium border border-gray-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* KPI Counters */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-surface border border-surface-border rounded-xl p-4 flex items-center space-x-4">
          <div className="p-3 bg-blue-500/10 text-blue-400 rounded-lg border border-blue-500/20">
            <Database className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-white">{totalEvents}</div>
            <div className="text-xs text-gray-400">Total Normalized Events Ingested</div>
          </div>
        </div>

        <div className="bg-surface border border-surface-border rounded-xl p-4 flex items-center space-x-4">
          <div className="p-3 bg-red-500/10 text-red-400 rounded-lg border border-red-500/20">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="text-2xl font-bold text-white">{totalDetections}</div>
            <div className="text-xs text-gray-400">Total Threat Detections Triggered</div>
          </div>
        </div>
      </div>

      {/* Recent Detections Banner (if any) */}
      {detections.length > 0 && (
        <div className="bg-surface border border-red-500/30 rounded-xl p-5 space-y-3">
          <div className="flex items-center space-x-2 text-red-400 font-semibold text-sm">
            <AlertTriangle className="w-4 h-4" />
            <span>Active Triggered Threat Alerts ({detections.length})</span>
          </div>

          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {detections.map((d) => (
              <div
                key={d.id}
                className="p-3 bg-red-950/20 border border-red-900/40 rounded-lg flex flex-col md:flex-row md:items-center justify-between text-xs gap-2"
              >
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-0.5 rounded font-mono font-bold border ${getSeverityBadge(d.severity)}`}>
                    {d.severity}
                  </span>
                  <span className="font-semibold text-gray-200">{d.rule_code}:</span>
                  <span className="text-gray-300">{d.alert_summary}</span>
                </div>
                <div className="flex items-center space-x-3 text-gray-500 font-mono text-[11px] flex-shrink-0">
                  <span>{new Date(d.detected_at).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Events Table */}
      <div className="bg-surface border border-surface-border rounded-xl overflow-hidden">
        <div className="p-4 border-b border-surface-border flex items-center justify-between">
          <h4 className="text-sm font-semibold text-white">Recent Normalized Telemetry Feed</h4>
          <span className="text-xs text-gray-500 font-mono">Showing {events.length} most recent</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-gray-900/80 text-gray-400 uppercase font-mono tracking-wider border-b border-surface-border">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Event / Action</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Principal</th>
                <th className="py-3 px-4">Caller IP</th>
                <th className="py-3 px-4">Target Resource</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border font-mono text-gray-300">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-gray-500 font-sans">
                    No telemetry events received yet. Trigger a synthetic scenario from the Dashboard.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-gray-800/40 transition">
                    <td className="py-2.5 px-4 text-gray-400 flex items-center gap-1.5 whitespace-nowrap">
                      <Clock className="w-3.5 h-3.5 text-gray-500" />
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-white">
                      {ev.event_name}
                    </td>
                    <td className="py-2.5 px-4 text-blue-400">
                      {ev.event_category}
                    </td>
                    <td className="py-2.5 px-4 text-gray-300 truncate max-w-[180px]" title={ev.principal_name}>
                      <span className="flex items-center gap-1">
                        <User className="w-3.5 h-3.5 text-gray-500" />
                        {ev.principal_name || 'System'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-gray-400 whitespace-nowrap">
                      <span className="flex items-center gap-1">
                        <Globe className="w-3 h-3 text-gray-500" />
                        {ev.caller_ip || 'N/A'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-gray-400 truncate max-w-[180px]" title={ev.target_resource_name}>
                      {ev.target_resource_name || 'Azure Resource'}
                    </td>
                    <td className="py-2.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                          ev.action_status.toLowerCase() === 'success'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            : 'bg-red-500/10 text-red-400 border-red-500/20'
                        }`}
                      >
                        {ev.action_status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
