import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  RefreshCw,
  Power,
  Flame,
  Layers,
} from 'lucide-react';

interface DetectionRule {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  mitre_tactic: string;
  mitre_technique_id: string;
  description: string;
  rule_logic: {
    type?: string;
    threshold?: number;
    window_seconds?: number;
    filter?: Record<string, any>;
  };
  is_active: boolean;
  detection_count: number;
}

export const DetectionRules: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [togglingRule, setTogglingRule] = useState<string | null>(null);

  const fetchRules = async () => {
    try {
      const res = await fetch('/api/v1/rules');
      if (res.ok) {
        const data = await res.json();
        setRules(data);
      }
    } catch (err) {
      console.error('Failed to fetch detection rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggle = async (ruleId: string) => {
    setTogglingRule(ruleId);
    try {
      const res = await fetch(`/api/v1/rules/${ruleId}/toggle`, {
        method: 'PATCH',
      });
      if (res.ok) {
        const updated = await res.json();
        setRules((prev) =>
          prev.map((r) =>
            r.rule_id === ruleId ? { ...r, is_active: updated.is_active } : r
          )
        );
      }
    } catch (err) {
      console.error(`Failed to toggle rule ${ruleId}:`, err);
    } finally {
      setTogglingRule(null);
    }
  };

  const getSeverityBadge = (sev: string) => {
    const s = sev.toUpperCase();
    if (s === 'CRITICAL') return 'bg-red-500/20 text-red-400 border-red-500/30';
    if (s === 'HIGH') return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    if (s === 'MEDIUM') return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between p-4 bg-surface border border-surface-border rounded-xl gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
            <h3 className="font-semibold text-white">Detection Rule Catalog</h3>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Stateless patterns and stateful sliding-window rules mapped to MITRE ATT&CK for Cloud.
          </p>
        </div>

        <button
          onClick={fetchRules}
          className="flex items-center space-x-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-xs font-medium border border-gray-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Rules</span>
        </button>
      </div>

      {/* Rules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map((rule) => {
          const ruleType = rule.rule_logic?.type || 'stateless_pattern';
          const isThreshold = ruleType.includes('threshold');

          return (
            <div
              key={rule.id}
              className={`bg-surface border rounded-xl p-5 flex flex-col justify-between space-y-4 transition ${
                rule.is_active
                  ? 'border-surface-border hover:border-gray-700'
                  : 'border-gray-800/60 opacity-60'
              }`}
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                      {rule.rule_id}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${getSeverityBadge(rule.severity)}`}>
                      {rule.severity}
                    </span>
                  </div>

                  <button
                    disabled={togglingRule === rule.rule_id}
                    onClick={() => handleToggle(rule.rule_id)}
                    className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition border ${
                      rule.is_active
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                        : 'bg-gray-800 text-gray-400 border-gray-700 hover:bg-gray-700'
                    }`}
                  >
                    <Power className="w-3.5 h-3.5" />
                    <span>{rule.is_active ? 'Active' : 'Disabled'}</span>
                  </button>
                </div>

                <div>
                  <h4 className="font-semibold text-sm text-white">{rule.title}</h4>
                  <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                    {rule.description}
                  </p>
                </div>
              </div>

              {/* Badges & Telemetry Stats */}
              <div className="pt-3 border-t border-surface-border space-y-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2 py-0.5 bg-gray-900 text-gray-300 rounded font-mono text-[11px] border border-gray-800 flex items-center gap-1">
                    <Layers className="w-3 h-3 text-gray-500" />
                    {rule.mitre_tactic} ({rule.mitre_technique_id})
                  </span>

                  <span className="px-2 py-0.5 bg-gray-900 text-gray-300 rounded font-mono text-[11px] border border-gray-800">
                    {isThreshold
                      ? `Threshold: ≥${rule.rule_logic.threshold || 5} in ${rule.rule_logic.window_seconds || 180}s`
                      : 'Stateless Event Pattern'}
                  </span>
                </div>

                <div className="flex items-center justify-between text-gray-400 text-[11px] pt-1">
                  <span className="flex items-center gap-1 font-mono">
                    <Flame className="w-3.5 h-3.5 text-orange-400" />
                    Detections Triggered:
                  </span>
                  <span className="font-mono font-bold text-white bg-gray-800 px-2 py-0.5 rounded">
                    {rule.detection_count}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
