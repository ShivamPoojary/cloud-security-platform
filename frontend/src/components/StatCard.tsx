import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  subtitle?: string;
  variant?: 'default' | 'danger' | 'warning' | 'success';
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  icon,
  subtitle,
  variant = 'default',
}) => {
  const variantStyles = {
    default: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    danger: 'text-red-400 bg-red-500/10 border-red-500/20',
    warning: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    success: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  };

  return (
    <div className="bg-surface border border-surface-border rounded-xl p-5 flex flex-col justify-between">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-gray-400">{label}</span>
        <div className={`p-2 rounded-lg border ${variantStyles[variant]}`}>
          {icon}
        </div>
      </div>
      <div className="mt-4">
        <div className="text-2xl font-bold text-white">{value}</div>
        {subtitle && (
          <p className="text-xs text-gray-500 mt-1">{subtitle}</p>
        )}
      </div>
    </div>
  );
};
