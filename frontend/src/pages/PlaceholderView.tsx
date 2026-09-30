import React from 'react';
import { Construction } from 'lucide-react';

interface PlaceholderViewProps {
  title: string;
  phase: string;
  description: string;
}

export const PlaceholderView: React.FC<PlaceholderViewProps> = ({
  title,
  phase,
  description,
}) => {
  return (
    <div className="p-8 max-w-5xl mx-auto flex flex-col items-center justify-center min-h-[60vh] text-center space-y-4">
      <div className="p-4 bg-gray-800/60 border border-gray-700 rounded-2xl text-blue-400">
        <Construction className="w-10 h-10" />
      </div>
      <h3 className="text-xl font-bold text-white">{title}</h3>
      <p className="text-sm text-gray-400 max-w-md">{description}</p>
      <span className="px-3 py-1 text-xs font-mono rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
        Scheduled for {phase}
      </span>
    </div>
  );
};
