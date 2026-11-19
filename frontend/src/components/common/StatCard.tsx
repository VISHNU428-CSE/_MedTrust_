import React from 'react';
import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'blue' | 'emerald' | 'amber' | 'purple' | 'rose' | 'teal' | 'navy';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'teal',
}) => {
  const colorMap = {
    teal: {
      bg: 'bg-teal-50',
      text: 'text-[#147D78]',
      border: 'border-teal-200',
    },
    navy: {
      bg: 'bg-slate-100',
      text: 'text-[#14263D]',
      border: 'border-slate-300',
    },
    emerald: {
      bg: 'bg-emerald-50',
      text: 'text-[#237A52]',
      border: 'border-emerald-200',
    },
    amber: {
      bg: 'bg-amber-50',
      text: 'text-[#9A6700]',
      border: 'border-amber-200',
    },
    rose: {
      bg: 'bg-rose-50',
      text: 'text-[#B42318]',
      border: 'border-rose-200',
    },
    blue: {
      bg: 'bg-sky-50',
      text: 'text-sky-700',
      border: 'border-sky-200',
    },
    purple: {
      bg: 'bg-purple-50',
      text: 'text-purple-700',
      border: 'border-purple-200',
    },
  };

  const theme = colorMap[variant] || colorMap.teal;

  return (
    <div className="bg-white rounded-2xl border border-[#E1E7EF] p-5 shadow-xs hover:shadow-md transition-shadow">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-bold uppercase tracking-wider text-[#5B6675]">{title}</p>
          <p className="mt-1 text-2xl font-extrabold text-[#182230]">{value}</p>
          {subtitle && <p className="mt-1 text-xs text-[#5B6675]">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-xl ${theme.bg} ${theme.text} ${theme.border} border`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
