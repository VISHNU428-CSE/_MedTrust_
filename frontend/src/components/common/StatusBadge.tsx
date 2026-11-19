import React from 'react';
import type { ConsentStatus, RecordType } from '../../types';

interface StatusBadgeProps {
  status?: ConsentStatus | 'SUCCESS' | 'DENIED' | 'VERIFIED' | 'CHECKSUM_MISMATCH' | 'IPFS_UNAVAILABLE' | 'LEDGER_UNAVAILABLE' | string;
  type?: RecordType;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, type, className = '' }) => {
  if (status) {
    let colorClass = 'bg-slate-100 text-slate-700 border-[#E1E7EF]';

    switch (status) {
      case 'ACTIVE':
      case 'SUCCESS':
      case 'VERIFIED':
        colorClass = 'bg-emerald-50 text-[#237A52] border-emerald-200';
        break;
      case 'PENDING':
      case 'IPFS_UNAVAILABLE':
        colorClass = 'bg-amber-50 text-[#9A6700] border-amber-200';
        break;
      case 'REVOKED':
      case 'DENIED':
      case 'CHECKSUM_MISMATCH':
        colorClass = 'bg-rose-50 text-[#B42318] border-rose-200';
        break;
      case 'LEDGER_UNAVAILABLE':
        colorClass = 'bg-slate-100 text-[#B42318] border-slate-300';
        break;
      case 'EXPIRED':
        colorClass = 'bg-slate-100 text-[#5B6675] border-[#E1E7EF]';
        break;
    }

    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold border ${colorClass} ${className}`}>
        {status}
      </span>
    );
  }

  if (type) {
    const label = type.replace('_', ' ');
    let colorClass = 'bg-slate-100 text-[#14263D] border-[#E1E7EF]';

    if (type.includes('IMAGING')) {
      colorClass = 'bg-purple-50 text-purple-700 border-purple-200';
    } else if (type === 'PRESCRIPTION') {
      colorClass = 'bg-teal-50 text-[#147D78] border-teal-200';
    } else if (type === 'LAB_REPORT') {
      colorClass = 'bg-sky-50 text-sky-700 border-sky-200';
    } else if (type === 'GENOMIC_DATA') {
      colorClass = 'bg-indigo-50 text-indigo-700 border-indigo-200';
    } else if (type === 'CLINICAL_SUMMARY') {
      colorClass = 'bg-emerald-50 text-[#237A52] border-emerald-200';
    }

    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border ${colorClass} ${className}`}>
        {label}
      </span>
    );
  }

  return null;
};
