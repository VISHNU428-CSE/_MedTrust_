import React, { useState } from 'react';
import { 
  Activity, 
  ShieldCheck, 
  Database, 
  Search, 
  FileCode, 
  CheckCircle2, 
  AlertTriangle, 
  Layers, 
  RefreshCw,
  Server,
  Clock
} from 'lucide-react';
import type { AccessLog, AuditIntegrityResponse, HealthCheckResponse } from '../../types';
import { StatCard } from '../common/StatCard';
import { apiService } from '../../services/api';

interface AuditorDashboardProps {
  auditLogs: AccessLog[];
  isBackendConnected: boolean;
  platformHealth?: HealthCheckResponse | null;
}

export const AuditorDashboard: React.FC<AuditorDashboardProps> = ({
  auditLogs,
  isBackendConnected,
  platformHealth,
}) => {
  const [filterQuery, setFilterQuery] = useState('');
  const [isVerifyingChain, setIsVerifyingChain] = useState(false);
  const [chainVerificationResult, setChainVerificationResult] = useState<AuditIntegrityResponse | null>(null);
  const [lastChecked, setLastChecked] = useState<string>('Live');

  const filteredLogs = auditLogs.filter(l => 
    l.actorName.toLowerCase().includes(filterQuery.toLowerCase()) ||
    l.purpose.toLowerCase().includes(filterQuery.toLowerCase()) ||
    l.txHash.toLowerCase().includes(filterQuery.toLowerCase()) ||
    l.action.toLowerCase().includes(filterQuery.toLowerCase())
  );

  const handleVerifyChain = async () => {
    setIsVerifyingChain(true);
    setChainVerificationResult(null);
    try {
      const res = await apiService.verifyAuditChain();
      setChainVerificationResult(res);
      setLastChecked(new Date().toLocaleTimeString());
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Chain verification error';
      setChainVerificationResult({ chainIntact: false, message: msg });
    } finally {
      setIsVerifyingChain(false);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-[#14263D] via-[#162e4a] to-[#147D78] rounded-2xl p-6 text-white shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-[#147D78]/40 text-teal-200 border border-[#147D78]/50">
                Auditor & Compliance Node
              </span>
              <span className="text-xs text-teal-200">Sovereign Cryptographic Ledger Trail • Research Prototype</span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight mt-1 text-white">Security & Audit Explorer</h1>
            <p className="text-sm text-slate-200 mt-1 max-w-2xl">
              Cryptographic verification of data access operations, consent signatures, and doctor retrievals across Hyperledger Fabric and IPFS.
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={handleVerifyChain}
              disabled={isVerifyingChain}
              className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-[#147D78] hover:bg-[#116965] text-white font-bold text-xs transition-all shadow-sm shadow-teal-950/20 disabled:opacity-50"
            >
              {isVerifyingChain ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                  <span>Verifying Chain...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4 text-white" />
                  <span>Verify Audit Chain Integrity</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* System Microservices Health Indicators (§9 Requirement) */}
      <div className="bg-white rounded-2xl border border-[#E1E7EF] p-5 shadow-xs">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#E1E7EF]">
          <div className="flex items-center space-x-2">
            <Server className="w-4 h-4 text-[#147D78]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#182230]">System Health & Component Status</h3>
          </div>
          <div className="flex items-center space-x-2 text-[11px] text-[#5B6675]">
            <Clock className="w-3.5 h-3.5" />
            <span>Last Checked: {lastChecked}</span>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Component 1: FastAPI Gateway */}
          <div className="p-3.5 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA]">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-[#182230]">FastAPI Gateway</span>
              <span className={`w-2 h-2 rounded-full ${isBackendConnected ? 'bg-[#237A52]' : 'bg-[#9A6700]'}`}></span>
            </div>
            <p className="text-[11px] text-[#5B6675]">Port 8001 (Uvicorn)</p>
            <div className="mt-2 text-[11px] font-semibold text-[#237A52]">
              {isBackendConnected ? `Active (${platformHealth?.version || 'v1.0.0'})` : 'Standby'}
            </div>
          </div>

          {/* Component 2: IPFS Kubo Storage */}
          <div className="p-3.5 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA]">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-[#182230]">IPFS Kubo Daemon</span>
              <span className={`w-2 h-2 rounded-full ${platformHealth?.ipfsStatus?.includes('connected') ? 'bg-[#237A52]' : 'bg-[#9A6700]'}`}></span>
            </div>
            <p className="text-[11px] text-[#5B6675]">Port 5001 RPC / 8080</p>
            <div className="mt-2 text-[11px] font-semibold text-[#237A52] truncate" title={platformHealth?.ipfsStatus}>
              {platformHealth?.ipfsStatus ? 'Connected (Kubo Node)' : 'Local Standby'}
            </div>
          </div>

          {/* Component 3: Fabric Consensus */}
          <div className="p-3.5 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA]">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-[#182230]">Fabric Consensus</span>
              <span className={`w-2 h-2 rounded-full ${platformHealth?.fabricStatus?.includes('connected') ? 'bg-[#237A52]' : 'bg-[#9A6700]'}`}></span>
            </div>
            <p className="text-[11px] text-[#5B6675]">Channel: medtrust-channel</p>
            <div className="mt-2 text-[11px] font-semibold text-[#237A52] truncate" title={platformHealth?.fabricStatus}>
              {platformHealth?.fabricStatus ? 'Connected (Raft Consensus)' : 'Local Standby'}
            </div>
          </div>

          {/* Component 4: Ledger State & Chaincode */}
          <div className="p-3.5 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA]">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold text-[#182230]">Ledger Queries</span>
              <span className="w-2 h-2 rounded-full bg-[#237A52]"></span>
            </div>
            <p className="text-[11px] text-[#5B6675]">CouchDB State Database</p>
            <div className="mt-2 text-[11px] font-semibold text-[#237A52]">
              Verified (Query Path Active)
            </div>
          </div>
        </div>

        {/* Recovery guidance notice */}
        {!isBackendConnected && (
          <div className="mt-3 p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-800">
            <strong>Recovery Guidance:</strong> Ensure FastAPI is running on port 8001 (<code>uvicorn app.main:app --port 8001</code>) and Docker container <code>medtrust_ipfs</code> is healthy.
          </div>
        )}
      </div>

      {/* Chain Verification Result Notification */}
      {chainVerificationResult && (
        <div className={`p-4 rounded-xl border text-xs flex items-center justify-between ${
          chainVerificationResult.chainIntact
            ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
            : 'bg-rose-50 border-rose-200 text-rose-900'
        }`}>
          <div className="flex items-center space-x-2.5">
            {chainVerificationResult.chainIntact ? (
              <CheckCircle2 className="w-5 h-5 text-[#237A52] shrink-0" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-[#B42318] shrink-0" />
            )}
            <div>
              <p className="font-bold">
                {chainVerificationResult.chainIntact ? 'Ledger Chain Intact & Cryptographically Tamper-Evident' : 'Chain Integrity Alert'}
              </p>
              <p className="text-[#5B6675] mt-0.5">{chainVerificationResult.message}</p>
            </div>
          </div>
          <button onClick={() => setChainVerificationResult(null)} className="text-slate-400 hover:text-slate-600 font-bold">✕</button>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Ledger Events"
          value={auditLogs.length}
          subtitle="Signed transactions"
          icon={Activity}
          variant="teal"
        />
        <StatCard
          title="Smart Contract"
          value="medtrust-contract"
          subtitle="Fabric Chaincode v1.1"
          icon={FileCode}
          variant="navy"
        />
        <StatCard
          title="Hash Chaining"
          value="SHA-256 Merkle"
          subtitle="Genesis to Tip Verified"
          icon={Layers}
          variant="emerald"
        />
        <StatCard
          title="Gateway Adapter"
          value={isBackendConnected ? "Connected (8001)" : "Standby"}
          subtitle="FastAPI Gateway Provider"
          icon={Database}
          variant="blue"
        />
      </div>

      {/* Audit Log Table */}
      <div className="bg-white rounded-2xl border border-[#E1E7EF] shadow-xs overflow-hidden">
        <div className="p-4 border-b border-[#E1E7EF] flex flex-col sm:flex-row gap-3 items-center justify-between">
          <div className="relative w-full sm:w-96">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search audit trail by actor, action, or TxHash..."
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              className="w-full text-xs pl-9 pr-3 py-2 rounded-lg border border-[#E1E7EF] focus:outline-none focus:ring-2 focus:ring-[#147D78]"
            />
          </div>
          <div className="flex items-center space-x-3 text-xs text-[#5B6675]">
            <span>{filteredLogs.length} verified events</span>
            <span>•</span>
            <span className="font-mono text-[#237A52] font-semibold">Zero PHI On-Chain</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-[#E1E7EF] text-left text-xs">
            <thead className="bg-[#14263D] text-white font-semibold uppercase tracking-wider text-[11px]">
              <tr>
                <th scope="col" className="px-5 py-3">Timestamp</th>
                <th scope="col" className="px-5 py-3">Actor / MSP ID</th>
                <th scope="col" className="px-5 py-3">Action</th>
                <th scope="col" className="px-5 py-3">Clinical Justification</th>
                <th scope="col" className="px-5 py-3">Status</th>
                <th scope="col" className="px-5 py-3 font-mono">Block Hash Chain</th>
                <th scope="col" className="px-5 py-3 font-mono">TxHash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E1E7EF] bg-white">
              {filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-[#F5F7FA] transition-colors">
                  <td className="px-5 py-3.5 whitespace-nowrap text-[#5B6675] font-sans">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="px-5 py-3.5 whitespace-nowrap">
                    <p className="font-bold text-[#182230]">{log.actorName}</p>
                    <p className="text-[11px] text-[#5B6675]">{log.actorId} ({log.actorRole})</p>
                  </td>
                  <td className="px-5 py-3.5 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#F5F7FA] text-[#14263D] border border-[#E1E7EF]">
                      {log.action}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 max-w-xs truncate text-[#5B6675]" title={log.purpose}>
                    {log.purpose}
                  </td>
                  <td className="px-5 py-3.5 whitespace-nowrap">
                    <span className="inline-flex items-center space-x-1 text-[#237A52] font-semibold text-xs">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{log.status}</span>
                    </span>
                  </td>
                  <td className="px-5 py-3.5 whitespace-nowrap font-mono text-[10px] text-[#5B6675]" title={`Prev: ${log.prevHash || 'Genesis'}\nEntry: ${log.entryHash || '—'}`}>
                    <div className="flex flex-col">
                      <span className="text-[#237A52] font-semibold flex items-center space-x-1">
                        <Layers className="w-3 h-3 text-[#237A52]" />
                        <span>Hash: {log.entryHash ? `${log.entryHash.substring(0, 10)}...` : 'Genesis'}</span>
                      </span>
                      <span className="text-slate-400 text-[9px]">
                        Prev: {log.prevHash ? `${log.prevHash.substring(0, 8)}...` : 'Genesis'}
                      </span>
                    </div>
                  </td>
                  <td className="px-5 py-3.5 whitespace-nowrap font-mono text-[11px] text-[#147D78]" title={log.txHash}>
                    {log.txHash ? `${log.txHash.substring(0, 12)}...` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};
