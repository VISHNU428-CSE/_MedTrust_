import React, { useState } from 'react';
import {
  ShieldCheck,
  Database,
  Lock,
  Server,
  ArrowRight,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Cpu,
  Layers,
  FileCheck,
  Stethoscope,
  User,
  Activity,
  LogIn,
  ShieldAlert
} from 'lucide-react';
import type { HealthCheckResponse, AppView, UserRole } from '../../types';

interface LandingPageProps {
  onNavigate?: (view: AppView) => void;
  onNavigateToApp?: (role: UserRole) => void;
  onOpenAuth?: (mode: 'login' | 'register' | 'register-patient' | 'register-doctor', role?: UserRole) => void;
  isBackendConnected: boolean;
  platformHealth?: HealthCheckResponse | null;
  backendVersion?: string | null;
}

export const LandingPage: React.FC<LandingPageProps> = ({
  onNavigate,
  onNavigateToApp: _onNavigateToApp,
  onOpenAuth,
  isBackendConnected,
  platformHealth,
  backendVersion,
}) => {
  const [selectedStep, setSelectedStep] = useState<number>(0);

  const handleAuthNav = (mode: 'login' | 'register' | 'register-patient' | 'register-doctor' = 'login', role?: UserRole) => {
    if (onOpenAuth) {
      onOpenAuth(mode, role);
    } else if (onNavigate) {
      onNavigate('LOGIN');
    }
  };

  const consentSteps = [
    {
      title: '1. Clinician Requests Access',
      actor: 'Doctor (Dr. Marcus Sterling)',
      roleBadge: 'DOCTOR',
      action: 'Submits granular access request',
      details: 'Physician specifies patient ID, clinical purpose, required record types (e.g. LAB_REPORT, IMAGING_MRI), and duration (e.g. 30 days). No access is granted without explicit patient endorsement.',
      cryptoNote: 'Generates on-chain request proposal registered with Hyperledger Fabric Gateway.',
      badgeColor: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    },
    {
      title: '2. Patient Evaluates & Signs',
      actor: 'Patient (Sovereign Vault)',
      roleBadge: 'PATIENT',
      action: 'Reviews scope & authorizes consent',
      details: 'Patient receives real-time notification in their Sovereign Vault. Patient evaluates the clinical purpose, selectively filters allowed record types, and confirms consent transaction on the Fabric ledger.',
      cryptoNote: 'Chaincode commits ACTIVE consent status to immutable state with cryptographic timestamp & TxID.',
      badgeColor: 'border-indigo-200 bg-indigo-50 text-indigo-800',
    },
    {
      title: '3. Verified Retrieval via Smart Contract',
      actor: 'Decentralized Gateway & IPFS',
      roleBadge: 'GATEWAY',
      action: 'Enforces consent rule & checks SHA-256',
      details: 'Doctor queries the record. FastAPI backend calls Fabric smart contract to verify active consent. Upon authorization, the encrypted AES-256-GCM ciphertext is fetched from IPFS Kubo, verified against ledger SHA-256 checksum, and decrypted in-memory.',
      cryptoNote: 'Dual-verification ensures tamper-evident integrity before clinician inspects any diagnostic data.',
      badgeColor: 'border-teal-200 bg-teal-50 text-teal-800',
    },
    {
      title: '4. Instant Atomic Revocation',
      actor: 'Patient (Sovereign Vault)',
      roleBadge: 'PATIENT',
      action: 'Revokes access with immediate effect',
      details: 'Patient can revoke consent at any time. The revocation transaction is immediately written to Fabric ledger state. Future retrieval attempts are denied in real-time by the smart contract rule evaluation engine.',
      cryptoNote: 'Revocation Invariant: Future requests fail instantly, while past authorized downloads remain cryptographically logged.',
      badgeColor: 'border-rose-200 bg-rose-50 text-rose-800',
    },
  ];

  return (
    <div className="space-y-12 pb-12">
      
      {/* Hero Section */}
      <section className="relative overflow-hidden rounded-3xl bg-[#14263D] text-white p-8 sm:p-12 shadow-md border border-[#E1E7EF]/20">
        <div className="relative z-10 max-w-4xl space-y-6">
          
          {/* Eyebrow Badge */}
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-[#147D78]/20 border border-[#147D78]/50 text-teal-300 text-xs font-semibold">
            <ShieldCheck className="w-4 h-4 text-[#147D78]" />
            <span>Decentralized Health Records &amp; Sovereign Consent Ledger</span>
          </div>

          {/* Main Title */}
          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight leading-tight text-white">
            Sovereign Health Data Sharing with Cryptographic Proof
          </h1>

          {/* Value Proposition */}
          <p className="text-base sm:text-lg text-slate-300 max-w-3xl leading-relaxed">
            MedTrust eliminates central single-points-of-failure and unauthorized data harvesting. 
            Patients retain cryptographic ownership of diagnostic records through client-side AES-256-GCM encryption, 
            IPFS content-addressable storage, and Hyperledger Fabric immutable consent smart contracts.
          </p>

          {/* Unified Call-to-Action Buttons */}
          <div className="pt-2 flex flex-wrap gap-3 sm:gap-4 items-center">
            <button
              onClick={() => handleAuthNav('login')}
              className="inline-flex items-center space-x-2 px-6 py-3.5 rounded-xl bg-[#147D78] hover:bg-[#116964] text-white font-bold text-sm transition-all shadow-sm cursor-pointer"
            >
              <LogIn className="w-4 h-4 text-teal-200" />
              <span>Sign In to MedTrust</span>
              <ArrowRight className="w-4 h-4 ml-1" />
            </button>

            <button
              onClick={() => handleAuthNav('register-patient')}
              className="inline-flex items-center space-x-2 px-6 py-3.5 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-semibold text-sm transition-all cursor-pointer"
            >
              <User className="w-4 h-4 text-teal-300" />
              <span>Register as Patient</span>
            </button>

            <button
              onClick={() => handleAuthNav('register-doctor')}
              className="inline-flex items-center space-x-2 px-6 py-3.5 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-semibold text-sm transition-all cursor-pointer"
            >
              <Stethoscope className="w-4 h-4 text-teal-300" />
              <span>Apply as Clinician</span>
            </button>
          </div>

          {/* Quick Role Portal Access in Hero */}
          <div className="pt-1 flex items-center gap-2 flex-wrap text-xs text-slate-300">
            <span className="text-[11px] font-semibold text-slate-400">Institutional Access:</span>
            <button
              onClick={() => handleAuthNav('login', 'PATIENT')}
              className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 border border-white/20 text-white font-medium text-xs transition-colors cursor-pointer"
            >
              <User className="w-3.5 h-3.5 text-indigo-300" />
              <span>Patient Vault</span>
            </button>
            <button
              onClick={() => handleAuthNav('login', 'DOCTOR')}
              className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 border border-white/20 text-white font-medium text-xs transition-colors cursor-pointer"
            >
              <Stethoscope className="w-3.5 h-3.5 text-teal-300" />
              <span>Doctor Portal</span>
            </button>
            <button
              onClick={() => handleAuthNav('login', 'ADMIN')}
              className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 border border-white/20 text-white font-medium text-xs transition-colors cursor-pointer"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-indigo-300" />
              <span>Admin Console</span>
            </button>
            <button
              onClick={() => handleAuthNav('login', 'AUDITOR')}
              className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 border border-white/20 text-white font-medium text-xs transition-colors cursor-pointer"
            >
              <Activity className="w-3.5 h-3.5 text-amber-300" />
              <span>Auditor Ledger</span>
            </button>
          </div>

          {/* Live Infrastructure Telemetry Strip */}
          <div className="pt-4 border-t border-white/10 flex flex-wrap items-center gap-4 sm:gap-6 text-xs text-slate-300">
            <div className="flex items-center space-x-2">
              <span className={`w-2.5 h-2.5 rounded-full ${isBackendConnected ? 'bg-[#237A52] animate-pulse' : 'bg-[#9A6700]'}`}></span>
              <span className="font-medium">
                FastAPI Gateway: {isBackendConnected ? `Live (${backendVersion || 'v1.0.0'})` : 'Standby / Local'}
              </span>
            </div>

            <div className="flex items-center space-x-2">
              <Database className="w-3.5 h-3.5 text-teal-400" />
              <span>
                {platformHealth?.ipfsStatus ? `IPFS: ${platformHealth.ipfsStatus.split(' ')[0]}` : 'IPFS Kubo Pinned'}
              </span>
            </div>

            <div className="flex items-center space-x-2">
              <Server className="w-3.5 h-3.5 text-indigo-400" />
              <span>
                {platformHealth?.fabricStatus 
                  ? `Fabric: ${platformHealth.fabricStatus.split(',')[0].replace('connected (', '')}` 
                  : 'Hyperledger Fabric v2.5'}
              </span>
            </div>

            <div className="flex items-center space-x-2">
              <Lock className="w-3.5 h-3.5 text-amber-400" />
              <span>AES-256-GCM Zero-PHI</span>
            </div>
          </div>

        </div>
      </section>

      {/* 3 Core Architectural Pillars */}
      <section className="space-y-6">
        <div className="text-center max-w-2xl mx-auto space-y-2">
          <h2 className="text-2xl sm:text-3xl font-bold text-[#182230] tracking-tight">
            How MedTrust Secures Health Records
          </h2>
          <p className="text-sm text-[#5B6675]">
            A layered cryptographic protocol delivering mathematical access enforcement rather than trust in a central database administrator.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          
          {/* Pillar 1 */}
          <div className="bg-white p-6 rounded-2xl border border-[#E1E7EF] shadow-xs space-y-3 hover:border-[#147D78]/50 transition-colors">
            <div className="w-10 h-10 rounded-xl bg-teal-50 text-[#147D78] flex items-center justify-center border border-teal-100 font-bold">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-[#182230]">Client-Side Zero-PHI Encryption</h3>
            <p className="text-xs text-[#5B6675] leading-relaxed">
              Diagnostic files are encrypted using symmetric AES-256-GCM keys on the client before network transit. 
              Plaintext medical data and symmetric encryption keys are strictly banned from on-chain storage and raw IPFS blobs.
            </p>
            <div className="pt-2 text-[11px] font-mono text-[#147D78] bg-teal-50/60 p-2 rounded-lg border border-teal-100">
              AES-256-GCM + Safe Key Fingerprint
            </div>
          </div>

          {/* Pillar 2 */}
          <div className="bg-white p-6 rounded-2xl border border-[#E1E7EF] shadow-xs space-y-3 hover:border-[#147D78]/50 transition-colors">
            <div className="w-10 h-10 rounded-xl bg-indigo-50 text-indigo-700 flex items-center justify-center border border-indigo-100 font-bold">
              <Database className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-[#182230]">Content-Addressable IPFS Storage</h3>
            <p className="text-xs text-[#5B6675] leading-relaxed">
              Encrypted record ciphertexts are pinned directly to local or distributed IPFS Kubo nodes. 
              Every record is indexed by an immutable Content Identifier (CID) preventing content tampering or silent file alterations.
            </p>
            <div className="pt-2 text-[11px] font-mono text-indigo-700 bg-indigo-50/60 p-2 rounded-lg border border-indigo-100">
              CID v1 Sha256 Kubo Pinning
            </div>
          </div>

          {/* Pillar 3 */}
          <div className="bg-white p-6 rounded-2xl border border-[#E1E7EF] shadow-xs space-y-3 hover:border-[#147D78]/50 transition-colors">
            <div className="w-10 h-10 rounded-xl bg-[#14263D]/10 text-[#14263D] flex items-center justify-center border border-[#14263D]/20 font-bold">
              <Server className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-[#182230]">Fabric Smart Contract Consent</h3>
            <p className="text-xs text-[#5B6675] leading-relaxed">
              Access permissions, physician role scope, duration, and atomic revocations are executed by Hyperledger Fabric chaincode. 
              The consent ledger maintains a cryptographically signed SHA-256 hash-chain of all access events.
            </p>
            <div className="pt-2 text-[11px] font-mono text-[#14263D] bg-slate-100 p-2 rounded-lg border border-slate-200">
              Chaincode Rule Consensus (Raft)
            </div>
          </div>

        </div>
      </section>

      {/* Visual Interactive Patient Consent Lifecycle */}
      <section className="bg-white rounded-3xl border border-[#E1E7EF] p-6 sm:p-8 shadow-xs space-y-6">
        <div>
          <span className="text-xs font-bold text-[#147D78] uppercase tracking-wider">Consent Architecture</span>
          <h2 className="text-2xl font-bold text-[#182230] mt-1">Interactive Consent Lifecycle</h2>
          <p className="text-xs text-[#5B6675] mt-1">
            Click through each phase of the sovereign consent workflow to see how smart contracts enforce the Revocation Invariant.
          </p>
        </div>

        {/* Step Tabs */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 sm:gap-3">
          {consentSteps.map((step, idx) => {
            const isSelected = selectedStep === idx;
            return (
              <button
                key={idx}
                onClick={() => setSelectedStep(idx)}
                className={`text-left p-3.5 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'border-[#147D78] bg-teal-50/50 shadow-2xs ring-1 ring-[#147D78]'
                    : 'border-[#E1E7EF] bg-slate-50 hover:bg-slate-100/80 text-slate-600'
                }`}
              >
                <div className="flex items-center space-x-2">
                  <span className={`w-5 h-5 rounded-full text-[11px] flex items-center justify-center font-bold ${
                    isSelected ? 'bg-[#147D78] text-white' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {idx + 1}
                  </span>
                  <span className="text-xs font-bold text-[#182230] truncate">{step.title.split('. ')[1]}</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Active Step Showcase Card */}
        <div className="bg-[#F5F7FA] rounded-2xl p-6 border border-[#E1E7EF] space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#E1E7EF] pb-3">
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Active Step {selectedStep + 1} of 4</span>
              <h3 className="text-base font-bold text-[#182230]">{consentSteps[selectedStep].title}</h3>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-xs text-slate-500 font-medium">Actor:</span>
              <span className="text-xs font-bold text-[#182230]">{consentSteps[selectedStep].actor}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="space-y-2 bg-white p-4 rounded-xl border border-[#E1E7EF]">
              <div className="flex items-center space-x-1.5 text-slate-700 font-bold">
                <CheckCircle2 className="w-4 h-4 text-[#147D78]" />
                <span>Workflow Action &amp; Role Rule</span>
              </div>
              <p className="text-[#5B6675] leading-relaxed">
                {consentSteps[selectedStep].details}
              </p>
            </div>

            <div className="space-y-2 bg-white p-4 rounded-xl border border-[#E1E7EF]">
              <div className="flex items-center space-x-1.5 text-slate-700 font-bold">
                <Layers className="w-4 h-4 text-indigo-600" />
                <span>Cryptographic &amp; Ledger Invariant</span>
              </div>
              <p className="text-[#5B6675] leading-relaxed">
                {consentSteps[selectedStep].cryptoNote}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* System Architecture Overview Card / Diagram */}
      <section className="bg-white rounded-3xl border border-[#E1E7EF] p-6 sm:p-8 shadow-xs space-y-6">
        <div className="max-w-2xl space-y-1">
          <span className="text-xs font-bold text-[#147D78] uppercase tracking-wider">System Design</span>
          <h2 className="text-2xl font-bold text-[#182230]">Five-Tier Decentralized Architecture</h2>
          <p className="text-xs text-[#5B6675]">
            Production-grade separation of concerns across client, gateway, decentralized storage, and distributed ledger.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          
          {/* Tier 1 */}
          <div className="p-4 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA] space-y-2">
            <div className="w-7 h-7 rounded-lg bg-teal-100 text-[#147D78] flex items-center justify-center font-bold text-xs">
              1
            </div>
            <h4 className="text-xs font-bold text-[#182230]">React 19 + Vite</h4>
            <p className="text-[11px] text-[#5B6675] leading-relaxed">
              TypeScript SPA running on port 5174. Zero-secret client model; tokens stored in-memory only.
            </p>
            <span className="inline-block text-[10px] font-mono bg-white px-2 py-0.5 rounded border border-[#E1E7EF] text-slate-700">
              Role Auth (JWT)
            </span>
          </div>

          {/* Tier 2 */}
          <div className="p-4 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA] space-y-2">
            <div className="w-7 h-7 rounded-lg bg-indigo-100 text-indigo-700 flex items-center justify-center font-bold text-xs">
              2
            </div>
            <h4 className="text-xs font-bold text-[#182230]">FastAPI Gateway</h4>
            <p className="text-[11px] text-[#5B6675] leading-relaxed">
              Python 3 service on port 8001. Horizontal RBAC enforcement, file staging, and encryption orchestration.
            </p>
            <span className="inline-block text-[10px] font-mono bg-white px-2 py-0.5 rounded border border-[#E1E7EF] text-slate-700">
              REST API v1
            </span>
          </div>

          {/* Tier 3 */}
          <div className="p-4 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA] space-y-2">
            <div className="w-7 h-7 rounded-lg bg-amber-100 text-amber-800 flex items-center justify-center font-bold text-xs">
              3
            </div>
            <h4 className="text-xs font-bold text-[#182230]">IPFS Kubo Daemon</h4>
            <p className="text-[11px] text-[#5B6675] leading-relaxed">
              Decentralized storage node on port 5001. Pins AES-256-GCM ciphertexts with immutable Content IDs.
            </p>
            <span className="inline-block text-[10px] font-mono bg-white px-2 py-0.5 rounded border border-[#E1E7EF] text-slate-700">
              CID v1 Pinning
            </span>
          </div>

          {/* Tier 4 */}
          <div className="p-4 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA] space-y-2">
            <div className="w-7 h-7 rounded-lg bg-emerald-100 text-emerald-800 flex items-center justify-center font-bold text-xs">
              4
            </div>
            <h4 className="text-xs font-bold text-[#182230]">Fabric Gateway</h4>
            <p className="text-[11px] text-[#5B6675] leading-relaxed">
              Real Fabric Gateway adapter translating FastAPI requests into endorsed ledger transactions.
            </p>
            <span className="inline-block text-[10px] font-mono bg-white px-2 py-0.5 rounded border border-[#E1E7EF] text-slate-700">
              gRPC Endorsement
            </span>
          </div>

          {/* Tier 5 */}
          <div className="p-4 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA] space-y-2">
            <div className="w-7 h-7 rounded-lg bg-purple-100 text-purple-800 flex items-center justify-center font-bold text-xs">
              5
            </div>
            <h4 className="text-xs font-bold text-[#182230]">Hyperledger Fabric</h4>
            <p className="text-[11px] text-[#5B6675] leading-relaxed">
              Fabric v2.5 channel with Raft ordering. Executes chaincode consent logic and stores SHA-256 audit blocks.
            </p>
            <span className="inline-block text-[10px] font-mono bg-white px-2 py-0.5 rounded border border-[#E1E7EF] text-slate-700">
              Channel Ledger
            </span>
          </div>

        </div>
      </section>

      {/* Security & Privacy Highlights */}
      <section className="space-y-4">
        <div className="space-y-1">
          <span className="text-xs font-bold text-[#147D78] uppercase tracking-wider">Security &amp; Privacy Guarantees</span>
          <h2 className="text-2xl font-bold text-[#182230]">Strict Cryptographic Invariants</h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs space-y-2">
            <div className="flex items-center space-x-2 text-[#182230] font-bold text-xs">
              <Lock className="w-4 h-4 text-[#147D78]" />
              <span>Zero-PHI On-Chain</span>
            </div>
            <p className="text-xs text-[#5B6675] leading-relaxed">
              Absolute architectural ban on storing patient health information or decryption keys in Fabric world state or plain IPFS storage.
            </p>
          </div>

          <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs space-y-2">
            <div className="flex items-center space-x-2 text-[#182230] font-bold text-xs">
              <FileCheck className="w-4 h-4 text-[#237A52]" />
              <span>Tamper-Evident Merkle Chain</span>
            </div>
            <p className="text-xs text-[#5B6675] leading-relaxed">
              Every access event generates a SHA-256 block hash linked to the previous entry (<code className="text-slate-700 bg-slate-100 px-1 py-0.5 rounded">prevHash</code>) for verifiable auditing.
            </p>
          </div>

          <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs space-y-2">
            <div className="flex items-center space-x-2 text-[#182230] font-bold text-xs">
              <Clock className="w-4 h-4 text-[#9A6700]" />
              <span>Real-Time Revocation</span>
            </div>
            <p className="text-xs text-[#5B6675] leading-relaxed">
              Revocation writes immediately to ledger state. Smart contract rule evaluation instantaneously rejects subsequent access attempts.
            </p>
          </div>

          <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs space-y-2">
            <div className="flex items-center space-x-2 text-[#182230] font-bold text-xs">
              <Cpu className="w-4 h-4 text-indigo-600" />
              <span>Ledger SHA-256 Verification</span>
            </div>
            <p className="text-xs text-[#5B6675] leading-relaxed">
              Verify Ledger modal fetches live IPFS bytes and calculates on-demand SHA-256 checksums to confirm bit-level parity against blockchain records.
            </p>
          </div>
        </div>
      </section>

      {/* Academic Research & Engineering Demonstration Notice */}
      <section className="bg-slate-100 border border-slate-200 rounded-2xl p-6 space-y-2 text-xs text-[#5B6675]">
        <div className="flex items-center space-x-2 text-[#182230] font-bold">
          <AlertTriangle className="w-4 h-4 text-[#9A6700]" />
          <span>Academic Research &amp; Demonstration Notice</span>
        </div>
        <p className="leading-relaxed">
          MedTrust is engineered as a research and engineering demonstration architecture for sovereign health data sharing. 
          All records, patient identifiers, and clinical fixtures presented are synthetic test datasets designed for viva demonstrations and architectural evaluation. 
          This demonstration platform does not claim commercial HIPAA/GDPR clinical regulatory certifications without multi-party institutional audit.
        </p>
      </section>

      {/* Persona Demo Launch Cards */}
      <section className="space-y-4">
        <h3 className="text-lg font-bold text-[#182230]">Explore Role Portals &amp; Authenticated Personas</h3>
        <p className="text-xs text-[#5B6675]">
          MedTrust enforces backend-authoritative role routing. Each role signs in through the unified portal with authorized credentials.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2">
          
          <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs flex flex-col justify-between space-y-4 hover:border-[#147D78] transition-all">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded-full border border-indigo-100">
                  Patient Persona
                </span>
                <User className="w-4 h-4 text-slate-400" />
              </div>
              <h4 className="text-sm font-bold text-[#182230]">Patient Sovereign Vault</h4>
              <p className="text-xs text-[#5B6675] leading-relaxed">
                Inspect encrypted health records, upload new diagnostic files, approve or reject pending doctor access requests, and execute atomic revocations.
              </p>
            </div>
            <button
              onClick={() => handleAuthNav('login', 'PATIENT')}
              className="inline-flex items-center justify-center space-x-1 w-full py-2 rounded-lg bg-[#14263D] hover:bg-[#14263D]/90 text-white font-semibold text-xs transition-colors cursor-pointer"
            >
              <span>Sign In as Patient</span>
              <ArrowRight className="w-3.5 h-3.5 ml-1" />
            </button>
          </div>

          <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs flex flex-col justify-between space-y-4 hover:border-[#147D78] transition-all">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-100">
                  Physician Persona
                </span>
                <Stethoscope className="w-4 h-4 text-slate-400" />
              </div>
              <h4 className="text-sm font-bold text-[#182230]">Dr. Marcus Sterling Portal</h4>
              <p className="text-xs text-[#5B6675] leading-relaxed">
                Request consent for diagnostic procedures, review authorized records with live smart contract rule evaluation, and test revocation denials.
              </p>
            </div>
            <button
              onClick={() => handleAuthNav('login', 'DOCTOR')}
              className="inline-flex items-center justify-center space-x-1 w-full py-2 rounded-lg bg-[#147D78] hover:bg-[#116964] text-white font-semibold text-xs transition-colors cursor-pointer"
            >
              <span>Sign In as Doctor</span>
              <ArrowRight className="w-3.5 h-3.5 ml-1" />
            </button>
          </div>

          <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs flex flex-col justify-between space-y-4 hover:border-[#147D78] transition-all">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-800 bg-slate-100 px-2 py-0.5 rounded-full border border-slate-200">
                  Administrator
                </span>
                <ShieldAlert className="w-4 h-4 text-indigo-600" />
              </div>
              <h4 className="text-sm font-bold text-[#182230]">Platform Admin Console</h4>
              <p className="text-xs text-[#5B6675] leading-relaxed">
                Manage user identity accounts, view real-time security events, inspect microservices health. Zero-PHI boundary enforced.
              </p>
            </div>
            <button
              onClick={() => handleAuthNav('login', 'ADMIN')}
              className="inline-flex items-center justify-center space-x-1 w-full py-2 rounded-lg bg-indigo-950 hover:bg-indigo-900 text-white font-semibold text-xs transition-colors cursor-pointer"
            >
              <span>Sign In as Admin</span>
              <ArrowRight className="w-3.5 h-3.5 ml-1" />
            </button>
          </div>

          <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs flex flex-col justify-between space-y-4 hover:border-[#147D78] transition-all">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-amber-800 bg-amber-50 px-2 py-0.5 rounded-full border border-amber-100">
                  Compliance Auditor
                </span>
                <Activity className="w-4 h-4 text-slate-400" />
              </div>
              <h4 className="text-sm font-bold text-[#182230]">Federal Audit Ledger</h4>
              <p className="text-xs text-[#5B6675] leading-relaxed">
                Audit immutable access event trails, verify SHA-256 block hash-chain continuity (<code className="text-slate-600 bg-slate-100 px-1 py-0.5 rounded">prevHash</code> &rarr; <code className="text-slate-600 bg-slate-100 px-1 py-0.5 rounded">entryHash</code>), and confirm compliance.
              </p>
            </div>
            <button
              onClick={() => handleAuthNav('login', 'AUDITOR')}
              className="inline-flex items-center justify-center space-x-1 w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-900 text-white font-semibold text-xs transition-colors cursor-pointer"
            >
              <span>Sign In as Auditor</span>
              <ArrowRight className="w-3.5 h-3.5 ml-1" />
            </button>
          </div>

        </div>
      </section>

    </div>
  );
};
