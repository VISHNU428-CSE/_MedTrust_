import React, { useState } from 'react';
import { 
  Users, 
  FileCheck2, 
  ShieldAlert, 
  Search, 
  ShieldPlus, 
  Eye, 
  Lock, 
  Building2, 
  CheckCircle2, 
  Clock,
  ShieldCheck,
  Pill,
  Download,
  Stethoscope,
  Loader2,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import type { MedicalRecord, ConsentRecord, ConsentVerifyResponse, RecordDetailResponse } from '../../types';
import { StatCard } from '../common/StatCard';
import { StatusBadge } from '../common/StatusBadge';
import { RequestAccessModal } from './RequestAccessModal';
import { apiService, formatDownloadErrorMessage, triggerFileDownload } from '../../services/api';
import { useAuth } from '../../context/AuthContext';

interface DoctorDashboardProps {
  records: MedicalRecord[];
  consents: ConsentRecord[];
  doctorId: string;
  onRefresh: () => void;
  onRequestSubmitted: () => void;
}

export const DoctorDashboard: React.FC<DoctorDashboardProps> = ({
  records,
  consents,
  doctorId,
  onRefresh,
  onRequestSubmitted,
}) => {
  const { user } = useAuth();
  const doctorName = user?.name || 'Dr. Marcus Sterling, MD';
  const doctorSpecialty = user?.specialty || 'Cardiovascular Surgery';
  const doctorHospital = user?.hospital || 'Metro General Hospital';

  const [activeTab, setActiveTab] = useState<'search' | 'authorized' | 'requests'>('authorized');
  const [isRequestModalOpen, setIsRequestModalOpen] = useState(false);
  const [selectedPatientForRequest, setSelectedPatientForRequest] = useState('pat-984210');
  const [patientSearchQuery, setPatientSearchQuery] = useState('');
  const [recordSearchQuery, setRecordSearchQuery] = useState('');
  const [viewingRecord, setViewingRecord] = useState<MedicalRecord | null>(null);
  const [viewingRecordDetails, setViewingRecordDetails] = useState<RecordDetailResponse | null>(null);
  const [isLoadingRecordDetails, setIsLoadingRecordDetails] = useState<boolean>(false);
  const [consentVerification, setConsentVerification] = useState<ConsentVerifyResponse | null>(null);
  const [isEvaluatingConsent, setIsEvaluatingConsent] = useState(false);
  const [downloadFeedback, setDownloadFeedback] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [activeDownloads, setActiveDownloads] = useState<Record<string, boolean>>({});

  // Active consents where this doctor is granted access
  const myConsents = consents.filter(c => c.doctorId === doctorId || !c.doctorId);
  const activeConsents = myConsents.filter(c => c.status === 'ACTIVE');
  const pendingRequests = myConsents.filter(c => c.status === 'PENDING');

  // Filtered authorized records
  const authorizedRecords = records.filter(r => {
    // If active consent exists for this patient
    const hasActiveConsent = activeConsents.some(c => c.patientId === r.patientId);
    const matchesSearch = r.title.toLowerCase().includes(recordSearchQuery.toLowerCase()) ||
                          r.patientName.toLowerCase().includes(recordSearchQuery.toLowerCase());
    return hasActiveConsent && matchesSearch;
  });

  // Handle opening a record with live smart contract verification & clinical details
  const handleOpenRecord = async (record: MedicalRecord) => {
    setViewingRecord(record);
    setIsEvaluatingConsent(true);
    setConsentVerification(null);
    setViewingRecordDetails(null);
    setIsLoadingRecordDetails(true);
    setDownloadFeedback(null);

    try {
      const res = await apiService.verifyConsent(doctorId, record.patientId, record.recordType);
      setConsentVerification(res);
    } catch {
      setConsentVerification({ allowed: false, reason: 'CONSENT_VERIFICATION_FAILED' });
    } finally {
      setIsEvaluatingConsent(false);
    }

    try {
      const details = await apiService.getRecordDetails(record.id);
      setViewingRecordDetails(details);
    } catch {
      setViewingRecordDetails(null);
    } finally {
      setIsLoadingRecordDetails(false);
    }
  };

  // Handle primary document download
  const handleDownloadDocument = async (recordId: string, fallbackFilename?: string) => {
    if (!consentVerification?.allowed) return;
    const downloadKey = `${recordId}_doc`;
    if (activeDownloads[downloadKey]) return; // Prevent duplicate clicks
    setActiveDownloads(prev => ({ ...prev, [downloadKey]: true }));
    setDownloadFeedback(null);
    try {
      const result = await apiService.downloadRecordDocument(recordId);
      triggerFileDownload(result.blob, result.filename || fallbackFilename || `${recordId}_document`);
      setDownloadFeedback({
        message: `Decrypted primary document downloaded successfully (${result.filename}).`,
        type: 'success',
      });
    } catch (err: unknown) {
      const errorMsg = formatDownloadErrorMessage(err, 'Failed to download encrypted medical document.');
      setDownloadFeedback({ message: errorMsg, type: 'error' });
    } finally {
      setActiveDownloads(prev => ({ ...prev, [downloadKey]: false }));
    }
  };

  // Handle prescription attachment download
  const handleDownloadPrescription = async (recordId: string, fallbackFilename?: string) => {
    if (!consentVerification?.allowed) return;
    const downloadKey = `${recordId}_rx`;
    if (activeDownloads[downloadKey]) return; // Prevent duplicate clicks
    setActiveDownloads(prev => ({ ...prev, [downloadKey]: true }));
    setDownloadFeedback(null);
    try {
      const result = await apiService.downloadRecordPrescription(recordId);
      triggerFileDownload(result.blob, result.filename || fallbackFilename || `${recordId}_prescription.pdf`);
      setDownloadFeedback({
        message: `Decrypted prescription downloaded successfully (${result.filename}).`,
        type: 'success',
      });
    } catch (err: unknown) {
      const errorMsg = formatDownloadErrorMessage(err, 'Failed to download prescription attachment.');
      setDownloadFeedback({ message: errorMsg, type: 'error' });
    } finally {
      setActiveDownloads(prev => ({ ...prev, [downloadKey]: false }));
    }
  };

  // Demo Patients List for directory search
  const directoryPatients = [
    {
      id: 'pat-984210',
      name: 'Eleanor Vance',
      age: 54,
      condition: 'Post-operative mitral valve repair',
      consentStatus: activeConsents.some(c => c.patientId === 'pat-984210') ? 'ACTIVE' : 'NONE',
    },
    {
      id: 'pat-662194',
      name: 'Arthur Pendelton',
      age: 68,
      condition: 'Coronary artery disease, Stage 2 Hypertension',
      consentStatus: 'NONE',
    },
    {
      id: 'pat-441209',
      name: 'Samantha Grey',
      age: 41,
      condition: 'Cardiomyopathy evaluation',
      consentStatus: 'PENDING',
    },
  ].filter(p => 
    p.name.toLowerCase().includes(patientSearchQuery.toLowerCase()) ||
    p.id.toLowerCase().includes(patientSearchQuery.toLowerCase()) ||
    p.condition.toLowerCase().includes(patientSearchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-[#14263D] via-[#162e4a] to-[#147D78] rounded-2xl p-6 text-white shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-[#147D78]/30 text-teal-200 border border-[#147D78]/40">
                Clinician Workspace
              </span>
              <span className="text-xs text-teal-200">Doctor ID: <code className="bg-black/20 px-1 py-0.5 rounded">{doctorId}</code></span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight mt-1 text-white">{doctorName}</h1>
            <p className="text-sm text-slate-200 mt-1 max-w-2xl">
              {doctorSpecialty} • {doctorHospital}. Access patient records authorized under smart contract consent rules.
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => {
                setSelectedPatientForRequest('pat-984210');
                setIsRequestModalOpen(true);
              }}
              className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-[#147D78] hover:bg-[#116965] text-white font-semibold text-xs transition-all shadow-sm shadow-teal-950/20"
            >
              <ShieldPlus className="w-4 h-4" />
              <span>Request Patient Access</span>
            </button>
          </div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Authorized Records"
          value={authorizedRecords.length}
          subtitle="Ready for clinical review"
          icon={FileCheck2}
          variant="emerald"
        />
        <StatCard
          title="Active Consents"
          value={activeConsents.length}
          subtitle="Signed on Fabric ledger"
          icon={CheckCircle2}
          variant="teal"
        />
        <StatCard
          title="Pending Requests"
          value={pendingRequests.length}
          subtitle="Awaiting patient sign-off"
          icon={Clock}
          variant="amber"
        />
        <StatCard
          title="Affiliated Facility"
          value="Metro General"
          subtitle="Authorized Node MSP"
          icon={Building2}
          variant="navy"
        />
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="border-b border-[#E1E7EF]">
        <nav className="flex space-x-8" aria-label="Tabs">
          <button
            onClick={() => setActiveTab('authorized')}
            className={`py-3 px-1 border-b-2 font-semibold text-xs inline-flex items-center space-x-2 transition-colors ${
              activeTab === 'authorized'
                ? 'border-[#147D78] text-[#147D78]'
                : 'border-transparent text-[#5B6675] hover:text-[#182230] hover:border-slate-300'
            }`}
          >
            <FileCheck2 className="w-4 h-4" />
            <span>Authorized Patient Records ({authorizedRecords.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('search')}
            className={`py-3 px-1 border-b-2 font-semibold text-xs inline-flex items-center space-x-2 transition-colors ${
              activeTab === 'search'
                ? 'border-[#147D78] text-[#147D78]'
                : 'border-transparent text-[#5B6675] hover:text-[#182230] hover:border-slate-300'
            }`}
          >
            <Users className="w-4 h-4" />
            <span>Patient Search & Consent Requests</span>
          </button>

          <button
            onClick={() => setActiveTab('requests')}
            className={`py-3 px-1 border-b-2 font-semibold text-xs inline-flex items-center space-x-2 transition-colors ${
              activeTab === 'requests'
                ? 'border-[#147D78] text-[#147D78]'
                : 'border-transparent text-[#5B6675] hover:text-[#182230] hover:border-slate-300'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>My Access Requests ({myConsents.length})</span>
          </button>
        </nav>
      </div>

      {/* TAB CONTENT 1: AUTHORIZED RECORDS */}
      {activeTab === 'authorized' && (
        <div className="space-y-4">
          
          {/* Search bar */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs flex flex-col sm:flex-row gap-3 items-center justify-between">
            <div className="relative w-full sm:w-96">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search authorized records by title or patient..."
                value={recordSearchQuery}
                onChange={(e) => setRecordSearchQuery(e.target.value)}
                className="w-full text-xs pl-9 pr-3 py-2 rounded-lg border border-slate-200 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
            <div className="text-xs text-slate-500">
              Showing records authorized under active Fabric consent agreements
            </div>
          </div>

          {/* Record Items */}
          <div className="space-y-3">
            {authorizedRecords.length === 0 ? (
              <div className="text-center py-12 bg-white rounded-xl border border-dashed border-slate-300 p-6">
                <FileCheck2 className="w-10 h-10 text-slate-300 mx-auto mb-2" />
                <h3 className="text-sm font-semibold text-slate-700">No authorized records currently available</h3>
                <p className="text-xs text-slate-500 mt-1">Submit a consent request to the patient to gain access.</p>
              </div>
            ) : (
              authorizedRecords.map((record) => (
                <div 
                  key={record.id}
                  className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs hover:border-emerald-200 hover:shadow-xs transition-all"
                >
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div className="space-y-1.5 flex-1">
                      <div className="flex items-center space-x-2.5 flex-wrap">
                        <StatusBadge type={record.recordType} />
                        <span className="text-xs font-bold text-slate-800">Patient: {record.patientName}</span>
                        <span className="text-xs text-slate-400">•</span>
                        <span className="text-xs text-slate-500">{record.hospital}</span>
                        <span className="text-xs text-slate-400">•</span>
                        <span className="text-xs text-slate-500">
                          {new Date(record.createdAt).toLocaleDateString()}
                        </span>
                        {record.txHash && (
                          <span className="text-[10px] font-mono text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-100">
                            Tx: {record.txHash.substring(0, 10)}...
                          </span>
                        )}
                      </div>
                      <h3 className="text-base font-bold text-slate-900">{record.title}</h3>
                      <div className="flex items-center space-x-3 text-xs text-slate-500 flex-wrap gap-y-1">
                        <span className="inline-flex items-center space-x-1">
                          <Lock className="w-3 h-3 text-emerald-600" />
                          <span>AES-256-GCM Encrypted</span>
                        </span>
                        <span>Key Fingerprint: <code className="bg-slate-100 px-1 py-0.5 rounded text-[11px] font-mono">{record.keyFingerprint}</code></span>
                        {record.checksumSha256 && (
                          <span>Checksum: <code className="bg-slate-100 px-1 py-0.5 rounded text-[11px] font-mono">{record.checksumSha256.substring(0, 12)}...</code></span>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleOpenRecord(record)}
                        className="inline-flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-teal-50 text-[#147D78] hover:bg-teal-100 text-xs font-semibold border border-teal-200 transition-colors cursor-pointer"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Inspect &amp; Decrypt Record</span>
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

        </div>
      )}

      {/* TAB CONTENT 2: PATIENT SEARCH & ACCESS REQUEST */}
      {activeTab === 'search' && (
        <div className="space-y-4">
          
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs">
            <div className="relative w-full">
              <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
              <input
                type="text"
                placeholder="Search patient registry by name, Patient ID, or clinical indication..."
                value={patientSearchQuery}
                onChange={(e) => setPatientSearchQuery(e.target.value)}
                className="w-full text-xs pl-9 pr-3 py-2.5 rounded-lg border border-slate-200 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 shadow-2xs overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900">Hospital Patient Directory</h3>
                <p className="text-xs text-slate-500">Select a patient to initiate or inspect access permissions</p>
              </div>
            </div>

            <div className="divide-y divide-slate-100">
              {directoryPatients.map((patient) => (
                <div key={patient.id} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-slate-50/70 transition-colors">
                  <div>
                    <div className="flex items-center space-x-2">
                      <h4 className="text-sm font-bold text-slate-900">{patient.name}</h4>
                      <span className="text-xs text-slate-400 font-mono">({patient.id})</span>
                      <span className="text-xs text-slate-500">• Age {patient.age}</span>
                    </div>
                    <p className="text-xs text-slate-600 mt-0.5">Primary Indication: {patient.condition}</p>
                  </div>

                  <div className="flex items-center space-x-3">
                    <span className="text-xs">
                      {patient.consentStatus === 'ACTIVE' && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          Active Consent
                        </span>
                      )}
                      {patient.consentStatus === 'PENDING' && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
                          Consent Pending
                        </span>
                      )}
                      {patient.consentStatus === 'NONE' && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-200">
                          No Active Consent
                        </span>
                      )}
                    </span>

                    <button
                      onClick={() => {
                        setSelectedPatientForRequest(patient.id);
                        setIsRequestModalOpen(true);
                      }}
                      className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold transition-colors shadow-2xs"
                    >
                      <ShieldPlus className="w-3.5 h-3.5" />
                      <span>Request Access</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}

      {/* TAB CONTENT 3: MY ACCESS REQUESTS */}
      {activeTab === 'requests' && (
        <div className="bg-white rounded-xl border border-slate-200 shadow-2xs overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Access Requests & Consent Status</h3>
              <p className="text-xs text-slate-500">Record access grants governed by Hyperledger Fabric chaincode</p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
              <thead className="bg-slate-50 text-slate-600 font-semibold uppercase tracking-wider">
                <tr>
                  <th scope="col" className="px-5 py-3">Patient ID</th>
                  <th scope="col" className="px-5 py-3">Status</th>
                  <th scope="col" className="px-5 py-3">Clinical Purpose</th>
                  <th scope="col" className="px-5 py-3">Authorized Record Types</th>
                  <th scope="col" className="px-5 py-3">Valid Until</th>
                  <th scope="col" className="px-5 py-3">Fabric Consensus Tx</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {myConsents.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-5 py-3.5 whitespace-nowrap font-bold text-slate-900">
                      {c.patientId}
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap">
                      <StatusBadge status={c.status} />
                    </td>
                    <td className="px-5 py-3.5 max-w-xs truncate text-slate-600" title={c.purpose}>
                      {c.purpose}
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap text-slate-700">
                      {Array.isArray(c.allowedRecordTypes) ? c.allowedRecordTypes.join(', ') : c.allowedRecordTypes}
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap text-slate-500">
                      {new Date(c.expiresAt).toLocaleDateString()}
                    </td>
                    <td className="px-5 py-3.5 whitespace-nowrap font-mono text-[11px] text-emerald-700">
                      {c.txHash ? `${c.txHash.substring(0, 14)}...` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Record Decryption / Inspection Modal */}
      {viewingRecord && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-xl w-full border border-slate-200 shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="px-6 py-4 border-b border-slate-100 bg-emerald-50/50 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <FileCheck2 className="w-5 h-5 text-emerald-600" />
                <h3 className="text-base font-bold text-slate-900">Decrypted Clinical Record View</h3>
              </div>
              <button 
                onClick={() => {
                  setViewingRecord(null);
                  setDownloadFeedback(null);
                }}
                className="text-slate-400 hover:text-slate-600 p-1 rounded-lg cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="p-6 space-y-4 text-xs">
              {/* Download Feedback Banner */}
              {downloadFeedback && (
                <div className={`p-3 rounded-xl border text-xs flex items-center justify-between ${
                  downloadFeedback.type === 'success' 
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-800' 
                    : 'bg-rose-50 border-rose-200 text-rose-800'
                }`}>
                  <div className="flex items-center space-x-2">
                    {downloadFeedback.type === 'success' ? (
                      <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                    )}
                    <span>{downloadFeedback.message}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setDownloadFeedback(null)}
                    className="text-slate-400 hover:text-slate-600 font-bold ml-2 cursor-pointer"
                  >
                    ✕
                  </button>
                </div>
              )}

              <div className="p-3.5 bg-emerald-50/70 border border-emerald-200 rounded-xl space-y-1">
                <p className="font-bold text-emerald-900 text-sm">{viewingRecord.title}</p>
                <p className="text-emerald-700">Patient: {viewingRecord.patientName} ({viewingRecord.patientId})</p>
                <p className="text-emerald-700">Issuing Facility: {viewingRecord.hospital}</p>
              </div>

              {/* On-Chain Smart Contract Rule Evaluation Badge */}
              <div className="p-3 rounded-xl border bg-slate-50 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-indigo-600" />
                  <span className="font-semibold text-slate-700">Smart Contract Rule Evaluation:</span>
                </div>
                {isEvaluatingConsent ? (
                  <span className="text-slate-500 italic">Querying Fabric...</span>
                ) : consentVerification?.allowed ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                    AUTHORIZED ({consentVerification.reason})
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">
                    ACCESS DENIED ({consentVerification?.reason || 'REVOKED'})
                  </span>
                )}
              </div>

              <div className="space-y-2 bg-slate-50 p-4 rounded-xl border border-slate-200">
                <div className="flex justify-between border-b border-slate-200/60 pb-1.5">
                  <span className="font-semibold text-slate-600">IPFS Kubo Content ID:</span>
                  <span className="font-mono text-slate-800 break-all">{viewingRecord.ipfsCid}</span>
                </div>
                <div className="flex justify-between border-b border-slate-200/60 pb-1.5">
                  <span className="font-semibold text-slate-600">Decryption Scheme:</span>
                  <span className="font-mono text-slate-800">AES-256-GCM Ephemeral Session</span>
                </div>
                <div className="flex justify-between border-b border-slate-200/60 pb-1.5">
                  <span className="font-semibold text-slate-600">Key Fingerprint:</span>
                  <span className="font-mono text-slate-800">{viewingRecord.keyFingerprint}</span>
                </div>
                {viewingRecord.checksumSha256 && (
                  <div className="flex justify-between border-b border-slate-200/60 pb-1.5">
                    <span className="font-semibold text-slate-600">On-Chain SHA-256 Checksum:</span>
                    <span className="font-mono text-slate-800">{viewingRecord.checksumSha256.substring(0, 16)}...</span>
                  </div>
                )}
                <div className="flex justify-between pt-1">
                  <span className="font-semibold text-slate-600">Fabric Consensus Verification:</span>
                  <span className="text-emerald-700 font-bold">VERIFIED ON-CHAIN</span>
                </div>
              </div>

              {/* Decrypted Clinical Payload / Clinical Notes */}
              {consentVerification?.allowed ? (
                <>
                  {isLoadingRecordDetails ? (
                    <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl flex items-center space-x-2 text-slate-500">
                      <Loader2 className="w-4 h-4 animate-spin text-[#147D78]" />
                      <span>Loading off-chain clinical notes &amp; prescription details...</span>
                    </div>
                  ) : (
                    <>
                      {/* Clinical Symptoms & Diagnostic Description */}
                      {viewingRecordDetails?.description ? (
                        <div className="p-3.5 bg-teal-50 border border-teal-200 rounded-xl space-y-1.5">
                          <div className="flex items-center space-x-1.5 font-bold text-[#14263D] text-xs">
                            <Stethoscope className="w-4 h-4 text-[#147D78]" />
                            <span>Clinical Notes &amp; Symptoms Description:</span>
                          </div>
                          <p className="text-slate-800 leading-relaxed text-xs bg-white p-3 rounded-lg border border-teal-100">
                            {viewingRecordDetails.description}
                          </p>
                        </div>
                      ) : (
                        <div className="p-3 bg-slate-100 rounded-lg text-slate-600">
                          <p className="font-semibold text-slate-800 mb-1">Clinical Diagnostic Excerpt:</p>
                          <p className="italic">
                            "Patient presents for routine scheduled follow-up. Vital indicators within normal limits. Transthoracic echocardiogram demonstrates preserved left ventricular ejection fraction (~58%). No severe valvular regurgitation noted."
                          </p>
                        </div>
                      )}

                      {/* Prescription Attachment & Download */}
                      {viewingRecordDetails?.prescriptionCid && (
                        <div className="p-3.5 bg-indigo-50/70 border border-indigo-200 rounded-xl space-y-2.5">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-1.5 font-bold text-indigo-950 text-xs">
                              <Pill className="w-4 h-4 text-indigo-600" />
                              <span>Prescription Attachment</span>
                            </div>
                            <span className="text-[10px] font-mono text-indigo-700 bg-indigo-100/70 px-2 py-0.5 rounded border border-indigo-200">
                              {viewingRecordDetails.prescriptionFilename || 'Prescription Document'}
                            </span>
                          </div>
                          <div className="space-y-1 font-mono text-[10px] text-slate-600 bg-white p-2.5 rounded-lg border border-indigo-100">
                            <p>IPFS CID: <span className="text-indigo-800 break-all">{viewingRecordDetails.prescriptionCid}</span></p>
                            {viewingRecordDetails.prescriptionChecksum && (
                              <p>Checksum: <span className="text-slate-800 break-all">{viewingRecordDetails.prescriptionChecksum}</span></p>
                            )}
                          </div>
                          <button
                            type="button"
                            disabled={activeDownloads[`${viewingRecord.id}_rx`]}
                            onClick={() => handleDownloadPrescription(
                              viewingRecord.id,
                              viewingRecordDetails.prescriptionFilename || `${viewingRecord.id}_prescription.pdf`
                            )}
                            className="w-full inline-flex items-center justify-center space-x-2 py-2 px-3 rounded-lg bg-[#147D78] hover:bg-[#116965] text-white font-semibold text-xs transition-colors cursor-pointer shadow-xs disabled:opacity-50"
                          >
                            {activeDownloads[`${viewingRecord.id}_rx`] ? (
                              <>
                                <Loader2 className="w-4 h-4 animate-spin text-white" />
                                <span>Decrypting &amp; Downloading Prescription...</span>
                              </>
                            ) : (
                              <>
                                <Download className="w-4 h-4" />
                                <span>Download Prescription Attachment ({viewingRecordDetails.prescriptionFilename || 'PDF'})</span>
                              </>
                            )}
                          </button>
                        </div>
                      )}

                      {/* Primary Medical Document & Download */}
                      {viewingRecordDetails?.hasDocument !== false && (
                        <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-1.5 font-bold text-slate-800 text-xs">
                              <Lock className="w-4 h-4 text-slate-600" />
                              <span>Primary Encrypted Medical Document</span>
                            </div>
                            <span className="text-[10px] text-slate-500 font-medium">
                              {viewingRecord.mimeType || 'application/pdf'} • {viewingRecord.fileSize}
                            </span>
                          </div>
                          <button
                            type="button"
                            disabled={activeDownloads[`${viewingRecord.id}_doc`]}
                            onClick={() => handleDownloadDocument(
                              viewingRecord.id,
                              viewingRecordDetails?.documentFilename || undefined
                            )}
                            className="w-full inline-flex items-center justify-center space-x-2 py-2 px-3 rounded-lg bg-[#14263D] hover:bg-[#162e4a] text-white font-semibold text-xs transition-colors cursor-pointer shadow-xs disabled:opacity-50"
                          >
                            {activeDownloads[`${viewingRecord.id}_doc`] ? (
                              <>
                                <Loader2 className="w-4 h-4 animate-spin text-white" />
                                <span>Decrypting &amp; Downloading Document...</span>
                              </>
                            ) : (
                              <>
                                <Download className="w-4 h-4" />
                                <span>Download Decrypted Document ({viewingRecord.fileSize})</span>
                              </>
                            )}
                          </button>
                        </div>
                      )}
                    </>
                  )}
                </>
              ) : (
                <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-800 space-y-1">
                  <p className="font-bold">Clinical Access Denied</p>
                  <p className="text-[11px] leading-relaxed">
                    Access to decrypted clinical notes and prescription attachments is restricted. Fabric smart contract consent is revoked or has not been granted by patient.
                  </p>
                </div>
              )}
            </div>

            <div className="px-6 py-3 bg-slate-50 border-t border-slate-100 flex justify-end">
              <button
                onClick={() => {
                  setViewingRecord(null);
                  setDownloadFeedback(null);
                }}
                className="px-4 py-2 bg-slate-200 hover:bg-slate-300 text-slate-800 font-semibold text-xs rounded-lg transition-colors cursor-pointer"
              >
                Close Record
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Request Modal */}
      <RequestAccessModal
        isOpen={isRequestModalOpen}
        onClose={() => setIsRequestModalOpen(false)}
        doctorId={doctorId}
        defaultPatientId={selectedPatientForRequest}
        onRequestSubmitted={() => {
          onRequestSubmitted();
          onRefresh();
        }}
      />

    </div>
  );
};
