import React, { useState } from 'react';
import { 
  FileText, 
  ShieldCheck, 
  Clock, 
  Plus, 
  Search, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  History, 
  Lock, 
  Copy, 
  Check,
  Layers,
  RefreshCw,
  Eye,
  Pill,
  Download,
  Stethoscope,
  Loader2
} from 'lucide-react';
import type { MedicalRecord, ConsentRecord, AccessLog, RecordVerifyResponse, RecordDetailResponse } from '../../types';
import { StatCard } from '../common/StatCard';
import { StatusBadge } from '../common/StatusBadge';
import { UploadRecordModal } from './UploadRecordModal';
import { apiService, formatDownloadErrorMessage, triggerFileDownload } from '../../services/api';
import { useAuth } from '../../context/AuthContext';

interface PatientDashboardProps {
  records: MedicalRecord[];
  consents: ConsentRecord[];
  auditLogs: AccessLog[];
  patientId: string;
  patientName?: string;
  errorMessage?: string | null;
  onRefresh: () => void;
  onRecordAdded: (record: MedicalRecord) => void;
  onConsentUpdated: () => void;
}

export const PatientDashboard: React.FC<PatientDashboardProps> = ({
  records,
  consents,
  auditLogs,
  patientId,
  patientName: propPatientName,
  errorMessage,
  onRefresh,
  onRecordAdded,
  onConsentUpdated,
}) => {
  const { user } = useAuth();
  const resolvedPatientName = propPatientName || user?.name;
  const vaultTitle = resolvedPatientName 
    ? `${resolvedPatientName}'s Health Vault` 
    : 'Personal Health Vault';
  const ownRecords = records.filter(r => r.patientId === patientId);
  const isDemoUser = patientId === 'pat-984210';
  const [activeTab, setActiveTab] = useState<'records' | 'consents' | 'logs'>('records');
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [copiedCid, setCopiedCid] = useState<string | null>(null);
  const [actionFeedback, setActionFeedback] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [isProcessingAction, setIsProcessingAction] = useState(false);

  // Record integrity verification state
  const [verifyingRecordId, setVerifyingRecordId] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<RecordVerifyResponse | null>(null);

  // Clinical Record Details & Prescription inspection state
  const [selectedRecordForDetails, setSelectedRecordForDetails] = useState<MedicalRecord | null>(null);
  const [recordDetails, setRecordDetails] = useState<RecordDetailResponse | null>(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);
  const [modalFeedback, setModalFeedback] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [activeDownloads, setActiveDownloads] = useState<Record<string, boolean>>({});

  // Stats
  const activeConsentsCount = consents.filter(c => c.status === 'ACTIVE').length;
  const pendingRequestsCount = consents.filter(c => c.status === 'PENDING').length;
  const totalRecordsCount = records.length;
  const totalAuditLogsCount = auditLogs.length;

  // Filtered records
  const filteredRecords = records.filter(r => {
    const matchesSearch = r.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          r.hospital.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          r.ipfsCid.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = selectedCategory === 'ALL' || r.recordType === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  // Copy helper
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCid(text);
    setTimeout(() => setCopiedCid(null), 2000);
  };

  // Handle Consent Actions (Grant / Revoke)
  const handleConsentAction = async (consentId: string, action: 'GRANT' | 'REVOKE') => {
    setIsProcessingAction(true);
    setActionFeedback(null);
    try {
      const res = await apiService.updateConsentStatus(consentId, action);
      if (res.success) {
        setActionFeedback({
          message: `Consent successfully ${action === 'GRANT' ? 'granted' : 'revoked'} on Fabric ledger. TxID: ${res.txHash || 'Committed'}`,
          type: 'success',
        });
        onConsentUpdated();
      } else {
        setActionFeedback({
          message: res.error || `Failed to update consent status on Hyperledger Fabric ledger.`,
          type: 'error',
        });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error executing consent transaction';
      setActionFeedback({ message: msg, type: 'error' });
    } finally {
      setIsProcessingAction(false);
    }
  };

  // Handle Record Ledger Integrity Verification
  const handleVerifyRecord = async (recordId: string) => {
    setVerifyingRecordId(recordId);
    try {
      const result = await apiService.verifyRecordIntegrity(recordId);
      setVerifyResult(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Verification request failed';
      // Ensure modal opens even when ledger or IPFS reports unavailable status
      setVerifyResult({
        recordId,
        ipfsCid: 'UNKNOWN',
        checksumMatches: false,
        ledgerChecksum: 'UNAVAILABLE',
        computedSha256: 'UNAVAILABLE',
        status: 'LEDGER_UNAVAILABLE',
        detail: `Verification request failed: ${msg}`,
      });
    } finally {
      setVerifyingRecordId(null);
    }
  };

  // Handle Opening Clinical Record Details & Prescriptions
  const handleOpenRecordDetails = async (record: MedicalRecord) => {
    setSelectedRecordForDetails(record);
    setIsLoadingDetails(true);
    setRecordDetails(null);
    setModalFeedback(null);
    try {
      const details = await apiService.getRecordDetails(record.id);
      setRecordDetails(details);
    } catch {
      setRecordDetails(null);
    } finally {
      setIsLoadingDetails(false);
    }
  };

  // Handle Downloading Decrypted Primary Medical Document
  const handleDownloadDocument = async (recordId: string, fallbackFilename?: string) => {
    const downloadKey = `${recordId}_doc`;
    if (activeDownloads[downloadKey]) return; // Prevent duplicate clicks
    setActiveDownloads(prev => ({ ...prev, [downloadKey]: true }));
    setModalFeedback(null);
    setActionFeedback(null);
    try {
      const result = await apiService.downloadRecordDocument(recordId);
      triggerFileDownload(result.blob, result.filename || fallbackFilename || `${recordId}_document`);
      const successMsg = `Decrypted primary document downloaded successfully (${result.filename}).`;
      setModalFeedback({ message: successMsg, type: 'success' });
      setActionFeedback({ message: successMsg, type: 'success' });
    } catch (err: unknown) {
      const errorMsg = formatDownloadErrorMessage(err, 'Failed to download encrypted medical document.');
      setModalFeedback({ message: errorMsg, type: 'error' });
      setActionFeedback({ message: errorMsg, type: 'error' });
    } finally {
      setActiveDownloads(prev => ({ ...prev, [downloadKey]: false }));
    }
  };

  // Handle Downloading Decrypted Prescription Attachment
  const handleDownloadPrescription = async (recordId: string, fallbackFilename?: string) => {
    const downloadKey = `${recordId}_rx`;
    if (activeDownloads[downloadKey]) return; // Prevent duplicate clicks
    setActiveDownloads(prev => ({ ...prev, [downloadKey]: true }));
    setModalFeedback(null);
    setActionFeedback(null);
    try {
      const result = await apiService.downloadRecordPrescription(recordId);
      triggerFileDownload(result.blob, result.filename || fallbackFilename || `${recordId}_prescription.pdf`);
      const successMsg = `Decrypted prescription downloaded successfully (${result.filename}).`;
      setModalFeedback({ message: successMsg, type: 'success' });
      setActionFeedback({ message: successMsg, type: 'success' });
    } catch (err: unknown) {
      const errorMsg = formatDownloadErrorMessage(err, 'Failed to download prescription attachment.');
      setModalFeedback({ message: errorMsg, type: 'error' });
      setActionFeedback({ message: errorMsg, type: 'error' });
    } finally {
      setActiveDownloads(prev => ({ ...prev, [downloadKey]: false }));
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Banner / Hero */}
      <div className="bg-gradient-to-r from-[#14263D] via-[#162e4a] to-[#147D78] rounded-2xl p-6 text-white shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-[#147D78]/30 text-teal-200 border border-[#147D78]/40">
                Sovereign Health Vault
              </span>
              <span className="text-xs text-teal-200">Patient ID: <code className="bg-black/20 px-1 py-0.5 rounded">{patientId}</code></span>
              {resolvedPatientName && (
                <span className="text-xs text-teal-100 font-medium hidden sm:inline">
                  • Verified Patient: <strong className="text-white">{resolvedPatientName}</strong>
                </span>
              )}
            </div>
            <h1 className="text-2xl font-bold tracking-tight mt-1 text-white">{vaultTitle}</h1>
            <p className="text-sm text-slate-200 mt-1 max-w-2xl">
              Control granular access permissions to your health records. All grants, denials, and doctor access events are immutably signed to Hyperledger Fabric.
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setIsUploadOpen(true)}
              className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-[#147D78] hover:bg-[#116965] text-white font-semibold text-xs transition-all shadow-sm shadow-teal-950/20"
            >
              <Plus className="w-4 h-4" />
              <span>Upload Medical Record</span>
            </button>
          </div>
        </div>
      </div>

      {/* Synchronization / Error Banner */}
      {errorMessage && (
        <div className="p-4 rounded-xl border border-rose-300 bg-rose-50 text-rose-800 text-xs flex items-center justify-between shadow-2xs">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
            <span><strong>Live Synchronization Error:</strong> {errorMessage}</span>
          </div>
          <button
            onClick={onRefresh}
            className="px-2.5 py-1 rounded-lg bg-rose-100 hover:bg-rose-200 text-rose-900 font-semibold cursor-pointer transition-colors"
          >
            Retry Sync
          </button>
        </div>
      )}

      {/* Feedback Banner */}
      {actionFeedback && (
        <div className={`p-4 rounded-xl border text-xs flex items-center justify-between ${
          actionFeedback.type === 'success' 
            ? 'bg-emerald-50 border-emerald-200 text-emerald-800' 
            : 'bg-rose-50 border-rose-200 text-rose-800'
        }`}>
          <div className="flex items-center space-x-2">
            {actionFeedback.type === 'success' ? (
              <CheckCircle className="w-4 h-4 text-emerald-600" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-600" />
            )}
            <span>{actionFeedback.message}</span>
          </div>
          <button 
            onClick={() => setActionFeedback(null)} 
            className="text-slate-400 hover:text-slate-600 font-bold ml-2"
          >
            ✕
          </button>
        </div>
      )}

      {/* Record Verification Modal Dialog */}
      {verifyResult && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full border border-slate-200 shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="px-6 py-4 border-b border-[#E1E7EF] flex items-center justify-between bg-[#F5F7FA]">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-[#147D78]" />
                <h3 className="text-sm font-bold text-[#182230]">Ledger & IPFS Cryptographic Verification</h3>
              </div>
              <button onClick={() => setVerifyResult(null)} className="text-slate-400 hover:text-slate-600">✕</button>
            </div>
            <div className="p-6 space-y-4 text-xs">
              <div className="flex items-center space-x-2">
                <span className="font-semibold text-[#5B6675]">Verification Status:</span>
                <span className={`px-2.5 py-0.5 rounded font-bold uppercase text-xs border ${
                  verifyResult.status === 'VERIFIED'
                    ? 'bg-emerald-100 text-[#237A52] border-emerald-300'
                    : verifyResult.status === 'CHECKSUM_MISMATCH'
                    ? 'bg-rose-100 text-[#B42318] border-rose-300'
                    : verifyResult.status === 'IPFS_UNAVAILABLE' || verifyResult.status === 'IPFS_UNREACHABLE'
                    ? 'bg-amber-100 text-[#9A6700] border-amber-300'
                    : verifyResult.status === 'LEDGER_UNAVAILABLE'
                    ? 'bg-slate-100 text-[#14263D] border-slate-300'
                    : 'bg-slate-100 text-slate-800 border-slate-300'
                }`}>
                  {verifyResult.status.replace(/_/g, ' ')}
                </span>
              </div>
              <div className={`p-3 rounded-lg border text-xs ${
                verifyResult.status === 'VERIFIED'
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                  : verifyResult.status === 'CHECKSUM_MISMATCH'
                  ? 'bg-rose-50 border-rose-200 text-rose-900'
                  : verifyResult.status === 'IPFS_UNAVAILABLE' || verifyResult.status === 'IPFS_UNREACHABLE'
                  ? 'bg-amber-50 border-amber-200 text-amber-900'
                  : 'bg-slate-50 border-slate-200 text-slate-800'
              }`}>
                <p className="leading-relaxed">{verifyResult.detail}</p>
              </div>
              <div className="space-y-2 bg-[#F5F7FA] p-3 rounded-lg border border-[#E1E7EF] font-mono text-[11px]">
                <div>
                  <span className="text-[#5B6675] block font-sans text-[10px] uppercase font-bold">Ledger Checksum (SHA-256):</span>
                  <span className="text-[#182230] break-all">{verifyResult.ledgerChecksum}</span>
                </div>
                <div>
                  <span className="text-[#5B6675] block font-sans text-[10px] uppercase font-bold">Computed Checksum:</span>
                  <span className="text-[#182230] break-all">{verifyResult.computedSha256}</span>
                </div>
                <div>
                  <span className="text-[#5B6675] block font-sans text-[10px] uppercase font-bold">IPFS CID:</span>
                  <span className="text-[#147D78] break-all">{verifyResult.ipfsCid}</span>
                </div>
              </div>
            </div>
            <div className="px-6 py-3 bg-[#F5F7FA] border-t border-[#E1E7EF] flex items-center justify-between">
              <button
                type="button"
                onClick={() => handleVerifyRecord(verifyResult.recordId)}
                disabled={verifyingRecordId === verifyResult.recordId}
                className="px-3 py-1.5 rounded-lg border border-[#E1E7EF] hover:bg-slate-100 text-slate-700 font-semibold text-xs transition-colors flex items-center space-x-1.5 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${verifyingRecordId === verifyResult.recordId ? 'animate-spin text-[#147D78]' : 'text-slate-500'}`} />
                <span>{verifyingRecordId === verifyResult.recordId ? 'Verifying...' : 'Retry Verification'}</span>
              </button>
              <button
                type="button"
                onClick={() => setVerifyResult(null)}
                className="px-4 py-1.5 rounded-lg bg-[#14263D] hover:bg-[#162e4a] text-white font-semibold text-xs transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Clinical Record Details & Prescription Modal Dialog */}
      {selectedRecordForDetails && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-xl w-full border border-slate-200 shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150 max-h-[90vh] flex flex-col">
            
            {/* Header */}
            <div className="px-6 py-4 border-b border-[#E1E7EF] flex items-center justify-between bg-[#F5F7FA] shrink-0">
              <div className="flex items-center space-x-2.5">
                <div className="p-1.5 rounded-lg bg-[#147D78]/10 text-[#147D78]">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-[#182230]">Clinical Record &amp; Prescription Details</h3>
                  <p className="text-[11px] text-[#5B6675]">Off-chain clinical context anchored to Fabric record</p>
                </div>
              </div>
              <button 
                onClick={() => setSelectedRecordForDetails(null)} 
                className="text-slate-400 hover:text-slate-600 p-1 rounded-lg cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-4 text-xs overflow-y-auto flex-1">
              {/* Modal-specific Feedback Banner */}
              {modalFeedback && (
                <div className={`p-3 rounded-xl border text-xs flex items-center justify-between ${
                  modalFeedback.type === 'success' 
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-800' 
                    : 'bg-rose-50 border-rose-200 text-rose-800'
                }`}>
                  <div className="flex items-center space-x-2">
                    {modalFeedback.type === 'success' ? (
                      <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                    )}
                    <span>{modalFeedback.message}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setModalFeedback(null)}
                    className="text-slate-400 hover:text-slate-600 font-bold ml-2 cursor-pointer"
                  >
                    ✕
                  </button>
                </div>
              )}

              {/* Record Summary */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <span className="font-bold text-sm text-slate-900">{selectedRecordForDetails.title}</span>
                  <StatusBadge type={selectedRecordForDetails.recordType} />
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px] text-[#5B6675] pt-1">
                  <div>
                    <span className="font-semibold text-slate-700">Hospital:</span> {selectedRecordForDetails.hospital}
                  </div>
                  <div>
                    <span className="font-semibold text-slate-700">Date:</span> {new Date(selectedRecordForDetails.createdAt).toLocaleDateString()}
                  </div>
                  <div>
                    <span className="font-semibold text-slate-700">Patient ID:</span> {selectedRecordForDetails.patientId}
                  </div>
                  <div>
                    <span className="font-semibold text-slate-700">Encryption:</span> {selectedRecordForDetails.encryptionAlgorithm}
                  </div>
                </div>
              </div>

              {/* Loading State */}
              {isLoadingDetails ? (
                <div className="py-8 flex flex-col items-center justify-center space-y-2 text-[#5B6675]">
                  <Loader2 className="w-6 h-6 animate-spin text-[#147D78]" />
                  <p className="text-xs">Fetching clinical details &amp; prescription attachments...</p>
                </div>
              ) : (
                <>
                  {/* Clinical Symptoms & Description Section */}
                  <div className="rounded-xl border border-teal-200 bg-teal-50/50 p-4 space-y-2">
                    <div className="flex items-center space-x-2 text-xs font-bold text-[#14263D]">
                      <Stethoscope className="w-4 h-4 text-[#147D78]" />
                      <span>Clinical / Symptom Description</span>
                    </div>
                    {recordDetails?.description ? (
                      <p className="text-xs text-slate-800 leading-relaxed bg-white p-3 rounded-lg border border-teal-100">
                        {recordDetails.description}
                      </p>
                    ) : (
                      <p className="text-xs text-slate-500 italic bg-white/70 p-3 rounded-lg border border-teal-100">
                        No specific clinical symptom description was submitted with this record.
                      </p>
                    )}
                  </div>

                  {/* Prescription Attachment Section */}
                  <div className="rounded-xl border border-indigo-200 bg-indigo-50/40 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2 text-xs font-bold text-[#14263D]">
                        <Pill className="w-4 h-4 text-indigo-600" />
                        <span>Prescription Attachment</span>
                      </div>
                      {recordDetails?.prescriptionCid && (
                        <span className="text-[10px] font-mono text-indigo-700 bg-indigo-100/70 px-2 py-0.5 rounded border border-indigo-200">
                          {recordDetails.prescriptionFilename || 'Prescription Document'}
                        </span>
                      )}
                    </div>

                    {recordDetails?.prescriptionCid ? (
                      <div className="space-y-3">
                        <div className="p-3 bg-white rounded-lg border border-indigo-100 font-mono text-[11px] space-y-1.5 text-slate-700">
                          <div>
                            <span className="text-slate-400 block font-sans text-[10px] uppercase font-bold">Prescription IPFS CID:</span>
                            <span className="text-indigo-900 break-all">{recordDetails.prescriptionCid}</span>
                          </div>
                          {recordDetails.prescriptionChecksum && (
                            <div>
                              <span className="text-slate-400 block font-sans text-[10px] uppercase font-bold">Integrity Checksum:</span>
                              <span className="text-slate-800 break-all">{recordDetails.prescriptionChecksum}</span>
                            </div>
                          )}
                        </div>

                        <button
                          type="button"
                          disabled={activeDownloads[`${selectedRecordForDetails.id}_rx`]}
                          onClick={() => handleDownloadPrescription(
                            selectedRecordForDetails.id,
                            recordDetails.prescriptionFilename || `${selectedRecordForDetails.id}_prescription.pdf`
                          )}
                          className="w-full inline-flex items-center justify-center space-x-2 py-2 px-3 rounded-lg bg-[#147D78] hover:bg-[#116965] text-white font-semibold text-xs transition-colors cursor-pointer shadow-xs disabled:opacity-50"
                        >
                          {activeDownloads[`${selectedRecordForDetails.id}_rx`] ? (
                            <>
                              <Loader2 className="w-4 h-4 animate-spin text-white" />
                              <span>Decrypting &amp; Downloading Prescription...</span>
                            </>
                          ) : (
                            <>
                              <Download className="w-4 h-4" />
                              <span>Download Prescription Attachment ({recordDetails.prescriptionFilename || 'PDF'})</span>
                            </>
                          )}
                        </button>
                      </div>
                    ) : (
                      <p className="text-xs text-slate-500 italic bg-white/70 p-3 rounded-lg border border-indigo-100">
                        No prescription attachment was submitted for this record.
                      </p>
                    )}
                  </div>

                  {/* Primary Encrypted Document Summary */}
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2 text-xs font-bold text-slate-800">
                        <Lock className="w-4 h-4 text-slate-600" />
                        <span>Encrypted Medical Report Document</span>
                      </div>
                      <span className="text-[10px] text-slate-500">
                        {recordDetails?.hasDocument ? 'Document Included' : 'No Document Attached'}
                      </span>
                    </div>
                    <div className="font-mono text-[11px] text-slate-600 space-y-1">
                      <p>IPFS CID: <span className="text-[#147D78] break-all">{selectedRecordForDetails.ipfsCid}</span></p>
                      <p>Size: <span>{selectedRecordForDetails.fileSize}</span></p>
                      {selectedRecordForDetails.checksumSha256 && (
                        <p>Ledger SHA-256: <span className="text-slate-800 break-all">{selectedRecordForDetails.checksumSha256}</span></p>
                      )}
                    </div>
                    {recordDetails?.hasDocument !== false && (
                      <button
                        type="button"
                        disabled={activeDownloads[`${selectedRecordForDetails.id}_doc`]}
                        onClick={() => handleDownloadDocument(
                          selectedRecordForDetails.id,
                          recordDetails?.documentFilename || undefined
                        )}
                        className="w-full mt-2 inline-flex items-center justify-center space-x-2 py-2 px-3 rounded-lg bg-[#14263D] hover:bg-[#162e4a] text-white font-semibold text-xs transition-colors cursor-pointer shadow-xs disabled:opacity-50"
                      >
                        {activeDownloads[`${selectedRecordForDetails.id}_doc`] ? (
                          <>
                            <Loader2 className="w-4 h-4 animate-spin text-white" />
                            <span>Decrypting &amp; Downloading Document...</span>
                          </>
                        ) : (
                          <>
                            <Download className="w-4 h-4" />
                            <span>Download Decrypted Document ({selectedRecordForDetails.fileSize})</span>
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </>
              )}
            </div>

            {/* Footer */}
            <div className="px-6 py-3 bg-[#F5F7FA] border-t border-[#E1E7EF] flex items-center justify-between shrink-0">
              <button
                type="button"
                onClick={() => {
                  const recId = selectedRecordForDetails.id;
                  setSelectedRecordForDetails(null);
                  handleVerifyRecord(recId);
                }}
                className="px-3 py-1.5 rounded-lg border border-[#E1E7EF] hover:bg-slate-100 text-slate-700 font-semibold text-xs transition-colors flex items-center space-x-1.5 cursor-pointer"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-[#147D78]" />
                <span>Verify on Ledger</span>
              </button>
              <button
                type="button"
                onClick={() => setSelectedRecordForDetails(null)}
                className="px-4 py-1.5 rounded-lg bg-[#14263D] hover:bg-[#162e4a] text-white font-semibold text-xs transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>

          </div>
        </div>
      )}

      {/* Stat Cards Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Encrypted Records"
          value={totalRecordsCount}
          subtitle="Pinned on IPFS Kubo"
          icon={FileText}
          variant="teal"
        />
        <StatCard
          title="Active Consents"
          value={activeConsentsCount}
          subtitle="Physicians with active access"
          icon={ShieldCheck}
          variant="emerald"
        />
        <StatCard
          title="Pending Requests"
          value={pendingRequestsCount}
          subtitle="Awaiting your approval"
          icon={Clock}
          variant="amber"
        />
        <StatCard
          title="Audit Trail Logs"
          value={totalAuditLogsCount}
          subtitle="Ledger-verified access events"
          icon={History}
          variant="navy"
        />
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="border-b border-[#E1E7EF]">
        <nav className="flex space-x-8" aria-label="Tabs">
          <button
            onClick={() => setActiveTab('records')}
            className={`py-3 px-1 border-b-2 font-semibold text-xs inline-flex items-center space-x-2 transition-colors ${
              activeTab === 'records'
                ? 'border-[#147D78] text-[#147D78]'
                : 'border-transparent text-[#5B6675] hover:text-[#182230] hover:border-slate-300'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Medical Records ({records.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('consents')}
            className={`py-3 px-1 border-b-2 font-semibold text-xs inline-flex items-center space-x-2 transition-colors ${
              activeTab === 'consents'
                ? 'border-[#147D78] text-[#147D78]'
                : 'border-transparent text-[#5B6675] hover:text-[#182230] hover:border-slate-300'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Consent Management</span>
            {pendingRequestsCount > 0 && (
              <span className="bg-amber-100 text-amber-800 text-[10px] font-bold px-1.5 py-0.5 rounded-full ml-1">
                {pendingRequestsCount} pending
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('logs')}
            className={`py-3 px-1 border-b-2 font-semibold text-xs inline-flex items-center space-x-2 transition-colors ${
              activeTab === 'logs'
                ? 'border-[#147D78] text-[#147D78]'
                : 'border-transparent text-[#5B6675] hover:text-[#182230] hover:border-slate-300'
            }`}
          >
            <History className="w-4 h-4" />
            <span>Access Audit Logs ({auditLogs.length})</span>
          </button>
        </nav>
      </div>

      {/* TAB CONTENT 1: MEDICAL RECORDS */}
      {activeTab === 'records' && (
        <div className="space-y-4">
          
          {/* Filter & Search Bar */}
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs flex flex-col sm:flex-row gap-3 items-center justify-between">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search by title, hospital, or CID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full text-xs pl-9 pr-3 py-2 rounded-lg border border-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            <div className="flex items-center space-x-2 w-full sm:w-auto">
              <span className="text-xs text-slate-500 font-medium">Filter Type:</span>
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="text-xs px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
              >
                <option value="ALL">All Categories</option>
                <option value="LAB_REPORT">Lab Reports</option>
                <option value="PRESCRIPTION">Prescriptions</option>
                <option value="IMAGING_MRI">MRI Scans</option>
                <option value="IMAGING_XRAY">X-Rays</option>
                <option value="CLINICAL_SUMMARY">Clinical Summaries</option>
              </select>
            </div>
          </div>

          {/* Welcome guidance for new patient vaults with zero records */}
          {ownRecords.length === 0 && !isDemoUser && (
            <div className="bg-gradient-to-r from-teal-50 to-indigo-50 border border-teal-200 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs shadow-2xs">
              <div className="space-y-0.5">
                <p className="font-bold text-[#14263D] flex items-center space-x-1.5">
                  <ShieldCheck className="w-4 h-4 text-[#147D78]" />
                  <span>Welcome to your Sovereign Vault, {resolvedPatientName || 'Patient'}</span>
                </p>
                <p className="text-[#5B6675]">
                  You have not uploaded any personal medical records to your vault yet. Click "Upload Medical Record" to encrypt and pin your first document with zero-PHI protection.
                </p>
              </div>
              <button
                onClick={() => setIsUploadOpen(true)}
                className="shrink-0 px-3 py-1.5 rounded-lg bg-[#147D78] text-white font-semibold hover:bg-[#116965] transition-colors cursor-pointer"
              >
                + Upload First Record
              </button>
            </div>
          )}

          {/* Record Items */}
          <div className="space-y-3">
            {filteredRecords.length === 0 ? (
              <div className="text-center py-12 bg-white rounded-xl border border-dashed border-slate-300 p-6">
                <FileText className="w-10 h-10 text-slate-300 mx-auto mb-2" />
                <h3 className="text-sm font-semibold text-slate-700">No medical records found</h3>
                <p className="text-xs text-slate-500 mt-1">Try adjusting your filters or upload a new record.</p>
              </div>
            ) : (
              filteredRecords.map((record) => (
                <div 
                  key={record.id}
                  className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs hover:border-indigo-200 hover:shadow-xs transition-all"
                >
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div className="space-y-1.5 flex-1">
                      <div className="flex items-center space-x-2.5 flex-wrap">
                        <StatusBadge type={record.recordType} />
                        {record.patientId === patientId ? (
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 inline-flex items-center">
                            <CheckCircle className="w-3 h-3 text-emerald-600 mr-1 inline" />
                            Personal Record
                          </span>
                        ) : (
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-50 text-amber-800 border border-amber-200 inline-flex items-center">
                            <span className="w-1.5 h-1.5 rounded-full bg-amber-500 mr-1.5 inline-block"></span>
                            Demo Seed Record ({record.patientName || 'Eleanor Vance'})
                          </span>
                        )}
                        <span className="text-xs font-semibold text-slate-400">•</span>
                        <span className="text-xs font-medium text-slate-600">{record.hospital}</span>
                        <span className="text-xs font-semibold text-slate-400">•</span>
                        <span className="text-xs text-slate-500">
                          {new Date(record.createdAt).toLocaleDateString(undefined, {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric',
                          })}
                        </span>
                        {record.txHash && (
                          <span className="text-[10px] font-mono text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100">
                            Tx: {record.txHash.substring(0, 10)}...
                          </span>
                        )}
                      </div>
                      <h3 className="text-base font-bold text-slate-900">{record.title}</h3>
                      <div className="flex items-center space-x-3 text-xs text-slate-500 pt-1 flex-wrap gap-y-1">
                        <span className="inline-flex items-center space-x-1">
                          <Lock className="w-3 h-3 text-indigo-600" />
                          <span>{record.encryptionAlgorithm}</span>
                        </span>
                        <span>Key ID: <code className="text-slate-600 bg-slate-100 px-1 py-0.5 rounded font-mono text-[11px]">{record.keyFingerprint}</code></span>
                        <span>Size: {record.fileSize}</span>
                        {record.checksumSha256 && (
                          <span>Checksum: <code className="text-slate-600 bg-slate-100 px-1 py-0.5 rounded font-mono text-[11px]">{record.checksumSha256.substring(0, 12)}...</code></span>
                        )}
                      </div>
                    </div>

                    {/* IPFS CID details & Actions */}
                    <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2 lg:gap-3 bg-slate-50 p-2.5 rounded-lg border border-slate-200/80">
                      <div className="text-left sm:text-right">
                        <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">IPFS CID Hash</p>
                        <p className="text-xs font-mono text-slate-800 break-all max-w-xs">
                          {record.ipfsCid.substring(0, 16)}...{record.ipfsCid.substring(record.ipfsCid.length - 8)}
                        </p>
                      </div>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleDownloadDocument(record.id)}
                          disabled={activeDownloads[`${record.id}_doc`]}
                          className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-md bg-[#147D78]/10 border border-[#147D78]/25 text-[#147D78] hover:bg-[#147D78]/20 text-xs font-semibold transition-colors disabled:opacity-50 cursor-pointer"
                          title="Download and decrypt primary medical document"
                        >
                          {activeDownloads[`${record.id}_doc`] ? (
                            <>
                              <Loader2 className="w-3.5 h-3.5 animate-spin text-[#147D78]" />
                              <span>Downloading...</span>
                            </>
                          ) : (
                            <>
                              <Download className="w-3.5 h-3.5 text-[#147D78]" />
                              <span>Download</span>
                            </>
                          )}
                        </button>
                        <button
                          onClick={() => handleOpenRecordDetails(record)}
                          className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-md bg-[#14263D]/5 border border-[#14263D]/15 text-[#14263D] hover:bg-[#14263D]/10 text-xs font-semibold transition-colors cursor-pointer"
                          title="View clinical description & prescription attachment"
                        >
                          <Eye className="w-3.5 h-3.5 text-[#147D78]" />
                          <span>View Details</span>
                        </button>
                        <button
                          onClick={() => handleCopy(record.ipfsCid)}
                          className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-md bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 text-xs font-medium transition-colors"
                          title="Copy full IPFS CID hash"
                        >
                          {copiedCid === record.ipfsCid ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-600" />
                              <span className="text-emerald-700">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5 text-slate-500" />
                              <span>Copy CID</span>
                            </>
                          )}
                        </button>
                        <button
                          onClick={() => handleVerifyRecord(record.id)}
                          disabled={verifyingRecordId === record.id}
                          className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-md bg-teal-50 border border-teal-200 text-[#147D78] hover:bg-teal-100 text-xs font-semibold transition-colors disabled:opacity-50 cursor-pointer"
                          title="Verify SHA-256 against on-chain Fabric record metadata"
                        >
                          <ShieldCheck className="w-3.5 h-3.5 text-[#147D78]" />
                          <span>{verifyingRecordId === record.id ? 'Verifying...' : 'Verify Ledger'}</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

        </div>
      )}

      {/* TAB CONTENT 2: CONSENT MANAGEMENT */}
      {activeTab === 'consents' && (
        <div className="space-y-6">
          
          {/* Pending Consent Requests */}
          {pendingRequestsCount > 0 && (
            <div className="bg-amber-50/70 border border-amber-200 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <AlertTriangle className="w-5 h-5 text-amber-600" />
                  <h3 className="text-sm font-bold text-amber-900">
                    Pending Access Requests Requiring Patient Approval ({pendingRequestsCount})
                  </h3>
                </div>
              </div>

              <div className="space-y-3 pt-1">
                {consents.filter(c => c.status === 'PENDING').map(c => (
                  <div key={c.id} className="bg-white rounded-lg p-4 border border-amber-200/80 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-2xs">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-bold text-slate-900">{c.doctorName}</span>
                        <span className="text-xs text-slate-500">({c.specialty} • {c.hospital})</span>
                      </div>
                      <p className="text-xs text-slate-600 mt-1 font-medium">Purpose: "{c.purpose}"</p>
                      <div className="flex items-center space-x-3 text-xs text-slate-500 mt-2">
                        <span>Requested Scope: <strong className="text-slate-700">{Array.isArray(c.allowedRecordTypes) ? c.allowedRecordTypes.join(', ') : c.allowedRecordTypes}</strong></span>
                        <span>•</span>
                        <span>Expires on: {new Date(c.expiresAt).toLocaleDateString()}</span>
                        {c.txHash && (
                          <span className="text-[10px] font-mono text-indigo-700 bg-indigo-50 px-1.5 py-0.5 rounded">
                            Tx: {c.txHash.substring(0, 10)}...
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleConsentAction(c.id, 'REVOKE')}
                        disabled={isProcessingAction}
                        className="px-3 py-1.5 rounded-lg border border-rose-200 text-rose-700 hover:bg-rose-50 text-xs font-semibold transition-colors disabled:opacity-50"
                      >
                        Reject
                      </button>
                      <button
                        onClick={() => handleConsentAction(c.id, 'GRANT')}
                        disabled={isProcessingAction}
                        className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold transition-colors shadow-2xs disabled:opacity-50"
                      >
                        Grant Consent
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Active & Historical Consents Table */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-2xs overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900">Active & Historical Doctor Consents</h3>
                <p className="text-xs text-slate-500">All permissions granted to healthcare providers</p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
                <thead className="bg-slate-50 text-slate-600 font-semibold uppercase tracking-wider">
                  <tr>
                    <th scope="col" className="px-5 py-3">Physician / Facility</th>
                    <th scope="col" className="px-5 py-3">Status</th>
                    <th scope="col" className="px-5 py-3">Clinical Purpose</th>
                    <th scope="col" className="px-5 py-3">Record Scope</th>
                    <th scope="col" className="px-5 py-3">Fabric TxID</th>
                    <th scope="col" className="px-5 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 bg-white">
                  {consents.map((consent) => (
                    <tr key={consent.id} className="hover:bg-slate-50/70 transition-colors">
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <p className="font-bold text-slate-900">{consent.doctorName}</p>
                        <p className="text-[11px] text-slate-500">{consent.specialty} • {consent.hospital}</p>
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <StatusBadge status={consent.status} />
                      </td>
                      <td className="px-5 py-3.5 max-w-xs truncate text-slate-600" title={consent.purpose}>
                        {consent.purpose}
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap text-slate-700">
                        {Array.isArray(consent.allowedRecordTypes) 
                          ? consent.allowedRecordTypes.join(', ') 
                          : consent.allowedRecordTypes}
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap font-mono text-[11px] text-indigo-700">
                        <span title={consent.txHash}>
                          {consent.txHash ? `${consent.txHash.substring(0, 12)}...` : '—'}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 whitespace-nowrap text-right">
                        {consent.status === 'ACTIVE' ? (
                          <button
                            onClick={() => handleConsentAction(consent.id, 'REVOKE')}
                            disabled={isProcessingAction}
                            className="inline-flex items-center space-x-1 px-2.5 py-1 rounded border border-rose-200 text-rose-700 hover:bg-rose-50 font-semibold transition-colors"
                          >
                            <XCircle className="w-3.5 h-3.5" />
                            <span>Revoke Access</span>
                          </button>
                        ) : consent.status === 'REVOKED' ? (
                          <span className="text-slate-400 font-medium italic">Revoked</span>
                        ) : (
                          <span className="text-slate-400 font-medium italic">{consent.status}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}

      {/* TAB CONTENT 3: ACCESS AUDIT LOGS */}
      {activeTab === 'logs' && (
        <div className="bg-white rounded-xl border border-slate-200 shadow-2xs overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Hyperledger Fabric Access Trail</h3>
              <p className="text-xs text-slate-500">Every interaction with your records is cryptographically stamped to the ledger with SHA-256 hash chains</p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
              <thead className="bg-slate-50 text-slate-600 font-semibold uppercase tracking-wider">
                <tr>
                  <th scope="col" className="px-5 py-3">Timestamp</th>
                  <th scope="col" className="px-5 py-3">Actor / Entity</th>
                  <th scope="col" className="px-5 py-3">Action</th>
                  <th scope="col" className="px-5 py-3">Target Record</th>
                  <th scope="col" className="px-5 py-3">Purpose</th>
                  <th scope="col" className="px-5 py-3">Block Hash Chain</th>
                  <th scope="col" className="px-5 py-3">Fabric TxID</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white font-mono text-[11px]">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-5 py-3 whitespace-nowrap text-slate-500 font-sans">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-5 py-3 whitespace-nowrap font-sans font-medium text-slate-900">
                      {log.actorName} <span className="text-xs text-slate-400 font-normal">({log.actorRole})</span>
                    </td>
                    <td className="px-5 py-3 whitespace-nowrap font-sans">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700">
                        {log.action}
                      </span>
                    </td>
                    <td className="px-5 py-3 font-sans text-slate-700 max-w-xs truncate">
                      {log.recordTitle || '—'}
                    </td>
                    <td className="px-5 py-3 font-sans text-slate-600 max-w-xs truncate">
                      {log.purpose}
                    </td>
                    <td className="px-5 py-3 whitespace-nowrap text-slate-500 font-mono text-[10px]" title={`Prev: ${log.prevHash || 'Genesis'}\nEntry: ${log.entryHash || '—'}`}>
                      <span className="text-emerald-700 font-semibold flex items-center space-x-1">
                        <Layers className="w-3 h-3 text-emerald-600" />
                        <span>{log.entryHash ? `${log.entryHash.substring(0, 8)}...` : 'Genesis'}</span>
                      </span>
                    </td>
                    <td className="px-5 py-3 whitespace-nowrap text-indigo-700" title={log.txHash}>
                      {log.txHash ? `${log.txHash.substring(0, 12)}...` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Upload Modal */}
      <UploadRecordModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        patientId={patientId}
        patientName={resolvedPatientName}
        onRecordUploaded={(rec) => {
          onRecordAdded(rec);
          onRefresh();
        }}
      />

    </div>
  );
};
