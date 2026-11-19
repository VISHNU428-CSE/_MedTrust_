import React, { useState, useEffect, useCallback } from 'react';
import { 
  ShieldAlert, 
  Users, 
  ShieldCheck, 
  Activity, 
  RefreshCw, 
  UserCheck, 
  UserX, 
  Lock, 
  Server,
  Stethoscope,
  Clock,
  CheckCircle2,
  XCircle,
  FileText,
  AlertCircle,
  Check,
  X,
  Loader2
} from 'lucide-react';
import { apiService } from '../../services/api';
import type { 
  UserSummary, 
  AdminTelemetry, 
  AccessLog, 
  HealthCheckResponse,
  DoctorApplicationSummary 
} from '../../types';

interface AdminDashboardProps {
  platformHealth?: HealthCheckResponse | null;
  isBackendConnected?: boolean;
}

export const AdminDashboard: React.FC<AdminDashboardProps> = ({
  platformHealth,
  isBackendConnected
}) => {
  const [telemetry, setTelemetry] = useState<AdminTelemetry | null>(null);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [securityEvents, setSecurityEvents] = useState<AccessLog[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [updatingUserId, setUpdatingUserId] = useState<string | null>(null);
  const [feedbackMessage, setFeedbackMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null);

  // Doctor Applications Review state
  const [doctorApplications, setDoctorApplications] = useState<DoctorApplicationSummary[]>([]);
  const [applicationFilter, setApplicationFilter] = useState<'PENDING' | 'APPROVED' | 'REJECTED' | 'ALL'>('PENDING');
  const [isAppsLoading, setIsAppsLoading] = useState<boolean>(false);
  const [actionInProgressId, setActionInProgressId] = useState<string | null>(null);

  // Rejection Modal state
  const [rejectModalDoctor, setRejectModalDoctor] = useState<DoctorApplicationSummary | null>(null);
  const [rejectionReasonInput, setRejectionReasonInput] = useState<string>('');
  const [rejectionReasonError, setRejectionReasonError] = useState<string | null>(null);

  const fetchDoctorApplications = useCallback(async (filter: string = applicationFilter) => {
    setIsAppsLoading(true);
    try {
      const apps = await apiService.getDoctorApplications(filter);
      setDoctorApplications(apps);
    } catch {
      // In standalone/offline fallback, empty array
      setDoctorApplications([]);
    } finally {
      setIsAppsLoading(false);
    }
  }, [applicationFilter]);

  const fetchAdminData = useCallback(async () => {
    try {
      const [telemData, usersData, eventsData] = await Promise.all([
        apiService.getAdminTelemetry().catch(() => null),
        apiService.getAdminUsers().catch(() => []),
        apiService.getAdminSecurityEvents().catch(() => []),
      ]);
      setTelemetry(telemData);
      setUsers(usersData);
      setSecurityEvents(eventsData);
      await fetchDoctorApplications(applicationFilter);
    } catch {
      setFeedbackMessage({ text: 'Unable to refresh administrative telemetry.', type: 'error' });
    } finally {
      setIsLoading(false);
    }
  }, [applicationFilter, fetchDoctorApplications]);

  useEffect(() => {
    let isMounted = true;
    async function init() {
      try {
        const [telemData, usersData, eventsData, appsData] = await Promise.all([
          apiService.getAdminTelemetry().catch(() => null),
          apiService.getAdminUsers().catch(() => []),
          apiService.getAdminSecurityEvents().catch(() => []),
          apiService.getDoctorApplications(applicationFilter).catch(() => []),
        ]);
        if (isMounted) {
          if (telemData) setTelemetry(telemData);
          setUsers(usersData);
          setSecurityEvents(eventsData);
          setDoctorApplications(appsData);
        }
      } catch {
        if (isMounted) {
          setFeedbackMessage({ text: 'Unable to refresh administrative telemetry.', type: 'error' });
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }
    void init();
    return () => {
      isMounted = false;
    };
  }, [applicationFilter]);

  const handleRefresh = async () => {
    setIsLoading(true);
    await fetchAdminData();
  };

  const handleFilterChange = async (newFilter: 'PENDING' | 'APPROVED' | 'REJECTED' | 'ALL') => {
    setApplicationFilter(newFilter);
    await fetchDoctorApplications(newFilter);
  };

  const handleApproveDoctor = async (doctor: DoctorApplicationSummary) => {
    setActionInProgressId(doctor.id);
    setFeedbackMessage(null);
    try {
      const res = await apiService.approveDoctorApplication(doctor.id);
      setFeedbackMessage({
        text: `Doctor application for ${res.name || doctor.name} approved successfully. Account is active and immediate clinical access is granted.`,
        type: 'success',
      });
      await Promise.all([
        fetchDoctorApplications(applicationFilter),
        apiService.getAdminUsers().then(setUsers).catch(() => null),
        apiService.getAdminTelemetry().then(setTelemetry).catch(() => null),
      ]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to approve doctor application';
      setFeedbackMessage({ text: msg, type: 'error' });
    } finally {
      setActionInProgressId(null);
    }
  };

  const handleOpenRejectModal = (doctor: DoctorApplicationSummary) => {
    setRejectModalDoctor(doctor);
    setRejectionReasonInput('');
    setRejectionReasonError(null);
  };

  const handleConfirmReject = async () => {
    if (!rejectModalDoctor) return;
    const cleanReason = rejectionReasonInput.trim();
    if (!cleanReason || cleanReason.length < 5) {
      setRejectionReasonError('Please provide a meaningful rejection reason of at least 5 characters for the audit trail.');
      return;
    }
    setRejectionReasonError(null);
    setActionInProgressId(rejectModalDoctor.id);
    try {
      const res = await apiService.rejectDoctorApplication(rejectModalDoctor.id, cleanReason);
      setFeedbackMessage({
        text: `Doctor application for ${res.name || rejectModalDoctor.name} rejected. Account deactivated and active sessions revoked.`,
        type: 'success',
      });
      setRejectModalDoctor(null);
      await Promise.all([
        fetchDoctorApplications(applicationFilter),
        apiService.getAdminUsers().then(setUsers).catch(() => null),
        apiService.getAdminTelemetry().then(setTelemetry).catch(() => null),
      ]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to reject doctor application';
      setFeedbackMessage({ text: msg, type: 'error' });
    } finally {
      setActionInProgressId(null);
    }
  };

  const handleToggleUserStatus = async (user: UserSummary) => {
    setUpdatingUserId(user.id);
    setFeedbackMessage(null);
    try {
      const newStatus = !user.isActive;
      await apiService.updateUserStatus(user.id, newStatus);
      setFeedbackMessage({
        text: `User ${user.name} status updated to ${newStatus ? 'ACTIVE' : 'SUSPENDED'}.`,
        type: 'success',
      });
      await fetchAdminData();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to update user status';
      setFeedbackMessage({ text: msg, type: 'error' });
    } finally {
      setUpdatingUserId(null);
    }
  };

  const pendingCount = doctorApplications.filter(a => a.approvalStatus === 'PENDING').length;

  return (
    <div className="space-y-8 pb-12">
      
      {/* Header Banner */}
      <div className="rounded-3xl bg-[#14263D] text-white p-6 sm:p-8 shadow-sm border border-[#E1E7EF]/20 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-2">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-500/20 border border-indigo-400/40 text-indigo-300 text-xs font-semibold">
            <ShieldAlert className="w-4 h-4 text-indigo-400" />
            <span>Platform Governance &amp; Identity Administration</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
            Administrator Console
          </h1>
          <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
            Verify state clinician licenses, review pending applications, and manage session status under strict Zero-PHI isolation.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-white/10 border border-white/20 text-xs">
            <span className={`w-2 h-2 rounded-full ${isBackendConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
            <span>
              {isBackendConnected 
                ? (platformHealth?.fabricStatus ? 'Fabric Consensus Active' : 'Backend Live (8001)') 
                : 'Local Standby'}
            </span>
          </div>
          <button
            onClick={handleRefresh}
            disabled={isLoading}
            className="self-start md:self-auto inline-flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white text-xs font-semibold transition-all cursor-pointer disabled:opacity-60"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-teal-300 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh Telemetry</span>
          </button>
        </div>
      </div>

      {/* Notice Message */}
      {feedbackMessage && (
        <div className={`p-4 rounded-2xl border text-xs flex items-center justify-between ${
          feedbackMessage.type === 'success' 
            ? 'bg-teal-50 border-teal-200 text-teal-800' 
            : 'bg-red-50 border-red-200 text-red-800'
        }`}>
          <span>{feedbackMessage.text}</span>
          <button 
            onClick={() => setFeedbackMessage(null)}
            className="text-xs font-bold hover:underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Strict Privacy Boundary Alert Card */}
      <div className="rounded-2xl bg-amber-50 border border-amber-200 p-5 text-amber-900 text-xs space-y-2">
        <div className="flex items-center space-x-2 font-bold text-amber-950">
          <Lock className="w-4 h-4 text-amber-700 shrink-0" />
          <span>Zero-PHI Least Privilege Enforcement</span>
        </div>
        <p className="leading-relaxed text-amber-800">
          By cryptographic and architectural design, <strong>Platform Administrators have zero access to clinical EHR records</strong>, diagnostic imaging files, or decryption keys. Clinical records are exclusively accessible to patients and authorized clinicians via Hyperledger Fabric consent smart contracts.
        </p>
      </div>

      {/* Telemetry Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs space-y-2">
          <div className="flex items-center justify-between text-[#5B6675]">
            <span className="text-xs font-semibold">Total Accounts</span>
            <Users className="w-4 h-4 text-teal-600" />
          </div>
          <p className="text-2xl font-black text-[#182230]">
            {telemetry ? telemetry.totalUsers : users.length || '—'}
          </p>
          <p className="text-[11px] text-[#5B6675]">Persistent SQLite database</p>
        </div>

        <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs space-y-2">
          <div className="flex items-center justify-between text-[#5B6675]">
            <span className="text-xs font-semibold">Active Clinicians</span>
            <Stethoscope className="w-4 h-4 text-emerald-600" />
          </div>
          <p className="text-2xl font-black text-[#237A52]">
            {telemetry ? telemetry.roleCounts.doctor : users.filter(u => u.role === 'DOCTOR' && u.isActive).length || '—'}
          </p>
          <p className="text-[11px] text-[#5B6675]">Approved medical personnel</p>
        </div>

        <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs space-y-2">
          <div className="flex items-center justify-between text-[#5B6675]">
            <span className="text-xs font-semibold">Active Sessions</span>
            <Server className="w-4 h-4 text-indigo-600" />
          </div>
          <p className="text-2xl font-black text-indigo-700">
            {telemetry ? telemetry.activeSessions : '1+'}
          </p>
          <p className="text-[11px] text-[#5B6675]">Live JWT sessions in cache</p>
        </div>

        <div className="bg-white p-5 rounded-2xl border border-[#E1E7EF] shadow-2xs space-y-2">
          <div className="flex items-center justify-between text-[#5B6675]">
            <span className="text-xs font-semibold">Privacy Boundary</span>
            <ShieldCheck className="w-4 h-4 text-[#147D78]" />
          </div>
          <div className="flex items-center space-x-1.5 pt-1">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-sm font-bold text-emerald-700">Enforced</span>
          </div>
          <p className="text-[11px] text-[#5B6675]">Clinical endpoints strictly banned</p>
        </div>

      </div>

      {/* --- DOCTOR APPLICATION & LICENSURE REVIEW SECTION --- */}
      <div className="bg-white rounded-2xl border border-[#E1E7EF] shadow-2xs overflow-hidden space-y-0">
        
        {/* Section Header */}
        <div className="p-5 border-b border-[#E1E7EF] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <Stethoscope className="w-4 h-4 text-[#147D78]" />
              <h2 className="text-base font-bold text-[#182230]">Doctor Licensure &amp; Credential Applications</h2>
            </div>
            <p className="text-xs text-[#5B6675]">
              Verify state medical board license numbers and approve or reject clinician applications.
            </p>
          </div>

          {/* Status Filter Tabs */}
          <div className="flex items-center rounded-xl bg-[#F5F7FA] p-1 border border-[#E1E7EF] text-xs">
            <button
              onClick={() => handleFilterChange('PENDING')}
              className={`px-3 py-1 rounded-lg font-bold transition-all cursor-pointer ${
                applicationFilter === 'PENDING'
                  ? 'bg-white text-amber-900 shadow-2xs'
                  : 'text-[#5B6675] hover:text-[#182230]'
              }`}
            >
              Pending {pendingCount > 0 && `(${pendingCount})`}
            </button>
            <button
              onClick={() => handleFilterChange('APPROVED')}
              className={`px-3 py-1 rounded-lg font-bold transition-all cursor-pointer ${
                applicationFilter === 'APPROVED'
                  ? 'bg-white text-emerald-900 shadow-2xs'
                  : 'text-[#5B6675] hover:text-[#182230]'
              }`}
            >
              Approved
            </button>
            <button
              onClick={() => handleFilterChange('REJECTED')}
              className={`px-3 py-1 rounded-lg font-bold transition-all cursor-pointer ${
                applicationFilter === 'REJECTED'
                  ? 'bg-white text-red-900 shadow-2xs'
                  : 'text-[#5B6675] hover:text-[#182230]'
              }`}
            >
              Rejected
            </button>
            <button
              onClick={() => handleFilterChange('ALL')}
              className={`px-3 py-1 rounded-lg font-bold transition-all cursor-pointer ${
                applicationFilter === 'ALL'
                  ? 'bg-white text-[#14263D] shadow-2xs'
                  : 'text-[#5B6675] hover:text-[#182230]'
              }`}
            >
              All
            </button>
          </div>
        </div>

        {/* Applications Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#F5F7FA] border-b border-[#E1E7EF] text-[#5B6675] uppercase text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4 font-semibold">Clinician Applicant</th>
                <th className="py-3 px-4 font-semibold">Institution &amp; Specialty</th>
                <th className="py-3 px-4 font-semibold">License Number</th>
                <th className="py-3 px-4 font-semibold">Application Date</th>
                <th className="py-3 px-4 font-semibold">Status &amp; Review Info</th>
                <th className="py-3 px-4 font-semibold text-right">Administrative Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E1E7EF]">
              {doctorApplications.map((app) => {
                const isPending = app.approvalStatus === 'PENDING';
                const isApproved = app.approvalStatus === 'APPROVED';
                const isRejected = app.approvalStatus === 'REJECTED';
                const isActing = actionInProgressId === app.id;

                return (
                  <tr key={app.id} className="hover:bg-slate-50 transition-colors">
                    {/* Doctor Name & Email */}
                    <td className="py-3.5 px-4">
                      <p className="font-bold text-[#182230]">{app.name}</p>
                      <p className="text-[11px] text-[#5B6675] font-mono">{app.email}</p>
                      <p className="text-[10px] text-slate-400 font-mono mt-0.5">ID: {app.id}</p>
                    </td>

                    {/* Hospital & Specialty */}
                    <td className="py-3.5 px-4">
                      <p className="font-semibold text-[#182230]">{app.hospital || '—'}</p>
                      <p className="text-[11px] text-[#5B6675]">{app.specialty || 'General Practice'}</p>
                    </td>

                    {/* Medical License */}
                    <td className="py-3.5 px-4">
                      <span className="inline-flex items-center space-x-1 font-mono font-semibold text-teal-800 bg-teal-50 px-2 py-0.5 rounded border border-teal-200">
                        <FileText className="w-3 h-3 text-teal-600" />
                        <span>{app.licenseNumber || 'Unspecified'}</span>
                      </span>
                    </td>

                    {/* Date */}
                    <td className="py-3.5 px-4 text-[#5B6675]">
                      {app.appliedAt ? new Date(app.appliedAt).toLocaleDateString() : '—'}
                    </td>

                    {/* Status & Review Info */}
                    <td className="py-3.5 px-4">
                      <div className="space-y-1">
                        <span className={`inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${
                          isApproved ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                          isRejected ? 'bg-red-50 text-red-700 border-red-200' :
                          'bg-amber-50 text-amber-800 border-amber-200'
                        }`}>
                          {isApproved && <CheckCircle2 className="w-3 h-3 text-emerald-600" />}
                          {isRejected && <XCircle className="w-3 h-3 text-red-600" />}
                          {isPending && <Clock className="w-3 h-3 text-amber-600" />}
                          <span>{app.approvalStatus}</span>
                        </span>

                        {app.reviewedBy && (
                          <p className="text-[10px] text-slate-500">
                            By: <span className="font-mono">{app.reviewedBy}</span>
                          </p>
                        )}
                        {app.rejectionReason && (
                          <p className="text-[10px] text-red-700 bg-red-50/80 p-1 rounded border border-red-100 max-w-xs">
                            Reason: {app.rejectionReason}
                          </p>
                        )}
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="py-3.5 px-4 text-right">
                      <div className="inline-flex items-center space-x-2">
                        {isPending ? (
                          <>
                            <button
                              onClick={() => handleApproveDoctor(app)}
                              disabled={isActing}
                              className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white shadow-2xs transition-all cursor-pointer disabled:opacity-50"
                              title="Approve clinician application"
                            >
                              {isActing ? (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              ) : (
                                <Check className="w-3.5 h-3.5" />
                              )}
                              <span>Approve</span>
                            </button>

                            <button
                              onClick={() => handleOpenRejectModal(app)}
                              disabled={isActing}
                              className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-semibold border border-red-200 text-red-700 hover:bg-red-50 transition-all cursor-pointer disabled:opacity-50"
                              title="Reject clinician application"
                            >
                              <X className="w-3.5 h-3.5" />
                              <span>Reject</span>
                            </button>
                          </>
                        ) : isRejected ? (
                          <button
                            onClick={() => handleApproveDoctor(app)}
                            disabled={isActing}
                            className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-semibold border border-emerald-200 text-emerald-700 hover:bg-emerald-50 transition-all cursor-pointer disabled:opacity-50"
                            title="Re-evaluate and approve"
                          >
                            <Check className="w-3.5 h-3.5" />
                            <span>Approve</span>
                          </button>
                        ) : (
                          <span className="text-[11px] font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                            Active Clinician
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}

              {doctorApplications.length === 0 && !isAppsLoading && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-[#5B6675]">
                    No doctor applications found under status &apos;{applicationFilter}&apos;.
                  </td>
                </tr>
              )}
              {isAppsLoading && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-[#5B6675]">
                    <div className="flex items-center justify-center space-x-2">
                      <Loader2 className="w-4 h-4 animate-spin text-[#147D78]" />
                      <span>Loading doctor applications...</span>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* User Management Section */}
      <div className="bg-white rounded-2xl border border-[#E1E7EF] shadow-2xs overflow-hidden">
        <div className="p-5 border-b border-[#E1E7EF] flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-[#182230]">Registered Platform Accounts</h2>
            <p className="text-xs text-[#5B6675]">Manage user accounts, roles, and authorization status</p>
          </div>
          <span className="text-xs font-semibold bg-slate-100 text-slate-700 px-2.5 py-1 rounded-lg border border-slate-200">
            {users.length} Registered
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#F5F7FA] border-b border-[#E1E7EF] text-[#5B6675] uppercase text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4 font-semibold">User</th>
                <th className="py-3 px-4 font-semibold">Role</th>
                <th className="py-3 px-4 font-semibold">Hospital / Affiliation</th>
                <th className="py-3 px-4 font-semibold">Account ID</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E1E7EF]">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-slate-50 transition-colors">
                  <td className="py-3.5 px-4">
                    <p className="font-bold text-[#182230]">{u.name}</p>
                    <p className="text-[11px] text-[#5B6675] font-mono">{u.email}</p>
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                      u.role === 'PATIENT' ? 'bg-indigo-50 text-indigo-700 border-indigo-200' :
                      u.role === 'DOCTOR' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' :
                      u.role === 'ADMIN' ? 'bg-purple-50 text-purple-700 border-purple-200' :
                      'bg-amber-50 text-amber-700 border-amber-200'
                    }`}>
                      {u.role}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-[#5B6675]">
                    {u.hospital || '—'}
                  </td>
                  <td className="py-3.5 px-4 font-mono text-[11px] text-slate-500">
                    {u.id}
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="flex items-center space-x-1.5">
                      <span className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-bold ${
                        u.isActive 
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' 
                          : 'bg-red-50 text-red-700 border border-red-200'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${u.isActive ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
                        <span>{u.isActive ? 'ACTIVE' : 'SUSPENDED'}</span>
                      </span>
                      {u.role === 'DOCTOR' && u.approvalStatus && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                          {u.approvalStatus}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => handleToggleUserStatus(u)}
                      disabled={updatingUserId === u.id || u.role === 'ADMIN'}
                      className={`inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer disabled:opacity-40 ${
                        u.isActive
                          ? 'border border-red-200 text-red-700 hover:bg-red-50'
                          : 'border border-emerald-200 text-emerald-700 hover:bg-emerald-50'
                      }`}
                      title={u.role === 'ADMIN' ? 'Root Admin cannot be suspended' : ''}
                    >
                      {u.isActive ? (
                        <>
                          <UserX className="w-3.5 h-3.5" />
                          <span>Suspend</span>
                        </>
                      ) : (
                        <>
                          <UserCheck className="w-3.5 h-3.5" />
                          <span>Activate</span>
                        </>
                      )}
                    </button>
                  </td>
                </tr>
              ))}
              {users.length === 0 && !isLoading && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-[#5B6675]">
                    No registered accounts found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Events Section */}
      <div className="bg-white rounded-2xl border border-[#E1E7EF] shadow-2xs p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Activity className="w-4 h-4 text-indigo-600" />
            <h2 className="text-base font-bold text-[#182230]">Recent Platform Security Events</h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">Hyperledger Fabric Audit Trail</span>
        </div>

        <div className="space-y-2">
          {securityEvents.slice(0, 5).map((evt) => (
            <div key={evt.id} className="p-3 rounded-xl border border-[#E1E7EF] bg-[#F5F7FA] flex items-center justify-between text-xs">
              <div className="space-y-0.5">
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-[#182230]">{evt.actorName}</span>
                  <span className="text-[10px] text-slate-500 font-mono">({evt.actorRole})</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-200 text-slate-800">
                    {evt.action}
                  </span>
                </div>
                <p className="text-[11px] text-[#5B6675]">{evt.purpose}</p>
              </div>
              <div className="text-right text-[10px] text-slate-400 font-mono">
                <p>{new Date(evt.timestamp).toLocaleTimeString()}</p>
                <p className="truncate max-w-[120px]">{evt.txHash}</p>
              </div>
            </div>
          ))}
          {securityEvents.length === 0 && (
            <p className="text-xs text-[#5B6675] py-4 text-center">
              No recent administrative security events recorded.
            </p>
          )}
        </div>
      </div>

      {/* Rejection Reason Modal */}
      {rejectModalDoctor && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#14263D]/60 backdrop-blur-xs">
          <div className="bg-white rounded-2xl border border-[#E1E7EF] shadow-xl max-w-md w-full p-6 space-y-4">
            
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-2.5">
                <div className="p-2 rounded-xl bg-red-100 text-red-700">
                  <AlertCircle className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-[#182230]">Reject Clinician Application</h3>
                  <p className="text-xs text-[#5B6675]">{rejectModalDoctor.name}</p>
                </div>
              </div>
              <button
                onClick={() => setRejectModalDoctor(null)}
                className="text-[#5B6675] hover:text-[#182230] text-sm font-bold cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Applicant Details Recap */}
            <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs space-y-1">
              <div className="flex justify-between">
                <span className="text-slate-500">License Number:</span>
                <span className="font-mono font-bold text-[#182230]">{rejectModalDoctor.licenseNumber}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Hospital:</span>
                <span className="text-[#182230]">{rejectModalDoctor.hospital || '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Email:</span>
                <span className="font-mono text-[#182230]">{rejectModalDoctor.email}</span>
              </div>
            </div>

            {/* Reason Textarea */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-[#182230]">
                Administrative Rejection Reason (Required)
              </label>
              <textarea
                value={rejectionReasonInput}
                onChange={(e) => {
                  setRejectionReasonInput(e.target.value);
                  if (rejectionReasonError && e.target.value.trim().length >= 5) {
                    setRejectionReasonError(null);
                  }
                }}
                rows={3}
                placeholder="State medical board license number could not be verified in state registry..."
                className="w-full p-2.5 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 text-[#182230]"
              />
              <div className="flex items-center justify-between text-[11px]">
                <span className={rejectionReasonInput.trim().length >= 5 ? 'text-emerald-600' : 'text-slate-400'}>
                  {rejectionReasonInput.trim().length} / 5 characters minimum
                </span>
                <span className="text-slate-400">Logged to Fabric ledger</span>
              </div>
              {rejectionReasonError && (
                <p className="text-xs text-red-600 font-semibold">{rejectionReasonError}</p>
              )}
            </div>

            {/* Modal Actions */}
            <div className="flex items-center justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setRejectModalDoctor(null)}
                className="px-3 py-2 rounded-xl border border-[#E1E7EF] hover:bg-slate-50 text-xs font-semibold text-[#5B6675] cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmReject}
                disabled={rejectionReasonInput.trim().length < 5 || actionInProgressId === rejectModalDoctor.id}
                className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-semibold transition-all cursor-pointer disabled:opacity-50 flex items-center space-x-1.5"
              >
                {actionInProgressId === rejectModalDoctor.id ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Rejecting...</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-3.5 h-3.5" />
                    <span>Confirm Rejection</span>
                  </>
                )}
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
