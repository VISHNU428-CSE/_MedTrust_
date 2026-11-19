import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Database, 
  LogOut, 
  LogIn, 
  User, 
  Stethoscope, 
  ShieldAlert, 
  Activity,
  Globe
} from 'lucide-react';
import type { ActiveView, UserProfile, HealthCheckResponse } from '../../types';

interface NavbarProps {
  currentView: ActiveView;
  onViewChange: (view: ActiveView) => void;
  currentUser: UserProfile | null;
  isAuthenticated: boolean;
  onSignOut: () => void;
  isBackendConnected: boolean;
  platformHealth?: HealthCheckResponse | null;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentView,
  onViewChange,
  currentUser,
  isAuthenticated,
  onSignOut,
  isBackendConnected,
  platformHealth,
}) => {
  const [showSignOutConfirm, setShowSignOutConfirm] = useState<boolean>(false);
  return (
    <header className="bg-white border-b border-[#E1E7EF] sticky top-0 z-40 shadow-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Brand & Platform Identifier */}
          <button 
            onClick={() => onViewChange('LANDING')}
            className="flex items-center space-x-3 text-left focus:outline-hidden group cursor-pointer"
          >
            <div className="bg-[#14263D] group-hover:bg-[#162e4a] text-teal-400 p-2 rounded-xl shadow-xs flex items-center justify-center transition-colors">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-lg font-extrabold tracking-tight text-[#14263D]">MedTrust</span>
                <span className="text-[10px] bg-[#147D78]/10 text-[#147D78] font-bold px-2 py-0.5 rounded-full border border-[#147D78]/20">
                  Fabric + IPFS
                </span>
              </div>
              <p className="text-[11px] text-[#5B6675] hidden sm:block">
                Decentralized Health Records &amp; Sovereign Consent
              </p>
            </div>
          </button>

          {/* Center Navigation & Active Context */}
          <nav aria-label="Portal Navigation" className="flex items-center space-x-1">
            {!isAuthenticated ? (
              <div className="hidden md:flex items-center bg-[#F5F7FA] p-1 rounded-xl border border-[#E1E7EF] text-xs font-semibold text-[#5B6675]">
                <button
                  onClick={() => onViewChange('LANDING')}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                    currentView === 'LANDING'
                      ? 'bg-white text-[#147D78] shadow-xs'
                      : 'hover:text-[#182230]'
                  }`}
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Overview</span>
                </button>
                <div className="h-4 w-px bg-[#E1E7EF] mx-1"></div>
                <button
                  onClick={() => onViewChange('PATIENT')}
                  className={`flex items-center space-x-1 px-2.5 py-1.5 rounded-lg transition-all cursor-pointer ${
                    currentView === 'PATIENT' ? 'bg-white text-indigo-700 shadow-xs' : 'hover:text-[#182230]'
                  }`}
                  title="Patient Sovereign Vault"
                >
                  <User className="w-3.5 h-3.5 text-indigo-600" />
                  <span>Patient</span>
                </button>
                <button
                  onClick={() => onViewChange('DOCTOR')}
                  className={`flex items-center space-x-1 px-2.5 py-1.5 rounded-lg transition-all cursor-pointer ${
                    currentView === 'DOCTOR' ? 'bg-white text-teal-700 shadow-xs' : 'hover:text-[#182230]'
                  }`}
                  title="Doctor Clinical Portal"
                >
                  <Stethoscope className="w-3.5 h-3.5 text-teal-600" />
                  <span>Doctor</span>
                </button>
                <button
                  onClick={() => onViewChange('ADMIN')}
                  className={`flex items-center space-x-1 px-2.5 py-1.5 rounded-lg transition-all cursor-pointer ${
                    currentView === 'ADMIN' ? 'bg-white text-indigo-800 shadow-xs' : 'hover:text-[#182230]'
                  }`}
                  title="Platform Administrator Console"
                >
                  <ShieldAlert className="w-3.5 h-3.5 text-indigo-700" />
                  <span>Admin</span>
                </button>
                <button
                  onClick={() => onViewChange('AUDITOR')}
                  className={`flex items-center space-x-1 px-2.5 py-1.5 rounded-lg transition-all cursor-pointer ${
                    currentView === 'AUDITOR' ? 'bg-white text-amber-700 shadow-xs' : 'hover:text-[#182230]'
                  }`}
                  title="Compliance Audit Ledger"
                >
                  <Activity className="w-3.5 h-3.5 text-amber-700" />
                  <span>Auditor</span>
                </button>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => currentUser?.role && onViewChange(currentUser.role as any)}
                className="flex items-center bg-[#F5F7FA] hover:bg-slate-100 px-3 py-1.5 rounded-xl border border-[#E1E7EF] text-xs font-bold text-[#14263D] transition-colors cursor-pointer"
                title="Go to your authorized portal"
              >
                {currentUser?.role === 'PATIENT' && (
                  <span className="flex items-center space-x-1.5 text-indigo-900">
                    <User className="w-4 h-4 text-indigo-600" />
                    <span>Patient Sovereign Vault</span>
                  </span>
                )}
                {currentUser?.role === 'DOCTOR' && (
                  <span className="flex items-center space-x-1.5 text-teal-900">
                    <Stethoscope className="w-4 h-4 text-[#147D78]" />
                    <span>Doctor Clinical Portal</span>
                  </span>
                )}
                {currentUser?.role === 'ADMIN' && (
                  <span className="flex items-center space-x-1.5 text-slate-900">
                    <ShieldAlert className="w-4 h-4 text-indigo-700" />
                    <span>Platform Administrator Console</span>
                  </span>
                )}
                {currentUser?.role === 'AUDITOR' && (
                  <span className="flex items-center space-x-1.5 text-amber-900">
                    <Activity className="w-4 h-4 text-amber-700" />
                    <span>Compliance Audit Ledger</span>
                  </span>
                )}
              </button>
            )}
          </nav>

          {/* Right Status & Auth Actions */}
          <div className="flex items-center space-x-3">
            
            {/* Infrastructure Telemetry Pill */}
            <div className="hidden lg:flex items-center space-x-2 px-2.5 py-1 rounded-md text-xs font-medium border bg-[#F5F7FA] text-[#5B6675] border-[#E1E7EF]">
              <span className={`w-2 h-2 rounded-full ${isBackendConnected ? 'bg-[#237A52] animate-pulse' : 'bg-[#9A6700]'}`}></span>
              <Database className="w-3.5 h-3.5 text-[#5B6675]" />
              <span>
                {isBackendConnected 
                  ? (platformHealth?.fabricStatus ? 'Fabric Consensus Live' : 'Backend Live (8001)') 
                  : 'Local Standby'}
              </span>
            </div>

            {/* Auth Action: Sign In button OR User Profile & Sign Out */}
            {!isAuthenticated ? (
              <button
                onClick={() => onViewChange('LOGIN')}
                className={`inline-flex items-center space-x-1.5 px-4 py-2 rounded-xl text-xs font-bold transition-all shadow-xs cursor-pointer ${
                  currentView === 'LOGIN'
                    ? 'bg-[#147D78] text-white'
                    : 'bg-[#14263D] hover:bg-[#162e4a] text-white'
                }`}
              >
                <LogIn className="w-3.5 h-3.5 text-teal-400" />
                <span>Sign In</span>
              </button>
            ) : (
              <div className="flex items-center space-x-3">
                {/* User chip */}
                <div className="hidden sm:block text-right">
                  <p className="text-xs font-bold text-[#182230] leading-tight">
                    {currentUser?.name}
                  </p>
                  <p className="text-[10px] text-[#5B6675] leading-tight">
                    {currentUser?.hospital || currentUser?.role}
                  </p>
                </div>

                {/* Avatar */}
                <div className="w-8 h-8 rounded-full bg-[#14263D] text-teal-300 border border-[#E1E7EF] flex items-center justify-center font-bold text-xs shadow-xs">
                  {currentUser?.name?.charAt(0) || 'U'}
                </div>

                {/* Sign Out Button */}
                <button
                  onClick={() => setShowSignOutConfirm(true)}
                  title="Sign out of sovereign session"
                  className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-xl border border-red-200 text-red-700 bg-red-50/60 hover:bg-red-100/80 text-xs font-semibold transition-all cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5 text-red-600" />
                  <span className="hidden sm:inline">Sign Out</span>
                </button>
              </div>
            )}

          </div>

        </div>
      </div>

      {/* Accessible Sign Out Confirmation Modal */}
      {showSignOutConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#14263D]/60 backdrop-blur-xs">
          <div className="bg-white rounded-2xl border border-[#E1E7EF] shadow-xl max-w-sm w-full p-6 space-y-4">
            <div className="flex items-center space-x-3 text-red-600">
              <div className="w-10 h-10 rounded-xl bg-red-50 border border-red-100 flex items-center justify-center">
                <LogOut className="w-5 h-5 text-red-600" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-[#182230]">Confirm Session Sign Out</h3>
                <p className="text-xs text-[#5B6675]">MedTrust Sovereign Security</p>
              </div>
            </div>

            <p className="text-xs text-[#5B6675] leading-relaxed">
              Are you sure you want to sign out, <strong className="text-[#182230]">{currentUser?.name}</strong>? 
              Your active session token will be revoked on the backend and removed from session storage.
            </p>

            <div className="flex items-center justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setShowSignOutConfirm(false)}
                className="px-3.5 py-2 rounded-xl text-xs font-semibold text-[#5B6675] hover:bg-slate-100 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowSignOutConfirm(false);
                  onSignOut();
                }}
                className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-bold transition-all shadow-xs cursor-pointer flex items-center space-x-1.5"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Confirm Sign Out</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};
