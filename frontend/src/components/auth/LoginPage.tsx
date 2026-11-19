import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Lock, 
  Mail, 
  Eye, 
  EyeOff, 
  AlertCircle, 
  ArrowLeft, 
  Loader2, 
  CheckCircle2, 
  KeyRound, 
  User, 
  Stethoscope, 
  Clock,
  Building2,
  Info,
  ArrowRight,
  FileText
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { apiService } from '../../services/api';
import type { UserProfile, UserRole, DoctorApplicationResponse } from '../../types';

export type AuthMode = 'login' | 'register-patient' | 'register-doctor';

interface LoginPageProps {
  onSuccess: (user: UserProfile) => void;
  onBackToOverview: () => void;
  initialMode?: 'login' | 'register' | 'register-patient' | 'register-doctor';
  initialRole?: UserRole | null;
}

function resolveInitialMode(mode?: string): AuthMode {
  if (mode === 'register-doctor') return 'register-doctor';
  if (mode === 'register' || mode === 'register-patient') return 'register-patient';
  return 'login';
}

export const LoginPage: React.FC<LoginPageProps> = ({ 
  onSuccess, 
  onBackToOverview, 
  initialMode = 'login'
}) => {
  const { login, register, recoverPassword } = useAuth();
  const [authMode, setAuthMode] = useState<AuthMode>(() => resolveInitialMode(initialMode));
  
  // Login form state (no automatic demo credentials autofill)
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [rememberMe, setRememberMe] = useState<boolean>(true);

  // Patient Registration form state
  const [regName, setRegName] = useState<string>('');
  const [regEmail, setRegEmail] = useState<string>('');
  const [regPassword, setRegPassword] = useState<string>('');
  const [showRegPassword, setShowRegPassword] = useState<boolean>(false);

  // Doctor Registration form state
  const [drName, setDrName] = useState<string>('');
  const [drEmail, setDrEmail] = useState<string>('');
  const [drPassword, setDrPassword] = useState<string>('');
  const [showDrPassword, setShowDrPassword] = useState<boolean>(false);
  const [drHospital, setDrHospital] = useState<string>('');
  const [drSpecialty, setDrSpecialty] = useState<string>('');
  const [drLicenseNumber, setDrLicenseNumber] = useState<string>('');

  // Doctor Application Submission Confirmation state
  const [submittedDoctorApp, setSubmittedDoctorApp] = useState<DoctorApplicationResponse | null>(null);

  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Recovery modal state
  const [showRecoveryModal, setShowRecoveryModal] = useState<boolean>(false);
  const [recoveryEmail, setRecoveryEmail] = useState<string>('');
  const [recoverySubmitting, setRecoverySubmitting] = useState<boolean>(false);
  const [recoverySuccessMessage, setRecoverySuccessMessage] = useState<string | null>(null);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setErrorMessage('Please provide both email and password.');
      return;
    }
    setErrorMessage(null);
    setIsSubmitting(true);
    try {
      const user = await login(email.trim(), password);
      onSuccess(user);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Invalid credentials. Please verify your email and password.';
      setErrorMessage(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handlePatientRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!regName.trim() || !regEmail.trim() || !regPassword) {
      setErrorMessage('Please fill in all required patient registration fields.');
      return;
    }
    if (regPassword.length < 6) {
      setErrorMessage('Password must be at least 6 characters.');
      return;
    }
    setErrorMessage(null);
    setIsSubmitting(true);
    try {
      const user = await register({
        name: regName.trim(),
        email: regEmail.trim(),
        password: regPassword,
      });
      onSuccess(user);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Registration failed. Please check your details.';
      setErrorMessage(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDoctorRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (
      !drName.trim() ||
      !drEmail.trim() ||
      !drPassword ||
      !drHospital.trim() ||
      !drSpecialty.trim() ||
      !drLicenseNumber.trim()
    ) {
      setErrorMessage('All fields including Medical License Number are required for clinician applications.');
      return;
    }
    if (drPassword.length < 6) {
      setErrorMessage('Password must be at least 6 characters long.');
      return;
    }
    setErrorMessage(null);
    setIsSubmitting(true);
    try {
      const response = await apiService.registerDoctor({
        name: drName.trim(),
        email: drEmail.trim(),
        password: drPassword,
        hospital: drHospital.trim(),
        specialty: drSpecialty.trim(),
        licenseNumber: drLicenseNumber.trim(),
      });
      // Invariant: Do NOT create or assume an active session. Show pending confirmation screen.
      setSubmittedDoctorApp(response);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Doctor registration application failed.';
      setErrorMessage(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRecoverySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recoveryEmail) {
      setRecoveryError('Please enter your registered email address.');
      return;
    }
    setRecoverySubmitting(true);
    setRecoveryError(null);
    try {
      const res = await recoverPassword(recoveryEmail.trim());
      setRecoverySuccessMessage(res.message);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unable to submit recovery request.';
      setRecoveryError(msg);
    } finally {
      setRecoverySubmitting(false);
    }
  };

  const isPendingError = errorMessage && (
    errorMessage.toLowerCase().includes('pending') ||
    errorMessage.toLowerCase().includes('approval status is')
  );

  const isRejectedError = errorMessage && (
    errorMessage.toLowerCase().includes('rejected') ||
    errorMessage.toLowerCase().includes('not approved')
  );

  return (
    <div className="max-w-xl mx-auto py-8 px-4 sm:px-6">
      
      {/* Back Link */}
      <button
        onClick={onBackToOverview}
        className="inline-flex items-center space-x-1.5 text-xs font-semibold text-[#5B6675] hover:text-[#14263D] mb-6 transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        <span>Return to Platform Overview</span>
      </button>

      {/* Main Card */}
      <div className="bg-white rounded-2xl border border-[#E1E7EF] shadow-sm p-6 sm:p-8 space-y-6">
        
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#14263D] text-teal-400 mb-1 shadow-xs">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#182230]">
            {authMode === 'login' && 'Sign In to MedTrust'}
            {authMode === 'register-patient' && 'Register Sovereign Patient'}
            {authMode === 'register-doctor' && 'Clinician Registration & Licensure'}
          </h1>
          <p className="text-xs text-[#5B6675]">
            {authMode === 'login' && 'Unified sovereign health data & consent platform'}
            {authMode === 'register-patient' && 'Create a sovereign patient identity with client-side encryption'}
            {authMode === 'register-doctor' && 'Submit state medical board credentials for administrative verification'}
          </p>
        </div>

        {/* Accessible Mode Selector Tabs (Hidden if viewing doctor application submission confirmation) */}
        {!submittedDoctorApp && (
          <div 
            className="flex rounded-xl bg-[#F5F7FA] p-1 border border-[#E1E7EF]" 
            role="tablist" 
            aria-label="Authentication Mode"
          >
            <button
              type="button"
              role="tab"
              id="tab-login"
              aria-selected={authMode === 'login'}
              aria-controls="panel-login"
              tabIndex={authMode === 'login' ? 0 : -1}
              onClick={() => {
                setAuthMode('login');
                setErrorMessage(null);
              }}
              className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                authMode === 'login'
                  ? 'bg-white text-[#14263D] shadow-xs'
                  : 'text-[#5B6675] hover:text-[#182230]'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              role="tab"
              id="tab-register-patient"
              aria-selected={authMode === 'register-patient'}
              aria-controls="panel-register-patient"
              tabIndex={authMode === 'register-patient' ? 0 : -1}
              onClick={() => {
                setAuthMode('register-patient');
                setErrorMessage(null);
              }}
              className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                authMode === 'register-patient'
                  ? 'bg-white text-[#147D78] shadow-xs'
                  : 'text-[#5B6675] hover:text-[#182230]'
              }`}
            >
              Patient Signup
            </button>
            <button
              type="button"
              role="tab"
              id="tab-register-doctor"
              aria-selected={authMode === 'register-doctor'}
              aria-controls="panel-register-doctor"
              tabIndex={authMode === 'register-doctor' ? 0 : -1}
              onClick={() => {
                setAuthMode('register-doctor');
                setErrorMessage(null);
              }}
              className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all cursor-pointer ${
                authMode === 'register-doctor'
                  ? 'bg-white text-[#147D78] shadow-xs'
                  : 'text-[#5B6675] hover:text-[#182230]'
              }`}
            >
              Doctor Application
            </button>
          </div>
        )}

        {/* Specialized Error & Status Alert Cards */}
        {errorMessage && (
          <>
            {isPendingError ? (
              <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 text-xs space-y-1.5">
                <div className="flex items-center space-x-2 font-bold text-amber-950">
                  <Clock className="w-4 h-4 text-amber-700 shrink-0" />
                  <span>Doctor Application Pending Administrative Approval</span>
                </div>
                <p className="text-amber-800 leading-relaxed">
                  {errorMessage}
                </p>
                <p className="text-[11px] text-amber-700 pt-1">
                  Healthcare regulatory policy requires platform administrators to verify your medical license credentials before clinical record access is enabled.
                </p>
              </div>
            ) : isRejectedError ? (
              <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-900 text-xs space-y-1.5">
                <div className="flex items-center space-x-2 font-bold text-red-950">
                  <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
                  <span>Doctor Application Not Approved</span>
                </div>
                <p className="text-red-800 leading-relaxed">
                  {errorMessage}
                </p>
                <p className="text-[11px] text-red-700 pt-1">
                  If this was in error, please contact platform administration or submit a new application with verified state license credentials.
                </p>
              </div>
            ) : (
              <div className="p-3.5 rounded-xl bg-red-50 border border-red-200 flex items-start space-x-3 text-red-800 text-xs">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
                <div className="flex-1">
                  <p className="font-semibold">Authentication Notice</p>
                  <p className="text-red-700 mt-0.5">{errorMessage}</p>
                </div>
              </div>
            )}
          </>
        )}

        {/* View A: Doctor Application Confirmation Screen */}
        {submittedDoctorApp ? (
          <div className="space-y-6 pt-2">
            <div className="p-5 rounded-2xl bg-gradient-to-br from-teal-50 to-emerald-50 border border-teal-200 space-y-4">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 rounded-xl bg-teal-600 text-white shadow-xs">
                  <Clock className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-[#14263D]">Application Submitted Successfully</h2>
                  <p className="text-xs text-[#5B6675]">Status: Pending Administrative Review</p>
                </div>
              </div>

              <p className="text-xs text-[#182230] leading-relaxed">
                Thank you, <strong>{submittedDoctorApp.name}</strong>. Your clinician application has been securely recorded on the platform and is currently awaiting administrator review.
              </p>

              {/* Application Details Summary Box */}
              <div className="p-3.5 rounded-xl bg-white border border-teal-100 space-y-2 text-xs">
                <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                  <span className="text-[#5B6675]">Application ID:</span>
                  <span className="font-mono font-bold text-[#182230]">{submittedDoctorApp.id}</span>
                </div>
                <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                  <span className="text-[#5B6675]">Medical License Number:</span>
                  <span className="font-mono font-semibold text-teal-800 bg-teal-50 px-2 py-0.5 rounded border border-teal-200">
                    {submittedDoctorApp.licenseNumber}
                  </span>
                </div>
                <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                  <span className="text-[#5B6675]">Hospital / Affiliation:</span>
                  <span className="font-semibold text-[#182230]">{submittedDoctorApp.hospital || '—'}</span>
                </div>
                <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                  <span className="text-[#5B6675]">Clinical Specialty:</span>
                  <span className="font-semibold text-[#182230]">{submittedDoctorApp.specialty || '—'}</span>
                </div>
                <div className="flex items-center justify-between pt-1">
                  <span className="text-[#5B6675]">Registered Email:</span>
                  <span className="font-mono text-[#182230]">{submittedDoctorApp.email}</span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-white/80 border border-teal-100 text-[11px] text-[#5B6675] leading-relaxed flex items-start space-x-2">
                <Info className="w-4 h-4 text-teal-700 shrink-0 mt-0.5" />
                <span>
                  <strong>Compliance Guardrail:</strong> In accordance with healthcare least-privilege standards, no authenticated session or clinical access is provisioned until a platform administrator verifies your credentials.
                </span>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-3">
              <button
                type="button"
                onClick={() => {
                  setEmail(submittedDoctorApp.email);
                  setPassword('');
                  setSubmittedDoctorApp(null);
                  setAuthMode('login');
                  setErrorMessage(null);
                }}
                className="flex-1 py-2.5 px-4 rounded-xl bg-[#14263D] hover:bg-[#162e4a] text-white text-xs font-semibold shadow-xs flex items-center justify-center space-x-2 transition-all cursor-pointer"
              >
                <span>Proceed to Sign In</span>
                <ArrowRight className="w-3.5 h-3.5 text-teal-300" />
              </button>
              <button
                type="button"
                onClick={onBackToOverview}
                className="py-2.5 px-4 rounded-xl border border-[#E1E7EF] hover:bg-slate-50 text-xs font-semibold text-[#5B6675] transition-colors cursor-pointer"
              >
                Return to Overview
              </button>
            </div>
          </div>
        ) : authMode === 'login' ? (
          /* View B: Clean Standard Sign In Panel */
          <div id="panel-login" role="tabpanel" aria-labelledby="tab-login" className="space-y-6">
            
            {/* Informational Role Guidance Banner */}
            <div className="rounded-xl border border-teal-100 bg-gradient-to-br from-teal-50/60 to-slate-50 p-4 space-y-2">
              <div className="flex items-start space-x-2.5">
                <Info className="w-4 h-4 text-[#147D78] shrink-0 mt-0.5" />
                <div className="text-xs">
                  <p className="font-bold text-[#14263D]">Secure Multi-Role Access</p>
                  <p className="text-[#5B6675] mt-0.5 leading-relaxed">
                    Patients, approved clinicians, compliance auditors, and administrators sign in using their registered institutional or personal credentials.
                  </p>
                </div>
              </div>
            </div>

            {/* Credentials Form (Clean - No staff demo autofill shortcuts) */}
            <form onSubmit={handleLoginSubmit} className="space-y-4">
              
              {/* Email */}
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-[#182230]">
                  Registered Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                    <Mail className="w-4 h-4" />
                  </div>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@example.med"
                    className="w-full pl-9 pr-3 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230] placeholder:text-[#5B6675]/50 transition-all"
                  />
                </div>
              </div>

              {/* Password */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-semibold text-[#182230]">
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setRecoveryEmail(email);
                      setRecoverySuccessMessage(null);
                      setRecoveryError(null);
                      setShowRecoveryModal(true);
                    }}
                    className="text-[11px] font-semibold text-[#147D78] hover:underline cursor-pointer"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full pl-9 pr-10 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230] placeholder:text-[#5B6675]/50 transition-all font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-[#5B6675] hover:text-[#182230] cursor-pointer"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Remember Session */}
              <div className="flex items-center justify-between pt-1">
                <label className="flex items-center space-x-2 text-xs text-[#5B6675] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="rounded border-[#E1E7EF] text-[#147D78] focus:ring-[#147D78] h-3.5 w-3.5"
                  />
                  <span>Remember session token</span>
                </label>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 px-4 rounded-xl bg-[#14263D] hover:bg-[#162e4a] text-white text-xs font-semibold shadow-xs flex items-center justify-center space-x-2 transition-all cursor-pointer disabled:opacity-60"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-teal-400" />
                    <span>Authenticating with Backend...</span>
                  </>
                ) : (
                  <>
                    <KeyRound className="w-4 h-4 text-teal-400" />
                    <span>Authenticate &amp; Route to Dashboard</span>
                  </>
                )}
              </button>
            </form>
          </div>
        ) : authMode === 'register-patient' ? (
          /* View C: Sovereign Patient Self-Registration */
          <div id="panel-register-patient" role="tabpanel" aria-labelledby="tab-register-patient" className="space-y-4">
            
            <div className="p-3.5 rounded-xl bg-teal-50 border border-teal-200 text-teal-950 text-xs space-y-1">
              <div className="flex items-start space-x-2">
                <User className="w-4 h-4 text-[#147D78] shrink-0 mt-0.5" />
                <div>
                  <p className="font-bold text-[#14263D]">Sovereign Patient Self-Registration</p>
                  <p className="text-teal-800 mt-0.5 leading-relaxed">
                    Creates an encrypted sovereign health vault with an automated patient ID and zero-knowledge credentials.
                  </p>
                </div>
              </div>
            </div>

            <form onSubmit={handlePatientRegisterSubmit} className="space-y-4 pt-1">
              {/* Name */}
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-[#182230]">
                  Full Legal Name
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                    <User className="w-4 h-4" />
                  </div>
                  <input
                    type="text"
                    required
                    value={regName}
                    onChange={(e) => setRegName(e.target.value)}
                    placeholder="e.g. Jane Doe"
                    className="w-full pl-9 pr-3 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230]"
                  />
                </div>
              </div>

              {/* Email */}
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-[#182230]">
                  Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                    <Mail className="w-4 h-4" />
                  </div>
                  <input
                    type="email"
                    required
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="patient@example.med"
                    className="w-full pl-9 pr-3 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230]"
                  />
                </div>
              </div>

              {/* Password */}
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-[#182230]">
                  Create Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    type={showRegPassword ? 'text' : 'password'}
                    required
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    placeholder="Minimum 6 characters"
                    className="w-full pl-9 pr-10 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230] font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowRegPassword(!showRegPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-[#5B6675] hover:text-[#182230] cursor-pointer"
                    aria-label={showRegPassword ? 'Hide password' : 'Show password'}
                  >
                    {showRegPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Register Submit Button */}
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 px-4 rounded-xl bg-[#147D78] hover:bg-[#116964] text-white text-xs font-semibold shadow-xs flex items-center justify-center space-x-2 transition-all cursor-pointer disabled:opacity-60"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-white" />
                    <span>Registering Sovereign Account...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4 text-teal-200" />
                    <span>Create Patient Account &amp; Launch Vault</span>
                  </>
                )}
              </button>
            </form>
          </div>
        ) : (
          /* View D: Doctor Licensure Registration Form */
          <div id="panel-register-doctor" role="tabpanel" aria-labelledby="tab-register-doctor" className="space-y-4">
            
            <div className="p-3.5 rounded-xl bg-teal-50 border border-teal-200 text-teal-950 text-xs space-y-1">
              <div className="flex items-start space-x-2">
                <Stethoscope className="w-4 h-4 text-[#147D78] shrink-0 mt-0.5" />
                <div>
                  <p className="font-bold text-[#14263D]">Clinician Registration &amp; Licensure</p>
                  <p className="text-teal-800 mt-0.5 leading-relaxed">
                    Doctor registrations require state medical license verification by platform administration before clinical access is granted.
                  </p>
                </div>
              </div>
            </div>

            <form onSubmit={handleDoctorRegisterSubmit} className="space-y-3.5 pt-1">
              {/* Full Name */}
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-[#182230]">
                  Full Legal Name &amp; Title
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                    <User className="w-4 h-4" />
                  </div>
                  <input
                    type="text"
                    required
                    value={drName}
                    onChange={(e) => setDrName(e.target.value)}
                    placeholder="e.g. Dr. Sarah Connor, MD"
                    className="w-full pl-9 pr-3 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230]"
                  />
                </div>
              </div>

              {/* Institutional Email */}
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-[#182230]">
                  Institutional / Work Email
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                    <Mail className="w-4 h-4" />
                  </div>
                  <input
                    type="email"
                    required
                    value={drEmail}
                    onChange={(e) => setDrEmail(e.target.value)}
                    placeholder="e.g. s.connor@stjude.org"
                    className="w-full pl-9 pr-3 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230]"
                  />
                </div>
              </div>

              {/* Password */}
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-[#182230]">
                  Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    type={showDrPassword ? 'text' : 'password'}
                    required
                    value={drPassword}
                    onChange={(e) => setDrPassword(e.target.value)}
                    placeholder="Minimum 6 characters"
                    className="w-full pl-9 pr-10 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230] font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowDrPassword(!showDrPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-[#5B6675] hover:text-[#182230] cursor-pointer"
                    aria-label={showDrPassword ? 'Hide password' : 'Show password'}
                  >
                    {showDrPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Hospital Affiliation & Specialty (2 Columns) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="block text-xs font-semibold text-[#182230]">
                    Hospital / Health System
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                      <Building2 className="w-4 h-4" />
                    </div>
                    <input
                      type="text"
                      required
                      value={drHospital}
                      onChange={(e) => setDrHospital(e.target.value)}
                      placeholder="e.g. St. Jude Hospital"
                      className="w-full pl-9 pr-3 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230]"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="block text-xs font-semibold text-[#182230]">
                    Medical Specialty
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                      <Stethoscope className="w-4 h-4" />
                    </div>
                    <input
                      type="text"
                      required
                      value={drSpecialty}
                      onChange={(e) => setDrSpecialty(e.target.value)}
                      placeholder="e.g. Pediatrics & Oncology"
                      className="w-full pl-9 pr-3 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230]"
                    />
                  </div>
                </div>
              </div>

              {/* State Medical License Number */}
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-[#182230]">
                  State Medical License Number (Required)
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#5B6675]">
                    <FileText className="w-4 h-4" />
                  </div>
                  <input
                    type="text"
                    required
                    value={drLicenseNumber}
                    onChange={(e) => setDrLicenseNumber(e.target.value)}
                    placeholder="e.g. MED-LIC-IL-592812"
                    className="w-full pl-9 pr-3 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:ring-2 focus:ring-[#147D78]/20 focus:border-[#147D78] bg-white text-[#182230] font-mono"
                  />
                </div>
                <p className="text-[10px] text-[#5B6675]">
                  Cross-referenced by platform administration against state medical registry.
                </p>
              </div>

              {/* Submit Doctor Application Button */}
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 px-4 rounded-xl bg-[#14263D] hover:bg-[#162e4a] text-white text-xs font-semibold shadow-xs flex items-center justify-center space-x-2 transition-all cursor-pointer disabled:opacity-60 mt-2"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-teal-400" />
                    <span>Submitting Application for Administrative Review...</span>
                  </>
                ) : (
                  <>
                    <Stethoscope className="w-4 h-4 text-teal-300" />
                    <span>Submit Clinician Credential Application</span>
                  </>
                )}
              </button>
            </form>
          </div>
        )}

      </div>

      {/* Account Recovery Modal */}
      {showRecoveryModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#14263D]/60 backdrop-blur-xs">
          <div className="bg-white rounded-2xl border border-[#E1E7EF] shadow-xl max-w-sm w-full p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold text-[#182230] flex items-center space-x-2">
                <KeyRound className="w-4 h-4 text-[#147D78]" />
                <span>Account Recovery</span>
              </h2>
              <button
                onClick={() => setShowRecoveryModal(false)}
                className="text-[#5B6675] hover:text-[#182230] text-sm font-bold cursor-pointer"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-[#5B6675]">
              Enter your registered healthcare email. If the account exists in SQLite storage, password reset instructions will be generated.
            </p>

            {recoverySuccessMessage && (
              <div className="p-3 rounded-xl bg-teal-50 border border-teal-200 text-teal-800 text-xs flex items-start space-x-2">
                <CheckCircle2 className="w-4 h-4 text-teal-600 shrink-0 mt-0.5" />
                <span>{recoverySuccessMessage}</span>
              </div>
            )}

            {recoveryError && (
              <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-800 text-xs">
                {recoveryError}
              </div>
            )}

            {!recoverySuccessMessage && (
              <form onSubmit={handleRecoverySubmit} className="space-y-3">
                <input
                  type="email"
                  required
                  value={recoveryEmail}
                  onChange={(e) => setRecoveryEmail(e.target.value)}
                  placeholder="name@example.med"
                  className="w-full px-3 py-2 text-xs border border-[#E1E7EF] rounded-xl focus:outline-none focus:border-[#147D78]"
                />
                <button
                  type="submit"
                  disabled={recoverySubmitting}
                  className="w-full py-2 rounded-xl bg-[#147D78] text-white text-xs font-semibold hover:bg-[#116964] transition-colors cursor-pointer disabled:opacity-60"
                >
                  {recoverySubmitting ? 'Submitting...' : 'Send Recovery Instructions'}
                </button>
              </form>
            )}

            <div className="pt-2 text-right">
              <button
                type="button"
                onClick={() => setShowRecoveryModal(false)}
                className="text-xs font-semibold text-[#5B6675] hover:text-[#182230] cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
