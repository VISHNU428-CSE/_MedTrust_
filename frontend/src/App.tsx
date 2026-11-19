import { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/common/Navbar';
import { LandingPage } from './components/landing/LandingPage';
import { LoginPage } from './components/auth/LoginPage';
import { PatientDashboard } from './components/patient/PatientDashboard';
import { DoctorDashboard } from './components/doctor/DoctorDashboard';
import { AuditorDashboard } from './components/auditor/AuditorDashboard';
import { AdminDashboard } from './components/admin/AdminDashboard';
import { AuthProvider, useAuth } from './context/AuthContext';
import type { ActiveView, MedicalRecord, ConsentRecord, AccessLog, HealthCheckResponse, UserProfile, UserRole } from './types';
import { 
  apiService, 
  INITIAL_RECORDS, 
  INITIAL_CONSENTS, 
  INITIAL_AUDIT_LOGS 
} from './services/api';
import { Shield, Database, Lock, Server, AlertTriangle, ArrowLeft } from 'lucide-react';

function MainApp() {
  const { user, isAuthenticated, logout } = useAuth();
  const [currentView, setCurrentView] = useState<ActiveView>(() => {
    const savedUser = apiService.getSavedUser();
    const savedView = sessionStorage.getItem('medtrust_active_view') as ActiveView | null;
    if (savedUser && savedView && (savedView === savedUser.role || savedView === 'LANDING')) {
      return savedView;
    }
    return savedUser ? (savedUser.role as ActiveView) : 'LANDING';
  });
  const [authMode, setAuthMode] = useState<'login' | 'register' | 'register-patient' | 'register-doctor'>('login');
  const [targetLoginRole, setTargetLoginRole] = useState<UserRole | null>(null);
  const [records, setRecords] = useState<MedicalRecord[]>([]);
  const [consents, setConsents] = useState<ConsentRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AccessLog[]>([]);
  const [dataError, setDataError] = useState<string | null>(null);
  const [isBackendConnected, setIsBackendConnected] = useState(false);
  const [platformHealth, setPlatformHealth] = useState<HealthCheckResponse | null>(null);
  const [backendVersion, setBackendVersion] = useState<string | null>(null);

  // Check backend health & Fabric/IPFS state
  const checkHealth = useCallback(async () => {
    const health = await apiService.checkHealth();
    setIsBackendConnected(health.online);
    setPlatformHealth(health);
    if (health.version) setBackendVersion(health.version);
  }, []);

  // Fetch live or baseline data scoped to active user
  const loadData = useCallback(async (activeProfile?: UserProfile | null) => {
    const targetUser = activeProfile || user;
    if (!targetUser) return;
    setDataError(null);

    try {
      if (targetUser.role === 'PATIENT') {
        const [fetchedRecords, fetchedConsents, fetchedLogs] = await Promise.all([
          apiService.getRecords(targetUser.id),
          apiService.getConsents(targetUser.id),
          apiService.getAuditLogs(targetUser.id),
        ]);
        const isDemoPatient = targetUser.id === 'pat-984210';
        const combinedRecords = isDemoPatient
          ? [...fetchedRecords, ...INITIAL_RECORDS.filter(r => !fetchedRecords.some(fr => fr.id === r.id))]
          : fetchedRecords;
        const combinedConsents = isDemoPatient
          ? [...fetchedConsents, ...INITIAL_CONSENTS.filter(c => !fetchedConsents.some(fc => fc.id === c.id))]
          : fetchedConsents;
        const combinedLogs = isDemoPatient
          ? [...fetchedLogs, ...INITIAL_AUDIT_LOGS.filter(l => !fetchedLogs.some(fl => fl.id === l.id))]
          : fetchedLogs;

        setRecords(combinedRecords);
        setConsents(combinedConsents);
        setAuditLogs(combinedLogs);
      } else if (targetUser.role === 'DOCTOR') {
        const [fetchedRecords, fetchedConsents] = await Promise.all([
          apiService.getRecords(),
          apiService.getConsents(),
        ]);
        setRecords(fetchedRecords);
        setConsents(fetchedConsents);
      } else if (targetUser.role === 'AUDITOR') {
        const fetchedLogs = await apiService.getAuditLogs();
        setAuditLogs(fetchedLogs);
      }
      // Note: For ADMIN, zero patient records are queried in compliance with least-privilege
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unable to synchronize ledger data';
      setDataError(msg);
    }
  }, [user]);

  // Initial health check & telemetry poll
  useEffect(() => {
    let isMounted = true;
    async function init() {
      if (isMounted) {
        await checkHealth();
        if (user) {
          await loadData(user);
        }
      }
    }
    init();

    const timer = setInterval(() => {
      if (isMounted) {
        checkHealth();
      }
    }, 15000);

    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, [checkHealth, loadData, user]);

  // Synchronize view with user authentication state and preserve authenticated dashboard
  useEffect(() => {
    if (user) {
      if (currentView !== 'LANDING' && currentView !== 'LOGIN' && currentView !== user.role) {
        // Enforce RBAC alignment: redirect mismatched views to user's authorized role
        const targetRole = user.role as ActiveView;
        setCurrentView(targetRole);
        sessionStorage.setItem('medtrust_active_view', targetRole);
      }
    } else if (!isAuthenticated && currentView !== 'LANDING' && currentView !== 'LOGIN') {
      setCurrentView('LANDING');
      sessionStorage.setItem('medtrust_active_view', 'LANDING');
    }
  }, [user, isAuthenticated, currentView]);

  // Handle navigation switching
  const handleViewChange = async (newView: ActiveView) => {
    // Protected route check: if attempting to view a protected dashboard while unauthenticated
    if (newView !== 'LANDING' && newView !== 'LOGIN' && !isAuthenticated) {
      const roleCandidate = newView as UserRole;
      if (['PATIENT', 'DOCTOR', 'ADMIN', 'AUDITOR'].includes(roleCandidate)) {
        setTargetLoginRole(roleCandidate);
      }
      setCurrentView('LOGIN');
      sessionStorage.setItem('medtrust_active_view', 'LOGIN');
      return;
    }
    // If authenticated user explicitly selects LOGIN, sign out cleanly to allow account switching
    if (newView === 'LOGIN' && isAuthenticated) {
      await logout();
      setTargetLoginRole(null);
      setCurrentView('LOGIN');
      sessionStorage.setItem('medtrust_active_view', 'LOGIN');
      return;
    }
    setCurrentView(newView);
    sessionStorage.setItem('medtrust_active_view', newView);
    if (newView !== 'LANDING' && newView !== 'LOGIN' && user) {
      await loadData(user);
    }
  };

  const handleLoginSuccess = async (authenticatedUser: UserProfile) => {
    // Route dynamically based on backend authoritative role
    const targetRole = authenticatedUser.role as ActiveView;
    setCurrentView(targetRole);
    sessionStorage.setItem('medtrust_active_view', targetRole);
    setTargetLoginRole(null);
    await loadData(authenticatedUser);
  };

  const handleSignOut = async () => {
    await logout();
    sessionStorage.removeItem('medtrust_active_view');
    setTargetLoginRole(null);
    setCurrentView('LANDING');
  };

  // Check role authorization for the current view
  const isRoleAuthorized = () => {
    if (currentView === 'LANDING' || currentView === 'LOGIN') return true;
    if (!isAuthenticated || !user) return false;
    return user.role === currentView;
  };

  return (
    <div className="min-h-screen bg-[#F5F7FA] flex flex-col font-sans text-[#182230]">
      
      {/* Top Navigation */}
      <Navbar
        currentView={currentView}
        onViewChange={handleViewChange}
        currentUser={user}
        isAuthenticated={isAuthenticated}
        onSignOut={handleSignOut}
        isBackendConnected={isBackendConnected}
        platformHealth={platformHealth}
      />

      {/* Main Content Area */}
      <main className="flex-1 w-full">
        
        {/* View 1: Public Landing Page */}
        {currentView === 'LANDING' && (
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <LandingPage
              onNavigate={handleViewChange}
              onNavigateToApp={async (role: UserRole) => {
                if (isAuthenticated && user?.role === role) {
                  setCurrentView(role);
                  sessionStorage.setItem('medtrust_active_view', role);
                } else {
                  if (isAuthenticated && user?.role !== role) {
                    await logout();
                  }
                  setAuthMode('login');
                  setTargetLoginRole(role);
                  setCurrentView('LOGIN');
                  sessionStorage.setItem('medtrust_active_view', 'LOGIN');
                }
              }}
              onOpenAuth={async (mode: 'login' | 'register' | 'register-patient' | 'register-doctor', role?: UserRole) => {
                setAuthMode(mode);
                setTargetLoginRole(role || null);
                if (role && isAuthenticated && user?.role === role) {
                  setCurrentView(role as ActiveView);
                  sessionStorage.setItem('medtrust_active_view', role);
                } else {
                  if (role && isAuthenticated && user?.role !== role) {
                    await logout();
                  }
                  setCurrentView('LOGIN');
                  sessionStorage.setItem('medtrust_active_view', 'LOGIN');
                }
              }}
              platformHealth={platformHealth}
              isBackendConnected={isBackendConnected}
              backendVersion={backendVersion}
            />
          </div>
        )}

        {/* View 2: Unified Login Page */}
        {currentView === 'LOGIN' && (
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <LoginPage
              initialMode={authMode}
              initialRole={targetLoginRole}
              onSuccess={handleLoginSuccess}
              onBackToOverview={() => {
                setTargetLoginRole(null);
                setCurrentView('LANDING');
                sessionStorage.setItem('medtrust_active_view', 'LANDING');
              }}
            />
          </div>
        )}

        {/* Protected Dashboard Views */}
        {currentView !== 'LANDING' && currentView !== 'LOGIN' && (
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            
            {/* Direct URL / Role Escalation Guard */}
            {!isRoleAuthorized() ? (
              <div className="max-w-md mx-auto py-12 text-center space-y-4">
                <div className="inline-flex p-3 rounded-2xl bg-amber-50 text-amber-600 border border-amber-200">
                  <AlertTriangle className="w-8 h-8" />
                </div>
                <h2 className="text-xl font-bold text-[#182230]">Access Restricted by RBAC Policy</h2>
                <p className="text-xs text-[#5B6675] leading-relaxed">
                  Your authenticated session is registered with role <strong>{user?.role}</strong>. You do not hold permissions to view the <strong>{currentView}</strong> portal.
                </p>
                <button
                  onClick={() => {
                    const fallbackRole = (user?.role as ActiveView) || 'LANDING';
                    setCurrentView(fallbackRole);
                    sessionStorage.setItem('medtrust_active_view', fallbackRole);
                  }}
                  className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-[#14263D] text-white text-xs font-semibold hover:bg-[#162e4a] cursor-pointer"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Return to Authorized Portal</span>
                </button>
              </div>
            ) : (
              <>
                {/* Patient Dashboard */}
                {currentView === 'PATIENT' && user && (
                  <PatientDashboard
                    records={records}
                    consents={consents}
                    auditLogs={auditLogs}
                    patientId={user.id}
                    patientName={user.name}
                    errorMessage={dataError}
                    onRefresh={() => loadData(user)}
                    onRecordAdded={(newRecord) => {
                      setRecords(prev => [newRecord, ...prev]);
                      loadData(user);
                    }}
                    onConsentUpdated={() => {
                      loadData(user);
                    }}
                  />
                )}

                {/* Doctor Dashboard */}
                {currentView === 'DOCTOR' && user && (
                  <DoctorDashboard
                    records={records}
                    consents={consents}
                    doctorId={user.id}
                    onRefresh={() => loadData(user)}
                    onRequestSubmitted={() => {
                      loadData(user);
                    }}
                  />
                )}

                {/* Administrator Dashboard */}
                {currentView === 'ADMIN' && (
                  <AdminDashboard
                    platformHealth={platformHealth}
                    isBackendConnected={isBackendConnected}
                  />
                )}

                {/* Auditor Dashboard */}
                {currentView === 'AUDITOR' && (
                  <AuditorDashboard
                    auditLogs={auditLogs}
                    isBackendConnected={isBackendConnected}
                    platformHealth={platformHealth}
                  />
                )}
              </>
            )}

          </div>
        )}

      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-[#E1E7EF] mt-auto py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-[#5B6675]">
            <div className="flex items-center space-x-2">
              <Shield className="w-4 h-4 text-[#147D78]" />
              <span className="font-semibold text-[#182230]">MedTrust Enterprise Platform</span>
              <span>•</span>
              <span>Zero-Trust Decentralized Healthcare</span>
            </div>

            <div className="flex items-center space-x-6 flex-wrap justify-center">
              <span className="flex items-center space-x-1.5">
                <Database className="w-3.5 h-3.5 text-[#5B6675]" />
                <span>
                  {platformHealth?.ipfsStatus 
                    ? `IPFS: ${platformHealth.ipfsStatus.split(' ')[0]}` 
                    : 'IPFS Kubo Daemon'}
                </span>
              </span>
              <span className="flex items-center space-x-1.5">
                <Server className="w-3.5 h-3.5 text-[#5B6675]" />
                <span>
                  {platformHealth?.fabricStatus 
                    ? `Fabric: ${platformHealth.fabricStatus.split(',')[0].replace('connected (', '')}` 
                    : 'Hyperledger Fabric v2.5'}
                </span>
              </span>
              <span className="flex items-center space-x-1.5">
                <Lock className="w-3.5 h-3.5 text-[#5B6675]" />
                <span>AES-256-GCM Zero-PHI</span>
              </span>
            </div>

            <div>
              <span>Gateway: {isBackendConnected ? `Live Gateway (${backendVersion || 'v1.0.0'})` : 'Local Standby'}</span>
            </div>
          </div>
        </div>
      </footer>

    </div>
  );
}

export function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}

export default App;
