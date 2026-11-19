import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { UserProfile } from '../types';
import { apiService } from '../services/api';

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<UserProfile>;
  register: (payload: { name: string; email: string; password: string; hospital?: string; specialty?: string }) => Promise<UserProfile>;
  logout: () => Promise<void>;
  recoverPassword: (email: string) => Promise<{ success: boolean; message: string }>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(() => apiService.getSavedUser());
  const [token, setToken] = useState<string | null>(() => apiService.getToken());
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Re-verify session on mount
  useEffect(() => {
    let isMounted = true;
    async function verifySession() {
      const existingToken = apiService.getToken();
      if (existingToken) {
        try {
          const profile = await apiService.getMe();
          if (isMounted) {
            setUser(profile);
            setToken(existingToken);
          }
        } catch {
          if (isMounted) {
            setUser(null);
            setToken(null);
          }
        }
      }
      if (isMounted) {
        setIsLoading(false);
      }
    }
    verifySession();
    return () => {
      isMounted = false;
    };
  }, []);

  const login = useCallback(async (email: string, password: string): Promise<UserProfile> => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await apiService.login({ email, password });
      setUser(result.user);
      setToken(result.accessToken);
      setIsLoading(false);
      return result.user;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Authentication failed';
      setError(msg);
      setIsLoading(false);
      throw err;
    }
  }, []);

  const register = useCallback(async (payload: { name: string; email: string; password: string; hospital?: string; specialty?: string }): Promise<UserProfile> => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await apiService.register(payload);
      setUser(result.user);
      setToken(result.accessToken);
      setIsLoading(false);
      return result.user;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Registration failed';
      setError(msg);
      setIsLoading(false);
      throw err;
    }
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    setIsLoading(true);
    try {
      await apiService.logout();
    } finally {
      setUser(null);
      setToken(null);
      setError(null);
      setIsLoading(false);
    }
  }, []);

  const recoverPassword = useCallback(async (email: string) => {
    return await apiService.recoverPassword(email);
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated: !!token && !!user,
    isLoading,
    error,
    login,
    register,
    logout,
    recoverPassword,
    clearError,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// oxlint-disable-next-line react/only-export-components
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
