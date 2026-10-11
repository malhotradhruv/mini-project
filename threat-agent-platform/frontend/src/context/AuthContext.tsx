import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

// Dynamically target port 8080 while supporting relative /api proxy
export const API_BASE = 'http://127.0.0.1:8080/api/v1';
export const API_BASE_URL = 'http://127.0.0.1:8080';

interface AuthContextType {
  token: string | null;
  role: string | null;
  username: string | null;
  deviceId: string;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Global Axios Request Interceptor for Bearer token
axios.interceptors.request.use(
  (config) => {
    const savedToken = localStorage.getItem('token') || localStorage.getItem('sentinel_token');
    if (savedToken) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${savedToken}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Global Axios Response Interceptor to enforce single-device session lock
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    const isSessionRevoked =
      error.response &&
      (error.response.status === 403 ||
        (error.response.status === 401 &&
          String(error.response.data?.detail || '').toLowerCase().includes('device')));

    if (isSessionRevoked) {
      localStorage.removeItem('token');
      localStorage.removeItem('role');
      localStorage.removeItem('username');
      localStorage.removeItem('sentinel_token');
      localStorage.removeItem('sentinel_role');
      localStorage.removeItem('sentinel_user');

      if (!window.sessionStorage.getItem('session_revoked_alerted')) {
        window.sessionStorage.setItem('session_revoked_alerted', 'true');
        alert('⚠️ Session Revoked: Your session was invalidated because another device logged into this account.');
      }
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(
    () => localStorage.getItem('token') || localStorage.getItem('sentinel_token')
  );
  const [role, setRole] = useState<string | null>(
    () => localStorage.getItem('role') || localStorage.getItem('sentinel_role')
  );
  const [username, setUsername] = useState<string | null>(
    () => localStorage.getItem('username') || localStorage.getItem('sentinel_user')
  );

  // Persistent device ID for Single-Device Session Lock
  const [deviceId] = useState<string>(() => {
    let saved = localStorage.getItem('sentinel_device_id');
    if (!saved) {
      saved = 'dev_' + Math.random().toString(36).substring(2, 12);
      localStorage.setItem('sentinel_device_id', saved);
    }
    return saved;
  });

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
      delete axios.defaults.headers.common['Authorization'];
    }
  }, [token]);

  const register = async (user: string, pass: string) => {
    await axios.post(`${API_BASE}/auth/register`, {
      username: user,
      password: pass,
      device_id: deviceId,
    });
  };

  const login = async (user: string, pass: string) => {
    window.sessionStorage.removeItem('session_revoked_alerted');
    const res = await axios.post(`${API_BASE}/auth/login`, {
      username: user,
      password: pass,
      device_id: deviceId,
    });
    const { access_token, role: userRole, username: authUser } = res.data;
    const resolvedUser = authUser || user;

    localStorage.setItem('token', access_token);
    localStorage.setItem('role', userRole || 'ANALYST');
    localStorage.setItem('username', resolvedUser);
    localStorage.setItem('sentinel_token', access_token);
    localStorage.setItem('sentinel_role', userRole || 'ANALYST');
    localStorage.setItem('sentinel_user', resolvedUser);

    setToken(access_token);
    setRole(userRole || 'ANALYST');
    setUsername(resolvedUser);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    localStorage.removeItem('username');
    localStorage.removeItem('sentinel_token');
    localStorage.removeItem('sentinel_role');
    localStorage.removeItem('sentinel_user');
    setToken(null);
    setRole(null);
    setUsername(null);
    window.location.href = '/login';
  };

  return (
    <AuthContext.Provider
      value={{
        token,
        role,
        username,
        deviceId,
        login,
        register,
        logout,
        isAuthenticated: !!token,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};

export default AuthContext;
