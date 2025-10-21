const TOKEN_KEY = 'vaultupload_token';
const PROFILE_KEY = 'vaultupload_profile';

const authService = {
  register: async ({ username, password, email, hcaptchaToken }) => {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, email, hcaptcha_token: hcaptchaToken })
    });
    if (!res.ok) {
      try {
        const j = await res.json();
        throw new Error(j.detail || 'Register failed');
      } catch {
        const t = await res.text();
        throw new Error(t || 'Register failed');
      }
    }
    return res.json();
  },
  // hcaptchaToken optional (when captcha enabled)
  login: async (username, password, hcaptchaToken) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, hcaptcha_token: hcaptchaToken })
    });
    if (!res.ok) {
      try {
        const j = await res.json();
        throw new Error(j.detail || 'Login failed');
      } catch {
        const t = await res.text();
        throw new Error(t || 'Login failed');
      }
    }
    const data = await res.json();
    if (data.mfa_required) {
      return { mfaRequired: true };
    }
    const { token } = data;
    localStorage.setItem(TOKEN_KEY, token);
    try {
      const meRes = await fetch('/api/auth/me', { headers: { 'Authorization': `Bearer ${token}` } });
      if (meRes.ok) {
        const profile = await meRes.json();
        localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
      }
    } catch {}
  },
  verifyOtp: async (username, otp) => {
    const res = await fetch('/api/auth/login/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, otp })
    });
    if (!res.ok) {
      try {
        const j = await res.json();
        throw new Error(j.detail || 'OTP verification failed');
      } catch {
        const t = await res.text();
        throw new Error(t || 'OTP verification failed');
      }
    }
    const data = await res.json();
    const { token } = data;
    localStorage.setItem(TOKEN_KEY, token);
    try {
      const meRes = await fetch('/api/auth/me', { headers: { 'Authorization': `Bearer ${token}` } });
      if (meRes.ok) {
        const profile = await meRes.json();
        localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
      }
    } catch {}
  },
  forgot: async (username) => {
    const res = await fetch('/api/auth/forgot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    if (!res.ok) throw new Error('Request failed');
    return res.json();
  },
  forgotCode: async (username) => {
    const res = await fetch('/api/auth/forgot/code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    if (!res.ok) {
      try { const j = await res.json(); throw new Error(j.detail || 'Request failed'); } catch { throw new Error('Request failed'); }
    }
    return res.json();
  },
  resetWithCode: async (username, code, newPassword) => {
    const res = await fetch('/api/auth/reset/code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, code, new_password: newPassword })
    });
    if (!res.ok) {
      try { const j = await res.json(); throw new Error(j.detail || 'Reset failed'); } catch { throw new Error('Reset failed'); }
    }
    return res.json();
  },
  resetPassword: async (token, newPassword) => {
    const res = await fetch('/api/auth/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, new_password: newPassword })
    });
    if (!res.ok) throw new Error('Reset failed');
    return res.json();
  },
  logout: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(PROFILE_KEY);
  },
  getToken: () => localStorage.getItem(TOKEN_KEY),
  isAuthenticated: () => !!localStorage.getItem(TOKEN_KEY),
  getProfile: () => {
    try { return JSON.parse(localStorage.getItem(PROFILE_KEY)); } catch { return null; }
  },
  isAdmin: () => {
    const p = authService.getProfile();
    return !!(p && Array.isArray(p.roles) && p.roles.includes('admin'));
  }
};

export default authService;
