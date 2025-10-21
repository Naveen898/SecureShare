import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import authService from '../services/authService';
import Alert from '../components/Alert';

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [hcaptchaToken, setHcaptchaToken] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [otp, setOtp] = useState('');
  const siteKey = import.meta.env.VITE_HCAPTCHA_SITE_KEY; // define in .env e.g. VITE_HCAPTCHA_SITE_KEY=your_site_key
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!mfaRequired && siteKey && !hcaptchaToken) {
      setError('Please complete captcha');
      return;
    }
    try {
      if (!mfaRequired) {
        const res = await authService.login(username, password, hcaptchaToken);
        if (res && res.mfaRequired) {
          setMfaRequired(true);
          return; // show OTP form
        }
        navigate('/files');
      } else {
        await authService.verifyOtp(username, otp);
        navigate('/files');
      }
    } catch (err) {
      setError(err.message || 'Login failed');
    }
  };

  // Load hCaptcha script once if site key present
  useEffect(() => {
    if (!siteKey) return;
    if (document.querySelector('script[data-hcaptcha]')) return; // already added
    const script = document.createElement('script');
    script.src = 'https://hcaptcha.com/1/api.js';
    script.async = true;
    script.defer = true;
    script.setAttribute('data-hcaptcha', 'true');
    document.head.appendChild(script);
    // Global callback referenced by data-callback attribute
    window.onHCaptchaSuccess = (token) => setHcaptchaToken(token);
    return () => { delete window.onHCaptchaSuccess; };
  }, [siteKey]);

  return (
  <div className="auth-split">
    <div className="auth-hero">
      <h1>SecureShare</h1>
      <p>Secure file sharing with malware scanning,<br/>expiring links & optional secrets.</p>
    </div>
    <div className="container auth-card auth-form-panel">
      <h2>{mfaRequired ? 'Enter MFA Code' : 'Login'}</h2>
      {error && <Alert type="error" message={error} />}
  <form onSubmit={handleSubmit} className="vertical-form">
        {!mfaRequired && (
          <>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
            />
            {siteKey && (
              <div style={{marginTop:'0.25rem'}}>
                <div className="h-captcha" data-sitekey={siteKey} data-callback="onHCaptchaSuccess"></div>
              </div>
            )}
            <button type="submit">Login</button>
            <div className="center-links" style={{marginTop:'0.5rem', fontSize:'0.8rem'}}>
              <Link to="/forgot">Forgot password?</Link>
            </div>
          </>
        )}
        {mfaRequired && (
          <>
            <p style={{marginTop:'0.25rem'}}>We sent a 6–8 character code to your email. Enter it below to finish signing in.</p>
            <input
              type="text"
              placeholder="One-time code"
              value={otp}
              onChange={e => setOtp(e.target.value)}
              required
            />
            <button type="submit">Verify code</button>
            <div className="center-links" style={{marginTop:'0.5rem', fontSize:'0.8rem'}}>
              <a href="#" onClick={(e)=>{e.preventDefault(); setMfaRequired(false); setOtp(''); setError('');}}>← Back to login</a>
            </div>
          </>
        )}
      </form>
    </div>
  </div>
  );
};

export default LoginPage;
