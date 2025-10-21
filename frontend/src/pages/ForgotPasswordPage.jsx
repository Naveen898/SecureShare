import React, { useState } from 'react';
import authService from '../services/authService';
import Alert from '../components/Alert';

const ForgotPasswordPage = () => {
  const [username, setUsername] = useState('');
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [phase, setPhase] = useState('request'); // request | verify
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const handleRequest = async (e) => {
    e.preventDefault();
    setStatus(null);
    setLoading(true);
    try {
      await authService.forgotCode(username);
      setStatus({ type: 'success', message: 'If the account exists, a reset code has been sent to the registered email.' });
      setPhase('verify');
    } catch (err) {
      setStatus({ type: 'error', message: err.message || 'Request failed' });
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e) => {
    e.preventDefault();
    setStatus(null);
    setLoading(true);
    try {
      await authService.resetWithCode(username, code, newPassword);
      setStatus({ type: 'success', message: 'Password has been reset. You can now sign in.' });
    } catch (err) {
      setStatus({ type: 'error', message: err.message || 'Reset failed' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-split">
      <div className="auth-hero">
        <h1>SecureShare</h1>
        <p>Securely upload, share, and retrieve files with confidence.<br/>Built-in scanning & expiring links.</p>
      </div>
      <div className="container auth-card auth-form-panel">
        <h2>Reset your password</h2>
        {status && <Alert type={status.type} message={status.message} />}
        {phase === 'request' && (
          <form onSubmit={handleRequest} className="vertical-form">
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              required
            />
            <button type="submit" disabled={loading}>{loading ? 'Sending...' : 'Send Reset Code'}</button>
          </form>
        )}
        {phase === 'verify' && (
          <form onSubmit={handleVerify} className="vertical-form">
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={e => setUsername(e.target.value)}
              required
              disabled
            />
            <input
              type="text"
              placeholder="Reset code"
              value={code}
              onChange={e => setCode(e.target.value)}
              required
            />
            <input
              type="password"
              placeholder="New password"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              required
            />
            <button type="submit" disabled={loading}>{loading ? 'Resetting…' : 'Reset Password'}</button>
            <div className="center-links" style={{marginTop:'0.5rem', fontSize:'0.8rem'}}>
              <a href="#" onClick={(e)=>{e.preventDefault(); setPhase('request'); setCode(''); setNewPassword('');}}>← Back</a>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default ForgotPasswordPage;
