import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import authService from '../services/authService';
import Alert from '../components/Alert';

function useQuery(){
  return new URLSearchParams(useLocation().search);
}

const ResetPasswordPage = () => {
  const query = useQuery();
  const initialToken = query.get('token') || '';
  const [username, setUsername] = useState('');
  const [token, setToken] = useState(initialToken);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus(null);
    if(password !== confirm){
      setStatus({ type:'error', message:'Passwords do not match' });
      return;
    }
    setLoading(true);
    try {
      await authService.resetPassword({ username, token, new_password: password });
      setStatus({ type: 'success', message: 'Password reset. Redirecting to login...' });
      setTimeout(()=>navigate('/login'), 1500);
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
        <h2>Reset Password</h2>
        {status && <Alert type={status.type} message={status.message} />}
        <form onSubmit={handleSubmit} className="vertical-form">
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={e=>setUsername(e.target.value)}
            required
          />
          <input
            type="text"
            placeholder="Reset Token"
            value={token}
            onChange={e=>setToken(e.target.value)}
            required
          />
          <input
              type="password"
              placeholder="New Password"
              value={password}
              onChange={e=>setPassword(e.target.value)}
              required
          />
          <input
              type="password"
              placeholder="Confirm Password"
              value={confirm}
              onChange={e=>setConfirm(e.target.value)}
              required
          />
          <button type="submit" disabled={loading}>{loading ? 'Resetting...' : 'Reset Password'}</button>
        </form>
      </div>
    </div>
  );
};

export default ResetPasswordPage;
