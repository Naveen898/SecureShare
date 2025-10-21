import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import authService from '../services/authService';
import Alert from '../components/Alert';

const RegisterPage = () => {
  const [form, setForm] = useState({ username:'', email:'', password:'', confirm:'' });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const handleChange = e => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async e => {
    e.preventDefault();
    setError(''); setSuccess('');
    if(form.password !== form.confirm){
      setError('Passwords do not match');
      return;
    }
    try {
      await authService.register({ username: form.username, password: form.password, email: form.email });
      setSuccess('Registered. Redirecting to login...');
      setTimeout(()=>navigate('/login'), 1200);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="auth-split">
      <div className="auth-hero">
        <h1>VaultUpload</h1>
        <p>Securely upload, share, and retrieve files with confidence.<br/>Built-in scanning & expiring links.</p>
      </div>
      <div className="container auth-card auth-form-panel">
        <h2>Create Account</h2>
        {error && <Alert type="error" message={error} />}
        {success && <Alert type="success" message={success} />}
        <form onSubmit={handleSubmit} className="vertical-form">
          <input name="username" placeholder="Username" value={form.username} onChange={handleChange} required />
          <input name="email" type="email" placeholder="Email (optional)" value={form.email} onChange={handleChange} />
          <input name="password" type="password" placeholder="Password" value={form.password} onChange={handleChange} required />
          <input name="confirm" type="password" placeholder="Confirm Password" value={form.confirm} onChange={handleChange} required />
          <button type="submit">Register</button>
        </form>
      </div>
    </div>
  );
};

export default RegisterPage;
