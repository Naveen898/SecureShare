import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Alert from '../components/Alert';
import authService from '../services/authService';

function useQuery() {
  return new URLSearchParams(useLocation().search);
}

const ReceivePage = () => {
  const query = useQuery();
  const navigate = useNavigate();
  const [fileId, setFileId] = useState(query.get('fileId') || '');
  const [employeeId, setEmployeeId] = useState('');
  const [receiverDeptId, setReceiverDeptId] = useState('');
  const [deptPin, setDeptPin] = useState('');
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [meta, setMeta] = useState(null);

  const fetchMeta = async () => {
    setLoading(true);
    setStatus(null);
    try {
      const res = await fetch('/api/uploads/public/metadata', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authService.getToken()}` },
        body: JSON.stringify({ file_id: fileId, employee_id: employeeId || undefined, department_id: receiverDeptId || undefined })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Lookup failed');
      setMeta(data.file);
      if (data.status === 'PENDING_APPROVAL') {
        setStatus({ type: 'info', message: 'Awaiting admin approval before you can download.' });
      }
    } catch (e) {
      setMeta(null);
      setStatus({ type: 'error', message: e.message || 'Lookup failed' });
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (e) => {
    e.preventDefault();
    setStatus(null);
    setDownloading(true);
    try {
      const res = await fetch('/api/uploads/public/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authService.getToken()}` },
        body: JSON.stringify({ file_id: fileId, department_id: receiverDeptId, department_pin: deptPin, employee_id: employeeId || undefined })
      });
      if (!res.ok) {
        let msg = 'Download failed';
        try { const j = await res.json(); msg = j.detail || msg; } catch {}
        throw new Error(msg);
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = meta?.name || fileId;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setStatus({ type: 'success', message: 'Download started' });
    } catch (err) {
      setStatus({ type: 'error', message: err.message || 'Download error' });
    } finally {
      setDownloading(false);
    }
  };

  // Auto-fetch metadata when fileId changes
  useEffect(() => {
    if (!authService.isAuthenticated()) {
      navigate('/login?next=/receive');
      return;
    }
  }, [navigate]);

  return (
    <div className="container wide receive-dashboard">
      <div className="page-header">
        <div>
          <h2>Receive File</h2>
          <p className="muted">Provide the File ID, Share Token and Secret (if required) to securely download.</p>
        </div>
      </div>
      <div className="panel surface">
        {status && <Alert type={status.type} message={status.message} />}        
        <div className="receive-form-grid">
          <div className="form-row">
            <label className="form-label">File ID</label>
            <input className="control" type="text" value={fileId} onChange={(e) => setFileId(e.target.value.trim())} required placeholder="uuid_filename" />
          </div>
          <div className="form-row">
            <label className="form-label">Your Employee ID (optional)</label>
            <input className="control" type="text" value={employeeId} onChange={(e)=>setEmployeeId(e.target.value.trim())} placeholder="E.g. E123" />
          </div>
          <div className="form-row">
            <label className="form-label">Your Department ID</label>
            <input className="control" type="number" value={receiverDeptId} onChange={(e)=>setReceiverDeptId(e.target.value)} placeholder="e.g. 5" />
          </div>
          <div className="form-row">
            <button className="secondary" onClick={fetchMeta} disabled={loading}>{loading ? 'Checking…' : 'Check File'}</button>
          </div>
        </div>
        {meta && (
          <div className="file-meta surface subtle" style={{marginTop:'1rem'}}>
            <div><strong>File:</strong> {meta.name} <span className="muted">({(meta.size/1024).toFixed(1)} KB)</span></div>
            <div><strong>From:</strong> {meta.sender ? `${meta.sender}${meta.sender_department ? ` (${meta.sender_department})` : ''}` : 'Unknown'}</div>
            <div><strong>Dept:</strong> {meta.department || '-'}</div>
            {meta.receiver_department && (
              <div><strong>To:</strong> {meta.receiver_department}</div>
            )}
            <div><strong>Expires:</strong> {meta.expires_at_ist || meta.expires_at}</div>
          </div>
        )}
        <form onSubmit={handleDownload} className="receive-form-grid" style={{marginTop:'1rem'}}>
          <div className="form-row">
            <label className="form-label">Department Download Key</label>
            <input className="control" type="password" value={deptPin} onChange={(e)=>setDeptPin(e.target.value)} placeholder="Enter department key" required />
          </div>
          <div className="actions">
            <button type="submit" className="primary" disabled={downloading || !meta || status?.type === 'info'}>{downloading ? 'Downloading…' : 'Download'}</button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ReceivePage;
