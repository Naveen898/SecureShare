import React, { useState, useEffect } from 'react';
import fileService from '../services/fileService';
import Alert from './Alert';
import authService from '../services/authService';

const FileUploadForm = () => {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [expiryHours, setExpiryHours] = useState(24);
  const [shareInfo, setShareInfo] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [comments, setComments] = useState('');
  const [departmentId, setDepartmentId] = useState('');
  const [departments, setDepartments] = useState([]);
  const [recipients, setRecipients] = useState('');
  const [revealed, setRevealed] = useState(false);

  // Auto-hide share token after first visibility change or navigation
  useEffect(() => {
    const handleVisibility = () => {
      if (document.hidden && shareInfo) {
        // remove token from state when user leaves tab
        setShareInfo(prev => prev ? { ...prev, token: undefined } : prev);
      }
    };
    const handleBeforeUnload = () => {
      if (shareInfo) {
        setShareInfo(prev => prev ? { ...prev, token: undefined } : prev);
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibility);
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [shareInfo]);

  // Load departments for selection
  useEffect(() => {
    const load = async () => {
      try {
        const token = authService.getToken();
        const res = await fetch('/api/misc/departments', { headers: { 'Authorization': `Bearer ${token}` } });
        if (res.ok) {
          const data = await res.json();
          setDepartments(data.departments || []);
        }
      } catch {}
    };
    load();
  }, []);

  const handleChange = (e) => {
    setFile(e.target.files[0]);
    setMessage('');
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file');
      return;
    }
    try {
      setScanning(true);
        const uploadResp = await fileService.uploadFile(file, { expiryHours, comments, departmentId, recipients });
      setMessage('File uploaded successfully');
      // share info now comes embedded (with share_token & receive_link)
      setShareInfo({
        fileId: uploadResp.metadata.file_id,
        expiresAtIST: uploadResp.metadata.expires_at_ist,
        departmentId: uploadResp.metadata.department_id,
        departmentName: uploadResp.metadata.department_name || null
      });
      setFile(null);
    } catch (e) {
      setError('Upload failed: ' + e.message);
    } finally {
      setScanning(false);
    }
  };

  return (
  <form onSubmit={handleSubmit} className="upload-form" aria-busy={scanning}>
      {message && <Alert type="success" message={message} />}
      {error && <Alert type="error" message={error} />}
      <div className="form-row">
        <label className="form-label">File</label>
        <input type="file" onChange={handleChange} className="control" />
      </div>
      <div className="form-row inline">
        <div className="field">
          <label className="form-label">Expiry (hrs)</label>
          <input type="number" min={1} max={24} value={expiryHours} onChange={e => setExpiryHours(Number(e.target.value))} className="control small" disabled={scanning} />
        </div>
      </div>
      <div className="form-row">
        <label className="form-label">Comments (optional)</label>
        <input type="text" value={comments} onChange={e => setComments(e.target.value)} placeholder="Add a note for recipients" className="control" disabled={scanning} />
      </div>
      <div className="form-row inline">
        <div className="field">
          <label className="form-label">Department</label>
          <select value={departmentId} onChange={e => setDepartmentId(e.target.value)} className="control" disabled={scanning}>
            <option value="">(use my default)</option>
            {departments.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </div>
        <div className="field">
          <label className="form-label">Recipients (employee IDs)</label>
          <input type="text" value={recipients} onChange={e => setRecipients(e.target.value)} placeholder="e.g. E123,E456" className="control" disabled={scanning} />
        </div>
      </div>
      <div className="actions"><button type="submit" className="primary" disabled={scanning}>{scanning ? 'Scanning…' : 'Upload'}</button></div>
      {shareInfo && (
        <div className="share-panel surface raised">
          <h4>Upload Complete</h4>
          <div className="kv"><span className="kv-key">File ID</span><code>{shareInfo.fileId}</code></div>
          <div className="kv"><span className="kv-key">Expiry (IST)</span><strong>{shareInfo.expiresAtIST}</strong></div>
          <div className="kv"><span className="kv-key">Target Dept</span><strong>{shareInfo.departmentName || shareInfo.departmentId || '(your dept)'}</strong></div>
          <div className="disclaimer-box">
            Share the File ID with the intended recipient. They will use Receive File with their Department Key.
          </div>
        </div>
      )}
      {scanning && (
        <div className="scan-overlay">
          <div className="scan-modal">
            <div className="spinner" />
            <p>File is being scanned for potential security concerns...</p>
          </div>
        </div>
      )}
    </form>
  );
};

export default FileUploadForm;
