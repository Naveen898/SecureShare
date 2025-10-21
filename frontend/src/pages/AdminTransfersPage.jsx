import React, { useEffect, useState } from 'react';
import transferService from '../services/transferService';
import authService from '../services/authService';
import Alert from '../components/Alert';

const AdminTransfersPage = () => {
  const [requests, setRequests] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [deciding, setDeciding] = useState(null);
  const [rejecting, setRejecting] = useState(null);
  const [rejectReason, setRejectReason] = useState('');

  const fetchData = async () => {
    try {
      setLoading(true);
      const data = await transferService.listPending();
      setRequests(data.requests || []);
    } catch (e) {
      setError(e.message || 'Failed to load');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleDecision = async (id, approve, reason) => {
    try {
      setDeciding(id);
      await transferService.decide(id, approve, reason);
      await fetchData();
    } catch (e) {
      setError(e.message || 'Decision failed');
    } finally {
      setDeciding(null);
    }
  };

  const openReject = (id) => { setRejecting(id); setRejectReason(''); };
  const submitReject = async () => {
    if (!rejecting) return;
    await handleDecision(rejecting, false, rejectReason || undefined);
    setRejecting(null);
    setRejectReason('');
  };

  if (!authService.isAdmin()) {
    return (
      <div className="container wide admin-transfers">
        <div className="page-header"><h2>Admin Transfers</h2></div>
        <div className="panel surface"><p>Access denied.</p></div>
      </div>
    );
  }

  return (
    <div className="container wide admin-transfers">
      <div className="page-header">
        <div>
          <h2>Pending Transfer Requests</h2>
          <p className="muted">Approve or reject file transfers between departments.</p>
        </div>
      </div>
      {error && <Alert type="error" message={error} />}
      <div className="panel surface">
        {loading ? (
          <p>Loading...</p>
        ) : requests.length === 0 ? (
          <p>No pending requests.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>File ID</th>
                <th>From Dept</th>
                <th>To Dept</th>
                <th>Reason</th>
                <th>Requested At</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {requests.map(r => (
                <tr key={r.id}>
                  <td>{r.id}</td>
                  <td><code className="break-all">{r.file_id}</code></td>
                  <td>{r.from_department || r.from_department_id || '-'}</td>
                  <td>{r.to_department || r.to_department_id || '-'}</td>
                  <td>{r.reason || '-'}</td>
                  <td>{r.created_at || '-'}</td>
                  <td>
                    <button disabled={deciding===r.id} onClick={() => handleDecision(r.id, true)} className="success">Approve</button>
                    <button disabled={deciding===r.id} onClick={() => openReject(r.id)} className="danger" style={{marginLeft: 8}}>Reject</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {rejecting && (
        <div className="modal-overlay">
          <div className="modal">
            <h3>Reject Transfer</h3>
            <p className="muted">Optionally provide a reason for audit and to notify the requester.</p>
            <textarea value={rejectReason} onChange={e=>setRejectReason(e.target.value)} placeholder="Reason (optional)" rows={4} style={{width:'100%'}} />
            <div style={{marginTop: 10, display:'flex', gap:8}}>
              <button onClick={submitReject} className="danger">Reject</button>
              <button onClick={()=>{ setRejecting(null); setRejectReason(''); }}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminTransfersPage;
