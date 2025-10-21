import React, { useEffect, useState } from 'react';
import transferService from '../services/transferService';
import Alert from '../components/Alert';

const MyTransfersPage = () => {
  const [requests, setRequests] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        const data = await transferService.listMine();
        setRequests(data.requests || []);
      } catch (e) {
        setError(e.message || 'Failed to load');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  return (
    <div className="container wide transfers-dashboard">
      <div className="page-header">
        <div>
          <h2>My Transfer Requests</h2>
          <p className="muted">Track the status of your file transfer requests across departments.</p>
        </div>
      </div>

      {error && <Alert type="error" message={error} />}

      <div className="panel surface">
        {loading ? (
          <p>Loading...</p>
        ) : requests.length === 0 ? (
          <p>No transfer requests.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>File ID</th>
                <th>From Dept</th>
                <th>To Dept</th>
                <th>Status</th>
                <th>Reason</th>
                <th>Requested At</th>
                <th>Decided At</th>
              </tr>
            </thead>
            <tbody>
              {requests.map(r => (
                <tr key={r.id}>
                  <td>{r.id}</td>
                  <td><code className="break-all">{r.file_id}</code></td>
                  <td>{r.from_department || r.from_department_id || '-'}</td>
                  <td>{r.to_department || r.to_department_id || '-'}</td>
                  <td>{r.status}</td>
                  <td>{r.reason || '-'}</td>
                  <td>{r.created_at || '-'}</td>
                  <td>{r.decided_at || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default MyTransfersPage;
