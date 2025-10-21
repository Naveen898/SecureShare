import authService from './authService';

const API_URL = '/api/uploads';

const transferService = {
  listPending: async () => {
    const res = await fetch(`${API_URL}/transfer/pending`, {
      headers: { 'Authorization': `Bearer ${authService.getToken()}` }
    });
    if (!res.ok) throw new Error('Failed to fetch pending transfers');
    return res.json();
  },
  decide: async (requestId, approve, reason) => {
    const res = await fetch(`${API_URL}/transfer/decision/${encodeURIComponent(requestId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authService.getToken()}` },
      body: JSON.stringify({ approve: !!approve, reason: reason || undefined })
    });
    if (!res.ok) {
      try { const j = await res.json(); throw new Error(j.detail || 'Decision failed'); } catch { throw new Error('Decision failed'); }
    }
    return res.json();
  },
  listMine: async () => {
    const res = await fetch(`${API_URL}/transfer/mine`, {
      headers: { 'Authorization': `Bearer ${authService.getToken()}` }
    });
    if (!res.ok) throw new Error('Failed to fetch my transfers');
    return res.json();
  }
};

export default transferService;
