import authService from './authService';

const API_URL = '/api/uploads';

const fileService = {
  uploadFile: async (file, { expiryHours = 24, comments = '', departmentId = '', recipients = '' } = {}) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('expiry_hours', expiryHours);
    if (comments) formData.append('comments', comments);
    if (departmentId) formData.append('department_id', departmentId);
    if (recipients) formData.append('recipient_employee_ids', recipients);
    const res = await fetch(API_URL + '/upload?expiry_hours=' + expiryHours, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authService.getToken()}` },
      body: formData
    });
    if (!res.ok) throw new Error('Upload failed');
    return res.json();
  },
  listFiles: async () => {
  const res = await fetch(API_URL, {
    headers: { 'Authorization': `Bearer ${authService.getToken()}` }
  });
  if (!res.ok) throw new Error('Fetch failed');
  const data = await res.json();
  return data.files || [];
},
  deleteFile: async (filename) => {
    const res = await fetch(`${API_URL}/${filename}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${authService.getToken()}` }
    });
    if (!res.ok) throw new Error('Delete failed');
    return res.json();
  },
  getShareToken: async (fileId) => {
    const res = await fetch(`${API_URL}/share/${fileId}`, {
      headers: { 'Authorization': `Bearer ${authService.getToken()}` }
    });
    if (!res.ok) throw new Error('Share token failed');
    return res.json();
  },
  accessFile: async ({ fileId, token, secretWord }) => {
    try {
      const res = await fetch(`${API_URL}/access/${fileId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authService.getToken()}` },
        body: JSON.stringify({ token, secret_word: secretWord })
      });
      const contentType = res.headers.get('Content-Type') || '';
      if (!res.ok) {
        if (contentType.includes('application/json')) {
          const data = await res.json();
          return { error: data.detail || data.error || 'Access denied' };
        }
        return { error: 'Access denied' };
      }
      if (contentType.startsWith('application/json')) {
        const data = await res.json();
        if (data.error) return { error: data.error };
        return { error: 'Unexpected JSON response' };
      }
      return await res.blob();
    } catch (e) {
      return { error: e.message || 'Network error' };
    }
  }
};

export default fileService;
