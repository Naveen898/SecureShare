import authService from './authService';

const ADMIN_URL = '/api/admin';

const headers = () => ({ 'Authorization': `Bearer ${authService.getToken()}`, 'Content-Type': 'application/json' });

const adminService = {
  getSummary: async () => {
    const res = await fetch(`${ADMIN_URL}/dashboard/summary`, { headers: headers() });
    if (!res.ok) throw new Error('Failed to load summary');
    return res.json();
  },
  getSecuritySettings: async () => {
    const res = await fetch(`${ADMIN_URL}/security/settings`, { headers: headers() });
    if (!res.ok) throw new Error('Failed to load settings');
    return res.json();
  },
  updateSecuritySettings: async (payload) => {
    const res = await fetch(`${ADMIN_URL}/security/settings`, { method: 'POST', headers: headers(), body: JSON.stringify(payload) });
    if (!res.ok) throw new Error('Failed to update settings');
    return res.json();
  },
  listUsers: async () => {
    const res = await fetch(`${ADMIN_URL}/users`, { headers: headers() });
    if (!res.ok) throw new Error('Failed to load users');
    return res.json();
  },
  deleteUser: async (userId) => {
    const res = await fetch(`${ADMIN_URL}/users/${userId}`, { method: 'DELETE', headers: headers() });
    if (!res.ok) throw new Error('Failed to delete user');
    return res.json();
  },
  createUser: async (payload) => {
    const res = await fetch(`${ADMIN_URL}/users`, { method: 'POST', headers: headers(), body: JSON.stringify(payload) });
    if (!res.ok) throw new Error('Failed to create user');
    return res.json();
  },
  updateUser: async (userId, payload) => {
    const res = await fetch(`${ADMIN_URL}/users/${userId}`, { method: 'PUT', headers: headers(), body: JSON.stringify(payload) });
    if (!res.ok) throw new Error('Failed to update user');
    return res.json();
  },
  listDepartments: async () => {
    const res = await fetch(`${ADMIN_URL}/departments`, { headers: headers() });
    if (!res.ok) throw new Error('Failed to load departments');
    return res.json();
  },
  setDepartmentPin: async (deptId, pin) => {
    const res = await fetch(`/api/admin/departments/${deptId}/pin`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authService.getToken()}` },
      body: JSON.stringify({ pin })
    });
    if (!res.ok) throw new Error('Failed to set PIN');
    return res.json();
  },
  clearDepartmentPin: async (deptId) => {
    const res = await fetch(`/api/admin/departments/${deptId}/pin`, {
      method: 'DELETE', headers: { 'Authorization': `Bearer ${authService.getToken()}` }
    });
    if (!res.ok) throw new Error('Failed to clear PIN');
    return res.json();
  },
  createDepartment: async (name) => {
    const res = await fetch(`${ADMIN_URL}/departments`, { method: 'POST', headers: headers(), body: JSON.stringify({ name }) });
    if (!res.ok) throw new Error('Failed to create department');
    return res.json();
  },
  deleteDepartment: async (deptId) => {
    const res = await fetch(`${ADMIN_URL}/departments/${deptId}`, { method: 'DELETE', headers: headers() });
    if (!res.ok) throw new Error('Failed to delete department');
    return res.json();
  },
  listRoles: async () => {
    const res = await fetch(`${ADMIN_URL}/roles`, { headers: headers() });
    if (!res.ok) throw new Error('Failed to load roles');
    return res.json();
  },
  createRole: async (name) => {
    const res = await fetch(`${ADMIN_URL}/roles`, { method: 'POST', headers: headers(), body: JSON.stringify({ name }) });
    if (!res.ok) throw new Error('Failed to create role');
    return res.json();
  },
  deleteRole: async (roleId) => {
    const res = await fetch(`${ADMIN_URL}/roles/${roleId}`, { method: 'DELETE', headers: headers() });
    if (!res.ok) throw new Error('Failed to delete role');
    return res.json();
  },
  listFiles: async () => {
    const res = await fetch(`${ADMIN_URL}/files`, { headers: headers() });
    if (!res.ok) throw new Error('Failed to load files');
    return res.json();
  },
  deleteFile: async (fileId) => {
    const res = await fetch(`/api/uploads/${encodeURIComponent(fileId)}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${authService.getToken()}` } });
    if (!res.ok) throw new Error('Failed to delete file');
    return res.json();
  },
  listLogs: async (limit = 100) => {
    const res = await fetch(`${ADMIN_URL}/logs?limit=${encodeURIComponent(limit)}`, { headers: headers() });
    if (!res.ok) throw new Error('Failed to load logs');
    return res.json();
  },
  clearLogs: async () => {
    const res = await fetch(`${ADMIN_URL}/logs`, { method: 'DELETE', headers: headers() });
    if (!res.ok) throw new Error('Failed to clear logs');
    return res.json();
  },
  exportLogs: async () => {
    const res = await fetch(`${ADMIN_URL}/logs/export`, { headers: headers() });
    if (!res.ok) throw new Error('Failed to export logs');
    return res.text();
  },
  verifyDepartmentPin: async (deptId, pin) => {
    const res = await fetch(`${ADMIN_URL}/departments/${deptId}/pin/verify`, { method: 'POST', headers: headers(), body: JSON.stringify({ pin }) });
    if (!res.ok) throw new Error('Failed to verify PIN');
    return res.json();
  },
  generateDepartmentPin: async (deptId) => {
    const res = await fetch(`${ADMIN_URL}/departments/${deptId}/pin/generate`, { method: 'POST', headers: headers() });
    if (!res.ok) throw new Error('Failed to generate PIN');
    return res.json();
  }
};

export default adminService;
