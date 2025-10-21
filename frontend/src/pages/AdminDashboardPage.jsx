import React, { useEffect, useState } from 'react';
import adminService from '../services/adminService';
import authService from '../services/authService';
import Alert from '../components/Alert';

const Section = ({ title, children }) => (
  <div className="panel surface raised" style={{ marginBottom: 16 }}>
    <h3>{title}</h3>
    {children}
  </div>
);

const AdminDashboardPage = () => {
  const [summary, setSummary] = useState(null);
  const [settings, setSettings] = useState(null);
  const [users, setUsers] = useState([]);
  const [depts, setDepts] = useState([]);
  const [roles, setRoles] = useState([]);
  const [files, setFiles] = useState([]);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [newDept, setNewDept] = useState('');
  const [newRole, setNewRole] = useState('');
  const [newUser, setNewUser] = useState({ username: '', password: '', email: '', employee_id: '', department_id: '', roles: '' });
  const [deptPins, setDeptPins] = useState({});
  const [userSearch, setUserSearch] = useState('');
  const [editingUserId, setEditingUserId] = useState(null);
  const [editUser, setEditUser] = useState({ username:'', email:'', employee_id:'', department_id:'', status:'' });

  const loadAll = async () => {
    try {
      const [s, sec, u, d, r, f, l] = await Promise.all([
        adminService.getSummary(),
        adminService.getSecuritySettings(),
        adminService.listUsers(),
        adminService.listDepartments(),
        adminService.listRoles(),
        adminService.listFiles(),
        adminService.listLogs(200)
      ]);
      setSummary(s);
      setSettings(sec);
      setUsers(u.users || []);
      setDepts(d.departments || []);
      setRoles(r.roles || []);
      // Filter out deleted files for clearer admin view
      setFiles((f.files || []).filter(x => !x.deleted));
      setLogs(l.logs || []);
    } catch (e) {
      setError(e.message || 'Failed to load');
    }
  };

  useEffect(() => { loadAll(); }, []);

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    try {
      setSaving(true);
      await adminService.updateSecuritySettings(settings);
    } catch (e) {
      setError(e.message || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const handleCreateDept = async (e) => {
    e.preventDefault();
    try {
      if (!newDept.trim()) return;
      await adminService.createDepartment(newDept.trim());
      setNewDept('');
      const d = await adminService.listDepartments();
      setDepts(d.departments || []);
    } catch (e) { setError(e.message || 'Failed to create department'); }
  };

  const handleCreateRole = async (e) => {
    e.preventDefault();
    try {
      if (!newRole.trim()) return;
      await adminService.createRole(newRole.trim());
      setNewRole('');
      const r = await adminService.listRoles();
      setRoles(r.roles || []);
    } catch (e) { setError(e.message || 'Failed to create role'); }
  };

  const [deletingFileId, setDeletingFileId] = useState(null);
  const handleDeleteFile = async (fileId) => {
    if (!window.confirm('Delete this file? This cannot be undone.')) return;
    try {
      setDeletingFileId(fileId);
      await adminService.deleteFile(fileId);
      const f = await adminService.listFiles();
      setFiles((f.files || []).filter(x => !x.deleted));
    } catch (e) { setError(e.message || 'Failed to delete file'); }
    finally { setDeletingFileId(null); }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      const payload = {
        username: newUser.username,
        password: newUser.password,
        email: newUser.email || undefined,
        employee_id: newUser.employee_id || undefined,
        department_id: newUser.department_id ? Number(newUser.department_id) : undefined,
        roles: newUser.roles ? newUser.roles.split(',').map(r => r.trim()).filter(Boolean) : []
      };
      await adminService.createUser(payload);
      setNewUser({ username: '', password: '', email: '', department_id: '', roles: '' });
      const u = await adminService.listUsers();
      setUsers(u.users || []);
    } catch (e) { setError(e.message || 'Failed to create user'); }
  };

  const handleDeleteUser = async (id) => {
    if (!window.confirm('Delete this user? This cannot be undone.')) return;
    try {
      await adminService.deleteUser(id);
      const u = await adminService.listUsers();
      setUsers(u.users || []);
    } catch (e) { setError(e.message || 'Failed to delete user'); }
  };

  const handleDeleteDept = async (id) => {
    if (!window.confirm('Delete this department?')) return;
    try {
      await adminService.deleteDepartment(id);
      const d = await adminService.listDepartments();
      setDepts(d.departments || []);
    } catch (e) { setError(e.message || 'Failed to delete department'); }
  };

  const handleDeleteRole = async (id) => {
    if (!window.confirm('Delete this role?')) return;
    try {
      await adminService.deleteRole(id);
      const r = await adminService.listRoles();
      setRoles(r.roles || []);
    } catch (e) { setError(e.message || 'Failed to delete role'); }
  };

  if (!authService.isAdmin()) {
    return (
      <div className="container wide admin-dashboard">
        <div className="page-header"><h2>Admin Dashboard</h2></div>
        <div className="panel surface"><p>Access denied.</p></div>
      </div>
    );
  }

  return (
    <div className="container wide admin-dashboard">
      <div className="page-header">
        <div>
          <h2>Admin Dashboard</h2>
          <p className="muted">Manage users, roles, departments, files, and security settings.</p>
        </div>
      </div>
  {error && <Alert type="error" message={error} />}

      <Section title="Summary">
        {!summary ? <p>Loading…</p> : (
          <ul>
            <li>Users: {summary.users}</li>
            <li>Files: {summary.files}</li>
            <li>Departments: {summary.departments}</li>
            <li>Roles: {summary.roles}</li>
          </ul>
        )}
      </Section>

      <Section title="Security Settings">
        {!settings ? <p>Loading…</p> : (
          <form onSubmit={handleSaveSettings}>
            <label><input type="checkbox" checked={!!settings.enforce_mfa_admin} onChange={e => setSettings({ ...settings, enforce_mfa_admin: e.target.checked })} /> Enforce MFA for admins</label><br />
            <label><input type="checkbox" checked={!!settings.enforce_mfa_all} onChange={e => setSettings({ ...settings, enforce_mfa_all: e.target.checked })} /> Enforce MFA for users</label><br />
            <label>Min Password Length <input type="number" value={settings.min_password_length || 8} onChange={e => setSettings({ ...settings, min_password_length: Number(e.target.value) })} /></label><br />
            <label>Password Regex <input type="text" value={settings.password_regex || ''} onChange={e => setSettings({ ...settings, password_regex: e.target.value })} placeholder="optional" /></label><br />
            <button type="submit" className="primary" disabled={saving}>{saving ? 'Saving…' : 'Save Settings'}</button>
          </form>
        )}
      </Section>

      <Section title="Users">
        <div style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
          <form onSubmit={handleCreateUser} style={{ marginBottom: 12 }}>
            <strong>Create User</strong><br />
            <input placeholder="username" value={newUser.username} onChange={e => setNewUser({ ...newUser, username: e.target.value })} />{' '}
            <input placeholder="password" type="password" value={newUser.password} onChange={e => setNewUser({ ...newUser, password: e.target.value })} />{' '}
            <input placeholder="email (optional)" value={newUser.email} onChange={e => setNewUser({ ...newUser, email: e.target.value })} />{' '}
            <input placeholder="employee_id (e.g., HR001)" value={newUser.employee_id} onChange={e => setNewUser({ ...newUser, employee_id: e.target.value.toUpperCase() })} style={{width:140}} />{' '}
            <select value={newUser.department_id} onChange={e => setNewUser({ ...newUser, department_id: e.target.value })}>
              <option value="">select dept</option>
              {depts.map(d => <option key={d.id} value={d.id}>{d.name} (#{d.id})</option>)}
            </select>{' '}
            <input placeholder="roles (comma-separated)" value={newUser.roles} onChange={e => setNewUser({ ...newUser, roles: e.target.value })} />{' '}
            <button type="submit">Create</button>
            <div className="muted" style={{marginTop:6}}>
              Tip: Use department initials followed by a 3-digit sequence for Employee ID (e.g., HR001, IT023).
            </div>
          </form>
          <div style={{marginLeft:16}}>
            <input placeholder="Search users..." value={userSearch} onChange={e=>setUserSearch(e.target.value)} />
          </div>
        </div>
        {!users.length ? <p>No users.</p> : (
          <table className="table"><thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Employee ID</th><th>Dept</th><th>Status</th><th>Actions</th></tr></thead><tbody>
            {users.filter(u=>{
              const q = userSearch.toLowerCase();
              if (!q) return true;
              return (
                (u.username||'').toLowerCase().includes(q) ||
                (u.email||'').toLowerCase().includes(q) ||
                (u.employee_id||'').toLowerCase().includes(q) ||
                String(u.id).includes(q)
              );
            }).map(u => (
              <tr key={u.id}>
                <td>{u.id}</td>
                <td>{editingUserId===u.id ? (
                  <input value={editUser.username} onChange={e=>setEditUser({...editUser, username:e.target.value})} />
                ) : u.username}</td>
                <td>{editingUserId===u.id ? (
                  <input value={editUser.email||''} onChange={e=>setEditUser({...editUser, email:e.target.value})} />
                ) : (u.email || '-')}</td>
                <td>{editingUserId===u.id ? (
                  <input value={editUser.employee_id||''} onChange={e=>setEditUser({...editUser, employee_id:e.target.value.toUpperCase()})} style={{width:120}} />
                ) : (u.employee_id || '-')}</td>
                <td>{editingUserId===u.id ? (
                  <select value={editUser.department_id ?? ''} onChange={e=>setEditUser({...editUser, department_id: e.target.value? Number(e.target.value): null})}>
                    <option value="">none</option>
                    {depts.map(d=> <option key={d.id} value={d.id}>{d.name}</option>)}
                  </select>
                ) : ((depts.find(d=>d.id===u.department_id)||{}).name || u.department_id || '-')}</td>
                <td>{editingUserId===u.id ? (
                  <select value={editUser.status||'active'} onChange={e=>setEditUser({...editUser, status:e.target.value})}>
                    <option value="active">active</option>
                    <option value="inactive">inactive</option>
                  </select>
                ) : u.status}
                </td>
                <td>
                  {editingUserId===u.id ? (
                    <>
                      <button onClick={async()=>{ try{ await adminService.updateUser(u.id, editUser); setEditingUserId(null); const uu = await adminService.listUsers(); setUsers(uu.users||[]);} catch(e){ setError(e.message||'Update failed'); } }}>Save</button>{' '}
                      <button onClick={()=>{ setEditingUserId(null); setEditUser({}); }}>Cancel</button>
                    </>
                  ): (
                    <>
                      <button onClick={()=>{ setEditingUserId(u.id); setEditUser({ username:u.username, email:u.email||'', employee_id:u.employee_id||'', department_id:u.department_id??'', status:u.status||'active' }); }}>Edit</button>{' '}
                      <button className="danger" onClick={()=>handleDeleteUser(u.id)}>Delete</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody></table>
        )}
      </Section>

      <Section title="Departments">
        <form onSubmit={handleCreateDept} style={{ marginBottom: 12 }}>
          <strong>Create Department</strong><br />
          <input placeholder="Department name" value={newDept} onChange={e => setNewDept(e.target.value)} />{' '}
          <button type="submit">Create</button>
        </form>
        {!depts.length ? <p>No departments.</p> : (
          <table className="table"><thead><tr><th>ID</th><th>Name</th><th>PIN</th><th>Actions</th></tr></thead><tbody>
            {depts.map(d => (
              <tr key={d.id}>
                <td>{d.id}</td>
                <td>{d.name}</td>
                <td>
                  <div style={{display:'flex', alignItems:'center', gap:8}}>
                    <span className={d.pin_set ? 'badge success' : 'badge'}>{d.pin_set ? 'PIN set' : 'No PIN'}</span>
                    <input style={{width:160}} placeholder="new PIN (4-8 chars)" value={deptPins[d.id] || ''} onChange={e => setDeptPins({ ...deptPins, [d.id]: e.target.value })} />
                    <button onClick={async()=>{ try{ await adminService.setDepartmentPin(d.id, deptPins[d.id]); setDeptPins({ ...deptPins, [d.id]: '' }); const d2 = await adminService.listDepartments(); setDepts(d2.departments||[]);} catch(e){ setError(e.message||'Failed'); }}}>Set</button>
                    <button onClick={async()=>{ try{ await adminService.clearDepartmentPin(d.id); const d2 = await adminService.listDepartments(); setDepts(d2.departments||[]);} catch(e){ setError(e.message||'Failed'); }}}>Clear</button>
                    <button onClick={async()=>{ try{ const r = await adminService.generateDepartmentPin(d.id); alert(`New PIN for ${d.name}: ${r.pin}\nPlease store it securely. It will not be shown again.`); const d2 = await adminService.listDepartments(); setDepts(d2.departments||[]);} catch(e){ setError(e.message||'Failed to generate'); }}}>Generate</button>
                    <button onClick={async()=>{ 
                      const pin = prompt('Enter a PIN to verify against this department');
                      if (pin==null) return;
                      try{ const r = await adminService.verifyDepartmentPin(d.id, pin); alert(r.valid ? 'PIN matches' : 'Invalid PIN'); } catch(e){ setError(e.message||'Verification failed'); }
                    }}>Verify</button>
                  </div>
                </td>
                <td><button className="danger" onClick={()=>handleDeleteDept(d.id)}>Delete</button></td>
              </tr>
            ))}
          </tbody></table>
        )}
      </Section>

      <Section title="Roles">
        <form onSubmit={handleCreateRole} style={{ marginBottom: 12 }}>
          <strong>Create Role</strong><br />
          <input placeholder="Role name" value={newRole} onChange={e => setNewRole(e.target.value)} />{' '}
          <button type="submit">Create</button>
        </form>
        {!roles.length ? <p>No roles.</p> : (
          <table className="table"><thead><tr><th>ID</th><th>Name</th><th>Actions</th></tr></thead><tbody>
            {roles.map(r => (
              <tr key={r.id}><td>{r.id}</td><td>{r.name}</td><td><button className="danger" onClick={()=>handleDeleteRole(r.id)}>Delete</button></td></tr>
            ))}
          </tbody></table>
        )}
      </Section>

      <Section title="Files">
        {!files.length ? <p>No files.</p> : (
          <table className="table"><thead><tr><th>File ID</th><th>Name</th><th>Size</th><th>Dept</th><th>Owner</th><th>Expires</th><th>Scan</th><th>Actions</th></tr></thead><tbody>
            {files.map(f => (
              <tr key={f.file_id}>
                <td><code className="break-all">{f.file_id}</code></td>
                <td>{f.orig_name}</td>
                <td>{f.size}</td>
                <td>{f.department_id || '-'}</td>
                <td>{f.owner_user_id || '-'}</td>
                <td>{f.expires_at || '-'}</td>
                <td>{f.scan_status || '-'}</td>
                <td>
                  <button className="danger" disabled={deletingFileId===f.file_id} onClick={() => handleDeleteFile(f.file_id)}>
                    {deletingFileId===f.file_id ? 'Deleting…' : 'Delete'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody></table>
        )}
      </Section>

      <Section title="Audit Logs (latest)">
        <div style={{display:'flex', gap:8, marginBottom:8}}>
          <button onClick={async()=>{ try{ await adminService.clearLogs(); const l = await adminService.listLogs(200); setLogs(l.logs||[]);} catch(e){ setError(e.message||'Failed to clear logs'); } }}>Clear Logs</button>
          <button onClick={async()=>{ try{ const text = await adminService.exportLogs(); const blob = new Blob([text], { type: 'text/plain' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `audit-logs-${new Date().toISOString().replace(/[:.]/g,'-')}.txt`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);} catch(e){ setError(e.message||'Failed to download logs'); } }}>Download .txt</button>
        </div>
        {!logs.length ? <p>No logs.</p> : (
          <table className="table"><thead><tr><th>Time</th><th>Action</th><th>File</th><th>User</th><th>IP</th><th>Meta</th></tr></thead><tbody>
            {logs.map(l => <tr key={l.id}><td>{l.ts || '-'}</td><td>{l.action}</td><td><code className="break-all">{l.file_id}</code></td><td>{l.actor_user_id || '-'}</td><td>{l.ip || '-'}</td><td><code className="break-all">{JSON.stringify(l.meta || {})}</code></td></tr>)}
          </tbody></table>
        )}
      </Section>
    </div>
  );
};

export default AdminDashboardPage;
