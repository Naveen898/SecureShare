import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import authService from '../services/authService';

const Navbar = () => {
  const navigate = useNavigate();
  const isLoggedIn = authService.isAuthenticated();
  const profile = authService.getProfile();

  const handleLogout = () => {
    authService.logout();
    navigate('/login');
  };

  return (
    <nav className="navbar" style={{display:'flex', gap:12, alignItems:'center'}}>
      <Link to="/files">SecureShare</Link>
      {isLoggedIn ? (
        <>
          <Link to="/upload">Upload</Link>
          <Link to="/receive">Receive</Link>
          <Link to="/transfers">My Transfers</Link>
          {authService.isAdmin() && <Link to="/admin">Dashboard</Link>}
          {authService.isAdmin() && <Link to="/admin/transfers">Approvals</Link>}
          <div style={{marginLeft:'auto', display:'flex', alignItems:'center', gap:12}}>
            <span className="muted">{profile?.employee_id ? `${profile.employee_id} • ` : ''}{profile?.username || ''}</span>
            <button onClick={handleLogout}>Logout</button>
          </div>
        </>
      ) : (
        <div style={{marginLeft:'auto'}}>
          <Link to="/login">Login</Link>
        </div>
      )}
    </nav>
  );
};

export default Navbar;
