import React, { useState } from 'react';
import fileService from '../services/fileService';

function formatExpiry(file){
  if(file.expires_at_ist) return file.expires_at_ist;
  if(!file.expires_at) return 'N/A';
  // fallback to raw iso if server not yet updated
  return file.expires_at;
}

const FileList = ({ files, setFiles }) => {
  const [confirming, setConfirming] = useState(null); // file_id being confirmed
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async (fileId) => {
    setDeleting(true);
    try {
      await fileService.deleteFile(fileId);
      setFiles(files.filter(f => f.file_id !== fileId));
    } finally {
      setDeleting(false);
      setConfirming(null);
    }
  };

  if(!files.length) {
    return <div className="empty-state">
      <div className="empty-illustration">📁</div>
      <h3>No files yet</h3>
      <p className="muted">Upload a file to get started. Your secure vault will show them here.</p>
    </div>;
  }
  return (
    <div className="files-grid">
      {files.map(file => {
        const sizeKB = file.size ? (file.size/1024).toFixed(1) : null;
        // Compute department display: show name(s) if provided
        const fromDept = file.from_department || null;
        const toDept = file.to_department || null;
        const deptDisplay = (() => {
          if (fromDept && toDept && fromDept !== toDept) return `${fromDept} → ${toDept}`;
          if (toDept) return toDept;
          if (fromDept) return fromDept;
          return file.department_id ?? '-';
        })();
        return (
          <div key={file.file_id} className="file-card">
            <div className="file-card-main">
              <div className="file-icon" aria-hidden>📄</div>
              <div className="file-meta">
                <a className="file-name" href={file.downloadUrl} target="_blank" rel="noopener noreferrer" title={file.name}>{file.name}</a>
                <div className="file-sub">
                  {sizeKB && <span>{sizeKB} KB</span>}<span className="dot" />
                  <span className="exp">Dept: {deptDisplay}</span><span className="dot" />
                  <span className="exp">Expires: {formatExpiry(file)}</span>
                </div>
              </div>
            </div>
            <div className="file-actions">
              {confirming === file.file_id ? (
                <>
                  <button className="danger" disabled={deleting} onClick={() => handleDelete(file.file_id)}>{deleting ? 'Deleting...' : 'Confirm'}</button>
                  <button className="plain" disabled={deleting} onClick={() => setConfirming(null)}>Cancel</button>
                </>
              ) : (
                <button className="danger outline" onClick={() => setConfirming(file.file_id)}>Delete</button>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default FileList;
