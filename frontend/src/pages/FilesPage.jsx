import React, { useEffect, useState } from 'react';
import fileService from '../services/fileService';
import FileList from '../components/FileList';
import Alert from '../components/Alert';

const FilesPage = () => {
  const [files, setFiles] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState('');

  useEffect(() => {
    refresh();
  }, []);

  const refresh = () => {
    setLoading(true);
    fileService.listFiles()
      .then(f => { setFiles(f); setError(''); })
      .catch(() => setError('Failed to fetch files'))
      .finally(()=> setLoading(false));
  };

  useEffect(()=>{
    if(!query){ setFiltered(files); return; }
    const q = query.toLowerCase();
    setFiltered(files.filter(f => f.name.toLowerCase().includes(q)));
  }, [query, files]);

  return (
    <div className="container wide files-dashboard">
      <div className="files-header">
        <div>
          <h2>Your Files</h2>
          <p className="muted">Secure vault of uploaded content. Expiring links auto-clean once time is up.</p>
        </div>
        <div className="files-actions">
          <div className="search-box">
            <input
              type="text"
              placeholder="Search files..."
              value={query}
              onChange={e=>setQuery(e.target.value)}
            />
            {query && <button className="plain" onClick={()=>setQuery('')} aria-label="Clear">×</button>}
          </div>
          <button onClick={refresh} className="refresh-btn" disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>
      {error && <Alert type="error" message={error} />}
      <FileList files={filtered} setFiles={setFiles} originalFiles={files} />
    </div>
  );
};

export default FilesPage;
