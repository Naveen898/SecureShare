import React from 'react';
import FileUploadForm from '../components/FileUploadForm';

const UploadPage = () => (
  <div className="container wide upload-dashboard">
    <div className="page-header">
      <div>
        <h2>Upload File</h2>
        <p className="muted">Add a file to your secure vault. Each file is scanned and given an expiring share link.</p>
      </div>
    </div>
    <div className="panel surface">
      <FileUploadForm />
    </div>
  </div>
);

export default UploadPage;
