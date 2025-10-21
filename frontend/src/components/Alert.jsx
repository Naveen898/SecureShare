import React from 'react';

const Alert = ({ type, message }) => (
  <div className={`alert alert-${type}`}>{message}</div>
);

export default Alert;
