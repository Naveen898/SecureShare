import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000'; // Update with your backend URL

export const uploadFile = async (file, token) => {
    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await axios.post(`${API_BASE_URL}/upload`, formData, {
            headers: {
                'Content-Type': 'multipart/form-data',
                'Authorization': `Bearer ${token}`
            }
        });
        return response.data;
    } catch (error) {
        throw new Error('File upload failed: ' + error.message);
    }
};

export const downloadFile = async (fileId, token) => {
    try {
        const response = await axios.get(`${API_BASE_URL}/download/${fileId}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            },
            responseType: 'blob' // Important for file download
        });
        return response.data;
    } catch (error) {
        throw new Error('File download failed: ' + error.message);
    }
};

export const validateToken = async (token) => {
    try {
        const response = await axios.get(`${API_BASE_URL}/auth/validate`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        return response.data;
    } catch (error) {
        throw new Error('Token validation failed: ' + error.message);
    }
};