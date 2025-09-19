// /home/tsn/PcapEditor/frontend/src/api.js
import axios from 'axios';

const API_URL = 'http://localhost:5001/api';

export const uploadPcap = (file) => {
  const formData = new FormData();
  formData.append('file', file);
  return axios.post(`${API_URL}/upload`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};

export const getPacketDetail = (packetId) => {
  return axios.get(`${API_URL}/packet/${packetId}`);
};

export const updatePacket = (packetId, hexData) => {
  return axios.post(`${API_URL}/packet/${packetId}/update`, { hex: hexData });
};

export const savePcap = (filename) => {
  return axios.post(`${API_URL}/save`, { filename }, {
    responseType: 'blob', // Important for file downloads
  });
};

export const undo = () => {
  return axios.post(`${API_URL}/undo`);
};

export const redo = () => {
  return axios.post(`${API_URL}/redo`);
};

export const deletePacket = (packetId) => {
  return axios.post(`${API_URL}/packet/${packetId}/delete`);
};

export const updatePacketTimestamp = (packetId, timestamp) => {
  return axios.post(`${API_URL}/packet/${packetId}/update_timestamp`, { timestamp });
};
