import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Inject JWT auth token into headers
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

export const mapPacket = (p) => ({
  id: p.id,
  scanId: p.scan_id,
  index: p.packet_index,
  timestamp: p.timestamp,
  sourceIp: p.source_ip,
  destIp: p.dest_ip,
  protocol: p.protocol,
  length: p.length,
  info: p.info,
  isThreat: p.is_threat,
  rawPayload: p.raw_payload,
  payloadHash: p.payload_hash,
});

export const mapDetection = (d) => ({
  id: d.id,
  scanId: d.scan_id,
  packetIndex: d.packet_index,
  md5Hash: d.md5_hash,
  ruleName: d.rule_name,
  description: d.description,
  author: d.author,
  tags: typeof d.tags === 'string' ? JSON.parse(d.tags) : (d.tags || []),
  severity: d.severity,
  vtPositives: d.vt_positives,
  vtTotal: d.vt_total,
  rawPayload: d.raw_payload,
});

export const mapScan = (s) => ({
  id: s.id,
  filename: s.filename,
  fileSize: s.file_size,
  totalPackets: s.total_packets,
  status: s.status,
  startedAt: s.started_at,
  completedAt: s.completed_at,
  threatCount: s.threat_count,
  packets: s.packets ? s.packets.map(mapPacket) : [],
  detections: s.detections ? s.detections.map(mapDetection) : [],
});

export const authAPI = {
  login: async (email, password) => {
    const response = await apiClient.post('/auth/login', { email, password });
    return response.data;
  },
  register: async (email, password, role = 'analyst') => {
    const response = await apiClient.post('/auth/register', { email, password, role });
    return response.data;
  },
};

export const workspacesAPI = {
  list: async () => {
    const response = await apiClient.get('/workspaces');
    return response.data;
  },
  create: async (payload) => {
    const response = await apiClient.post('/workspaces', payload);
    return response.data;
  },
  update: async (id, payload) => {
    const response = await apiClient.put(`/workspaces/${id}`, payload);
    return response.data;
  },
  delete: async (id) => {
    await apiClient.delete(`/workspaces/${id}`);
  },
  access: async (id) => {
    const response = await apiClient.post(`/workspaces/${id}/access`);
    return response.data;
  },
};

export const usersAPI = {
  getProfile: async () => {
    const response = await apiClient.get('/users/profile');
    return response.data;
  },
  updateProfile: async (payload) => {
    const response = await apiClient.put('/users/profile', payload);
    return response.data;
  },
};

export const scansAPI = {
  listScans: async (workspaceId) => {
    const response = await apiClient.get('/scans', {
      params: { workspace_id: workspaceId },
    });
    return response.data.map(mapScan);
  },
  getScanDetails: async (scanId) => {
    const response = await apiClient.get(`/scans/${scanId}`);
    return mapScan(response.data);
  },
  uploadScan: async (file, workspaceId, onUploadProgress) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await apiClient.post('/scans/upload', formData, {
      params: { workspace_id: workspaceId },
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress,
    });
    return mapScan(response.data);
  },
  getPackets: async (scanId) => {
    const response = await apiClient.get(`/scans/${scanId}/packets`);
    return response.data.map(mapPacket);
  },
  getDetections: async (scanId) => {
    const response = await apiClient.get(`/scans/${scanId}/detections`);
    return response.data.map(mapDetection);
  },
};

export default apiClient;
