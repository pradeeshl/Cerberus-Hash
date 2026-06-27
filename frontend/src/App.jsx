import { useMemo, useState, useEffect } from 'react';
import Sidebar from './components/Sidebar.jsx';
import AuthPage from './features/auth/AuthPage.jsx';
import Dashboard from './features/dashboard/Dashboard.jsx';
import UploadWorkspace from './features/scans/UploadWorkspace.jsx';
import ScanReport from './features/scans/ScanReport.jsx';
import ProfilePage from './features/profile/ProfilePage.jsx';
import WorkspaceModal from './components/WorkspaceModal.jsx';
import { scansAPI, workspacesAPI, usersAPI } from './api';

function parseDateValue(value) {
  if (!value) return 0;
  // Handle ISO string or custom date format
  return new Date(value.includes('T') ? value : value.replace(' ', 'T')).getTime();
}

export default function App() {
  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem('user');
    return savedUser ? JSON.parse(savedUser) : null;
  });
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [loadingScans, setLoadingScans] = useState(false);

  // Workspace-related states
  const [workspaces, setWorkspaces] = useState([]);
  const [activeWorkspace, setActiveWorkspace] = useState(null);
  const [isWorkspaceModalOpen, setIsWorkspaceModalOpen] = useState(false);

  // Fetch workspaces when user changes
  useEffect(() => {
    if (!user) {
      setWorkspaces([]);
      setActiveWorkspace(null);
      return;
    }

    const fetchWorkspaces = async () => {
      try {
        const list = await workspacesAPI.list();
        setWorkspaces(list);
        
        // Find default or saved active workspace
        const savedId = localStorage.getItem('activeWorkspaceId');
        let active = null;
        if (savedId) {
          active = list.find(w => w.id === Number(savedId));
        }
        if (!active && user.default_workspace_id) {
          active = list.find(w => w.id === user.default_workspace_id);
        }
        if (!active && list.length > 0) {
          active = list[0];
        }
        setActiveWorkspace(active || null);
      } catch (err) {
        console.error('Failed to fetch workspaces:', err);
      }
    };

    fetchWorkspaces();
  }, [user]);

  // Fetch scans when active workspace changes
  useEffect(() => {
    if (!user || !activeWorkspace) {
      setScans([]);
      return;
    }

    const fetchScans = async () => {
      setLoadingScans(true);
      try {
        const fetchedScans = await scansAPI.listScans(activeWorkspace.id);
        setScans(fetchedScans.sort((left, right) => parseDateValue(right.startedAt) - parseDateValue(left.startedAt)));
      } catch (error) {
        console.error('Failed to fetch scans:', error);
      } finally {
        setLoadingScans(false);
      }
    };

    fetchScans();
  }, [user, activeWorkspace]);

  const selectedScan = useMemo(
    () => scans.find((scan) => scan.id === selectedScanId) ?? scans[0] ?? null,
    [scans, selectedScanId],
  );

  const handleLogin = (account) => {
    setUser(account);
    setActiveTab('dashboard');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('activeWorkspaceId');
    setUser(null);
    setActiveTab('dashboard');
    setSelectedScanId(null);
  };

  const handleOpenScan = (scanId) => {
    setSelectedScanId(scanId);
    setActiveTab('scan-report');
  };

  const handleUploadComplete = (uploadedScan) => {
    setScans((currentScans) => [uploadedScan, ...currentScans]);
    setSelectedScanId(uploadedScan.id);
    setActiveTab('scan-report');
  };

  const handleSelectWorkspace = async (workspaceId) => {
    const ws = workspaces.find(w => w.id === workspaceId);
    if (ws) {
      setActiveWorkspace(ws);
      localStorage.setItem('activeWorkspaceId', workspaceId);
      try {
        await workspacesAPI.access(workspaceId);
      } catch (err) {
        console.error('Failed to mark workspace access:', err);
      }
    }
  };

  const handleCreateWorkspace = async (payload) => {
    const newWs = await workspacesAPI.create(payload);
    setWorkspaces(prev => [newWs, ...prev]);
    setActiveWorkspace(newWs);
    localStorage.setItem('activeWorkspaceId', newWs.id);
  };

  const handleUpdateProfile = async (payload) => {
    const updated = await usersAPI.updateProfile(payload);
    setUser(updated);
    localStorage.setItem('user', JSON.stringify(updated));
    const list = await workspacesAPI.list();
    setWorkspaces(list);
    if (payload.default_workspace_id) {
      const active = list.find(w => w.id === payload.default_workspace_id);
      if (active) {
        setActiveWorkspace(active);
        localStorage.setItem('activeWorkspaceId', active.id);
      }
    }
  };

  if (!user) {
    return <AuthPage onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-[#030712] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -left-24 top-12 h-72 w-72 rounded-full bg-violet-600/15 blur-3xl" />
        <div className="absolute right-0 top-32 h-80 w-80 rounded-full bg-cyan-500/15 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-96 w-96 rounded-full bg-purple-500/10 blur-3xl" />
      </div>

      <div className="relative grid min-h-screen lg:grid-cols-[18rem_minmax(0,1fr)]">
        <Sidebar 
          activeTab={activeTab} 
          setActiveTab={setActiveTab} 
          user={user} 
          onLogout={handleLogout} 
          workspaces={workspaces}
          activeWorkspace={activeWorkspace}
          onSelectWorkspace={handleSelectWorkspace}
          onCreateWorkspaceClick={() => setIsWorkspaceModalOpen(true)}
        />

        <main className="relative flex min-h-screen flex-col p-4 sm:p-6 lg:p-8">
          <div key={activeTab} className="animate-fade-in flex flex-col gap-6 w-full">
            {activeTab === 'dashboard' && (
              <Dashboard scans={scans} onOpenScan={handleOpenScan} title={activeWorkspace ? `${activeWorkspace.name} Dashboard` : "Operational Dashboard"} />
            )}

            {activeTab === 'history' && (
              <Dashboard scans={scans} onOpenScan={handleOpenScan} title="Scan History" />
            )}

            {activeTab === 'upload' && activeWorkspace && (
              <UploadWorkspace activeWorkspaceId={activeWorkspace.id} onUploadComplete={handleUploadComplete} />
            )}

            {activeTab === 'profile' && (
              <ProfilePage user={user} workspaces={workspaces} onUpdateProfile={handleUpdateProfile} />
            )}

            {activeTab === 'scan-report' && selectedScan && (
              <ScanReport
                key={selectedScan.id}
                scan={selectedScan}
              />
            )}

            {activeTab === 'scan-report' && !selectedScan && (
              <div className="glass-panel flex min-h-[24rem] items-center justify-center rounded-3xl p-8 text-slate-400">
                Select a completed scan to inspect packet-level findings.
              </div>
            )}
          </div>
        </main>
      </div>

      <WorkspaceModal 
        isOpen={isWorkspaceModalOpen}
        onClose={() => setIsWorkspaceModalOpen(false)}
        onCreate={handleCreateWorkspace}
      />
    </div>
  );
}