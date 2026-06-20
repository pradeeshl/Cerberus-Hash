import { useMemo, useState } from 'react';
import Sidebar from './components/Sidebar.jsx';
import AuthPage from './features/auth/AuthPage.jsx';
import Dashboard from './features/dashboard/Dashboard.jsx';
import UploadWorkspace from './features/scans/UploadWorkspace.jsx';
import ScanReport from './features/scans/ScanReport.jsx';
import { mockDetections, mockPackets, mockScans } from './mockData.js';

function parseDateValue(value) {
  return value ? new Date(value.replace(' ', 'T')).getTime() : 0;
}

export default function App() {
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scans, setScans] = useState(() => [...mockScans].sort((left, right) => parseDateValue(right.startedAt) - parseDateValue(left.startedAt)));
  const [selectedScanId, setSelectedScanId] = useState(null);

  const selectedScan = useMemo(
    () => scans.find((scan) => scan.id === selectedScanId) ?? scans[0] ?? null,
    [scans, selectedScanId],
  );

  const handleLogin = (account) => {
    setUser(account);
    setActiveTab('dashboard');
  };

  const handleLogout = () => {
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

  if (!user) {
    return <AuthPage onLogin={handleLogin} />;
  }

  return (
    <div className="min-h-screen bg-[#030712] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -left-24 top-12 h-72 w-72 rounded-full bg-emerald-500/10 blur-3xl" />
        <div className="absolute right-0 top-32 h-80 w-80 rounded-full bg-rose-500/10 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-96 w-96 rounded-full bg-cyan-500/5 blur-3xl" />
      </div>

      <div className="relative grid min-h-screen lg:grid-cols-[18rem_minmax(0,1fr)]">
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} user={user} onLogout={handleLogout} />

        <main className="relative flex min-h-screen flex-col gap-6 p-4 sm:p-6 lg:p-8">
          {activeTab === 'dashboard' && (
            <Dashboard scans={scans} onOpenScan={handleOpenScan} title="Operational Dashboard" />
          )}

          {activeTab === 'history' && (
            <Dashboard scans={scans} onOpenScan={handleOpenScan} title="Scan History" />
          )}

          {activeTab === 'upload' && <UploadWorkspace onUploadComplete={handleUploadComplete} />}

          {activeTab === 'scan-report' && selectedScan && (
            <ScanReport
              key={selectedScan.id}
              scan={selectedScan}
              fallbackPackets={mockPackets[selectedScan.id] ?? []}
              fallbackDetections={mockDetections[selectedScan.id] ?? []}
            />
          )}

          {activeTab === 'scan-report' && !selectedScan && (
            <div className="glass-panel flex min-h-[24rem] items-center justify-center rounded-3xl p-8 text-slate-400">
              Select a completed scan to inspect packet-level findings.
            </div>
          )}
        </main>
      </div>
    </div>
  );
}