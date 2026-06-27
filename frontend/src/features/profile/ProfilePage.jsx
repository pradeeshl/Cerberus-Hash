import { useState, useEffect } from 'react';
import { 
  User, 
  ShieldAlert, 
  Mail, 
  Bell, 
  Database,
  CheckCircle,
  HelpCircle,
  Eye
} from 'lucide-react';

const AVATARS = [
  { id: 'avatar_default', label: 'Default', bg: 'bg-slate-800 text-slate-400' },
  { id: 'avatar_analyst', label: 'Cyber Analyst', bg: 'bg-violet-600/20 text-violet-400 border border-violet-500/30' },
  { id: 'avatar_hunter', label: 'Threat Hunter', bg: 'bg-cyan-600/20 text-cyan-400 border border-cyan-500/30' },
  { id: 'avatar_operator', label: 'Core Operator', bg: 'bg-emerald-600/20 text-emerald-400 border border-emerald-500/30' },
  { id: 'avatar_expert', label: 'Forensic Lead', bg: 'bg-rose-600/20 text-rose-400 border border-rose-500/30' },
];

export default function ProfilePage({ 
  user = {}, 
  workspaces = [], 
  onUpdateProfile 
}) {
  const [email, setEmail] = useState(user.email || '');
  const [role, setRole] = useState(user.role || 'analyst');
  const [avatar, setAvatar] = useState(user.avatar || 'avatar_default');
  const [defaultWorkspaceId, setDefaultWorkspaceId] = useState(user.default_workspace_id || '');
  
  // Preferences
  const [emailAlerts, setEmailAlerts] = useState(user.preferences?.email_alerts !== false);
  const [desktopAlerts, setDesktopAlerts] = useState(user.preferences?.desktop_alerts !== false);
  const [autoCleanup, setAutoCleanup] = useState(user.preferences?.auto_cleanup === true);

  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    setEmail(user.email || '');
    setRole(user.role || 'analyst');
    setAvatar(user.avatar || 'avatar_default');
    setDefaultWorkspaceId(user.default_workspace_id || '');
    setEmailAlerts(user.preferences?.email_alerts !== false);
    setDesktopAlerts(user.preferences?.desktop_alerts !== false);
    setAutoCleanup(user.preferences?.auto_cleanup === true);
  }, [user]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(false);
    setLoading(true);

    try {
      await onUpdateProfile({
        email,
        role,
        avatar,
        default_workspace_id: defaultWorkspaceId ? Number(defaultWorkspaceId) : null,
        preferences: {
          email_alerts: emailAlerts,
          desktop_alerts: desktopAlerts,
          auto_cleanup: autoCleanup,
        }
      });
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update profile settings.');
    } finally {
      setLoading(false);
    }
  };

  const selectedAvatarObj = AVATARS.find(av => av.id === avatar) || AVATARS[0];

  return (
    <div className="space-y-6 max-w-4xl">
      <section className="glass-panel rounded-[2rem] p-6 sm:p-8">
        <div className="flex flex-col gap-4 border-b border-white/10 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl space-y-3">
            <div className="inline-flex items-center gap-2 rounded-full border border-violet-400/20 bg-violet-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.3em] text-violet-300">
              <User className="h-3.5 w-3.5" />
              User Control
            </div>
            <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Profile & Preferences</h1>
            <p className="max-w-3xl text-sm leading-6 text-slate-400 sm:text-base">
              Manage your credentials, change your analyst designation, select a primary workspace, and customize system notification alerts.
            </p>
          </div>
        </div>

        {success && (
          <div className="mt-6 flex items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3.5 text-sm text-emerald-300">
            <CheckCircle className="h-4 w-4" />
            Profile and configurations updated successfully.
          </div>
        )}

        {error && (
          <div className="mt-6 rounded-xl border border-rose-500/20 bg-rose-500/10 p-3.5 text-sm text-rose-400">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-8 space-y-6">
          {/* Avatar Selector */}
          <div className="space-y-3">
            <label className="text-sm font-semibold text-slate-300 block">Avatar / Designation Card</label>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {AVATARS.map(av => {
                const isSelected = avatar === av.id;
                return (
                  <button
                    key={av.id}
                    type="button"
                    onClick={() => setAvatar(av.id)}
                    className={`flex flex-col items-center justify-center p-4 rounded-2xl border transition ${
                      isSelected 
                        ? 'border-violet-500 bg-violet-500/10' 
                        : 'border-white/10 bg-slate-950/40 hover:border-white/20'
                    }`}
                  >
                    <div className={`h-12 w-12 rounded-full flex items-center justify-center font-bold text-lg ${av.bg}`}>
                      {av.label[0]}
                    </div>
                    <span className="mt-2 text-xs font-semibold text-white text-center truncate w-full">
                      {av.label}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid gap-6 md:grid-cols-2">
            {/* Left Col - Info */}
            <div className="space-y-4">
              <label className="block space-y-2">
                <span className="text-sm font-medium text-slate-300">Email Address</span>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-3.5 h-4 w-4 text-slate-500" />
                  <input
                    type="email"
                    required
                    disabled={loading}
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full rounded-2xl border border-white/10 bg-slate-950/60 pl-11 pr-4 py-3 text-slate-100 outline-none focus:border-violet-500/50 focus:ring-2 focus:ring-violet-500/20 text-sm"
                  />
                </div>
              </label>

              <label className="block space-y-2">
                <span className="text-sm font-medium text-slate-300">Default Workspace</span>
                <div className="relative">
                  <Database className="absolute left-3.5 top-3.5 h-4 w-4 text-slate-500" />
                  <select
                    disabled={loading}
                    value={defaultWorkspaceId}
                    onChange={(e) => setDefaultWorkspaceId(e.target.value)}
                    className="w-full rounded-2xl border border-white/10 bg-slate-950/60 pl-11 pr-4 py-3 text-slate-100 outline-none focus:border-violet-500/50 focus:ring-2 focus:ring-violet-500/20 text-sm appearance-none"
                  >
                    <option value="">No Default Workspace</option>
                    {workspaces.map(ws => (
                      <option key={ws.id} value={ws.id}>{ws.name}</option>
                    ))}
                  </select>
                </div>
              </label>

              <label className="block space-y-2">
                <span className="text-sm font-medium text-slate-300">Designation Role</span>
                <input
                  type="text"
                  required
                  disabled={loading}
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100 outline-none focus:border-violet-500/50 focus:ring-2 focus:ring-violet-500/20 text-sm"
                />
              </label>
            </div>

            {/* Right Col - Settings & Notifications */}
            <div className="space-y-4">
              <div className="glass-card rounded-3xl p-5 space-y-4">
                <div className="flex items-center gap-2 border-b border-white/10 pb-3">
                  <Bell className="h-4 w-4 text-violet-400" />
                  <span className="text-sm font-semibold text-white">System Notification Preferences</span>
                </div>

                <div className="space-y-3.5">
                  <label className="flex items-start gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      disabled={loading}
                      checked={emailAlerts}
                      onChange={(e) => setEmailAlerts(e.target.checked)}
                      className="mt-1 accent-violet-500"
                    />
                    <div>
                      <p className="text-xs font-semibold text-slate-200">Email Scan Reports</p>
                      <p className="text-[10px] text-slate-500">Send an email summary as soon as a PCAP analysis completes.</p>
                    </div>
                  </label>

                  <label className="flex items-start gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      disabled={loading}
                      checked={desktopAlerts}
                      onChange={(e) => setDesktopAlerts(e.target.checked)}
                      className="mt-1 accent-violet-500"
                    />
                    <div>
                      <p className="text-xs font-semibold text-slate-200">Desktop Threat Alerts</p>
                      <p className="text-[10px] text-slate-500">Show native browser notifications when critical malicious traffic is matching rules.</p>
                    </div>
                  </label>

                  <label className="flex items-start gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      disabled={loading}
                      checked={autoCleanup}
                      onChange={(e) => setAutoCleanup(e.target.checked)}
                      className="mt-1 accent-violet-500"
                    />
                    <div>
                      <p className="text-xs font-semibold text-slate-200">Auto-cleanup scans (30 days)</p>
                      <p className="text-[10px] text-slate-500">Automatically delete scans older than 30 days in project workspaces to save database size.</p>
                    </div>
                  </label>
                </div>
              </div>
            </div>
          </div>

          <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-white/10">
            <button
              type="submit"
              disabled={loading}
              className="flex items-center justify-center gap-2 rounded-2xl bg-violet-600 hover:bg-violet-500 px-6 py-3 font-semibold text-white transition disabled:opacity-50 text-sm"
            >
              {loading ? 'Saving adjustments...' : 'Save Adjustments'}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
