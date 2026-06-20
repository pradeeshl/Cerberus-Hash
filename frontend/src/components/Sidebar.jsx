import { 
  ShieldAlert, 
  LayoutDashboard, 
  UploadCloud, 
  History, 
  LogOut,
  UserCheck
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, user, onLogout }) {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'upload', label: 'Scan Workspace', icon: UploadCloud },
    { id: 'history', label: 'Scan History', icon: History },
  ];

  return (
    <aside className="w-64 bg-[#0a0f1d] border-r border-[#1e293b] flex flex-col justify-between h-screen sticky top-0">
      <div>
        {/* Brand/Logo Header */}
        <div className="p-6 border-b border-[#1e293b] flex items-center space-x-3">
          <div className="p-2 bg-emerald-500/10 rounded-lg border border-emerald-500/30">
            <ShieldAlert className="h-6 w-6 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white font-['Outfit']">
              CERBERUS<span className="text-emerald-500 font-extrabold">HASH</span>
            </h1>
            <p className="text-[10px] text-gray-500 font-mono tracking-widest uppercase">
              Threat Parser v1.0
            </p>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-4 space-y-1">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id || (item.id === 'history' && activeTab === 'scan-report');
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                  isActive 
                    ? 'bg-emerald-500/15 text-emerald-400 border-l-2 border-emerald-500' 
                    : 'text-gray-400 hover:bg-[#111827] hover:text-gray-200'
                }`}
              >
                <Icon className={`h-4 w-4 ${isActive ? 'text-emerald-400' : 'text-gray-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* User Session Info & Logout */}
      <div className="p-4 border-t border-[#1e293b] space-y-4">
        {user ? (
          <div className="flex items-center space-x-3 px-2">
            <div className="h-9 w-9 bg-slate-800 rounded-full flex items-center justify-center border border-slate-700">
              <UserCheck className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-200 truncate">{user.email}</p>
              <p className="text-xs text-gray-500 font-mono uppercase tracking-wider">{user.role}</p>
            </div>
          </div>
        ) : (
          <div className="px-2">
            <p className="text-xs text-gray-500">Not Authenticated</p>
          </div>
        )}
        
        <button
          onClick={onLogout}
          className="w-full flex items-center space-x-3 px-4 py-2.5 rounded-lg text-sm font-medium text-rose-400 hover:bg-rose-500/10 transition-all"
        >
          <LogOut className="h-4 w-4" />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
}
