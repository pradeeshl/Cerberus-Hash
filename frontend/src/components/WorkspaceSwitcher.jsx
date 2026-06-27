import { useState, useRef, useEffect } from 'react';
import { 
  Folder, 
  Shield, 
  Server, 
  Terminal, 
  HardDrive, 
  Cpu, 
  Database,
  ChevronDown, 
  Plus, 
  Search,
  Check,
  Settings
} from 'lucide-react';

const ICON_MAP = {
  Folder,
  Shield,
  Server,
  Terminal,
  HardDrive,
  Cpu,
  Database
};

const THEME_MAP = {
  violet: 'border-violet-500/30 text-violet-400 bg-violet-500/10',
  cyan: 'border-cyan-500/30 text-cyan-400 bg-cyan-500/10',
  emerald: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10',
  rose: 'border-rose-500/30 text-rose-400 bg-rose-500/10',
  amber: 'border-amber-500/30 text-amber-400 bg-amber-500/10',
  indigo: 'border-indigo-500/30 text-indigo-400 bg-indigo-500/10',
};

export default function WorkspaceSwitcher({ 
  workspaces = [], 
  activeWorkspace = null, 
  onSelectWorkspace, 
  onCreateClick 
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const dropdownRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const ActiveIcon = activeWorkspace ? (ICON_MAP[activeWorkspace.icon] || Folder) : Folder;
  const activeColorTheme = activeWorkspace ? (THEME_MAP[activeWorkspace.color_theme] || THEME_MAP.violet) : THEME_MAP.violet;

  const filteredWorkspaces = workspaces.filter(ws => 
    ws.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
    (ws.description && ws.description.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="relative px-4 py-2 border-b border-[#1e293b]" ref={dropdownRef}>
      <label className="text-[10px] font-mono tracking-widest text-slate-500 uppercase block mb-1.5 px-2">
        Active Environment
      </label>
      
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-xl border border-white/10 bg-slate-950/60 hover:bg-slate-950/90 transition text-left"
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <div className={`p-1.5 rounded-lg border ${activeColorTheme}`}>
            <ActiveIcon className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-white truncate">
              {activeWorkspace ? activeWorkspace.name : 'Select Workspace'}
            </p>
            {activeWorkspace?.labels?.length > 0 && (
              <span className="inline-block mt-0.5 text-[9px] font-medium tracking-wide uppercase px-1.5 py-0.2 bg-white/5 border border-white/10 rounded text-slate-400">
                {activeWorkspace.labels[0]}
              </span>
            )}
          </div>
        </div>
        <ChevronDown className={`h-4 w-4 text-slate-500 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute left-4 right-4 mt-2 z-50 rounded-2xl border border-white/10 bg-slate-950 p-2 shadow-2xl backdrop-blur-xl animate-fade-in">
          {/* Search bar */}
          <div className="relative mb-2">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search workspaces..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-white/10 bg-slate-900/60 text-slate-200 outline-none placeholder:text-slate-500 focus:border-violet-500/50"
            />
          </div>

          {/* List of workspaces */}
          <div className="max-h-56 overflow-y-auto space-y-0.5 pr-1">
            {filteredWorkspaces.map(ws => {
              const WsIcon = ICON_MAP[ws.icon] || Folder;
              const wsColor = THEME_MAP[ws.color_theme] || THEME_MAP.violet;
              const isSelected = activeWorkspace?.id === ws.id;
              
              return (
                <button
                  key={ws.id}
                  onClick={() => {
                    onSelectWorkspace(ws.id);
                    setIsOpen(false);
                  }}
                  className={`w-full flex items-center justify-between gap-2.5 px-3 py-2 rounded-xl text-left transition ${
                    isSelected ? 'bg-white/5' : 'hover:bg-white/5'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className={`p-1.5 rounded-lg border ${wsColor}`}>
                      <WsIcon className="h-3.5 w-3.5" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold text-white truncate">{ws.name}</p>
                      {ws.description && (
                        <p className="text-[10px] text-slate-500 truncate">{ws.description}</p>
                      )}
                    </div>
                  </div>
                  {isSelected && <Check className="h-3.5 w-3.5 text-violet-400 shrink-0" />}
                </button>
              );
            })}

            {filteredWorkspaces.length === 0 && (
              <div className="text-center py-4 text-xs text-slate-500">
                No environments found.
              </div>
            )}
          </div>

          {/* Create Button */}
          <div className="border-t border-white/10 mt-2 pt-2">
            <button
              onClick={() => {
                onCreateClick();
                setIsOpen(false);
              }}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold bg-violet-600 hover:bg-violet-500 text-white transition"
            >
              <Plus className="h-3.5 w-3.5" />
              Create Environment
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
