import { useState } from 'react';
import { 
  Folder, 
  Shield, 
  Server, 
  Terminal, 
  HardDrive, 
  Cpu, 
  Database,
  X 
} from 'lucide-react';

const ICONS = [
  { name: 'Folder', component: Folder },
  { name: 'Shield', component: Shield },
  { name: 'Server', component: Server },
  { name: 'Terminal', component: Terminal },
  { name: 'HardDrive', component: HardDrive },
  { name: 'Cpu', component: Cpu },
  { name: 'Database', component: Database },
];

const THEMES = [
  { name: 'violet', bg: 'bg-violet-500', border: 'border-violet-500' },
  { name: 'cyan', bg: 'bg-cyan-500', border: 'border-cyan-500' },
  { name: 'emerald', bg: 'bg-emerald-500', border: 'border-emerald-500' },
  { name: 'rose', bg: 'bg-rose-500', border: 'border-rose-500' },
  { name: 'amber', bg: 'bg-amber-500', border: 'border-amber-500' },
  { name: 'indigo', bg: 'bg-indigo-500', border: 'border-indigo-500' },
];

export default function WorkspaceModal({ isOpen, onClose, onCreate }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [colorTheme, setColorTheme] = useState('violet');
  const [icon, setIcon] = useState('Folder');
  const [labelsInput, setLabelsInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;

    setError(null);
    setLoading(true);

    const labels = labelsInput
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0);

    try {
      await onCreate({
        name,
        description,
        color_theme: colorTheme,
        icon,
        labels
      });
      setName('');
      setDescription('');
      setColorTheme('violet');
      setIcon('Folder');
      setLabelsInput('');
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create workspace.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="glass-panel w-full max-w-lg rounded-[2.5rem] border border-white/10 p-6 shadow-2xl relative animate-fade-in">
        <button 
          onClick={onClose}
          className="absolute top-6 right-6 p-2 rounded-xl hover:bg-white/5 text-slate-400 hover:text-white transition"
        >
          <X className="h-5 w-5" />
        </button>

        <div className="mb-6">
          <p className="text-xs uppercase tracking-[0.3em] text-violet-400">Environment Setup</p>
          <h2 className="text-2xl font-semibold text-white mt-1">New Workspace</h2>
        </div>

        {error && (
          <div className="mb-4 rounded-xl border border-rose-500/20 bg-rose-500/10 p-3.5 text-xs text-rose-400">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Workspace Name</span>
            <input
              type="text"
              required
              disabled={loading}
              placeholder="e.g. Incident Response Alpha"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100 outline-none placeholder:text-slate-600 focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/50 transition text-sm"
            />
          </label>

          <label className="block space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Description (Optional)</span>
            <textarea
              disabled={loading}
              placeholder="Brief summary of this environment's scope"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows="2"
              className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100 outline-none placeholder:text-slate-600 focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/50 transition text-sm resize-none"
            />
          </label>

          {/* Icon Picker */}
          <div className="space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">Workspace Icon</span>
            <div className="flex flex-wrap gap-2">
              {ICONS.map(ic => {
                const WsIcon = ic.component;
                const isSelected = icon === ic.name;
                return (
                  <button
                    key={ic.name}
                    type="button"
                    onClick={() => setIcon(ic.name)}
                    className={`p-3 rounded-xl border transition ${
                      isSelected 
                        ? 'border-violet-500 bg-violet-500/10 text-violet-400' 
                        : 'border-white/10 bg-slate-950/40 text-slate-400 hover:border-white/20'
                    }`}
                  >
                    <WsIcon className="h-4 w-4" />
                  </button>
                );
              })}
            </div>
          </div>

          {/* Color Picker */}
          <div className="space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">Accent Vibe</span>
            <div className="flex gap-2.5">
              {THEMES.map(th => {
                const isSelected = colorTheme === th.name;
                return (
                  <button
                    key={th.name}
                    type="button"
                    onClick={() => setColorTheme(th.name)}
                    className={`h-7 w-7 rounded-full transition flex items-center justify-center ${th.bg} ${
                      isSelected ? 'ring-2 ring-white ring-offset-2 ring-offset-slate-950' : 'opacity-60 hover:opacity-100'
                    }`}
                  />
                );
              })}
            </div>
          </div>

          <label className="block space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Labels (Comma-separated)</span>
            <input
              type="text"
              disabled={loading}
              placeholder="e.g. Incident Response, Client Alpha, Research"
              value={labelsInput}
              onChange={(e) => setLabelsInput(e.target.value)}
              className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3 text-slate-100 outline-none placeholder:text-slate-600 focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/50 transition text-sm"
            />
          </label>

          <button
            type="submit"
            disabled={loading || !name.trim()}
            className="w-full flex items-center justify-center gap-2 rounded-2xl bg-violet-600 hover:bg-violet-500 px-5 py-3.5 font-semibold text-white transition disabled:opacity-50 mt-4 text-sm"
          >
            {loading ? 'Initializing environment...' : 'Provision Environment'}
          </button>
        </form>
      </div>
    </div>
  );
}
