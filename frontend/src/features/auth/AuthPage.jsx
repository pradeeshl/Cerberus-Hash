import { useState } from 'react';
import { ArrowRight, Shield, Sparkles } from 'lucide-react';
import { authAPI } from '../../api';

export default function AuthPage({ onLogin }) {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('analyst@cerberus.local');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const isLoginMode = mode === 'login';

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      let data;
      if (isLoginMode) {
        data = await authAPI.login(email, password);
      } else {
        if (password.length < 6) {
          throw new Error('Password must be at least 6 characters long.');
        }
        data = await authAPI.register(email, password, 'analyst');
      }
      localStorage.setItem('token', data.access_token);
      localStorage.setItem('user', JSON.stringify(data.user));
      onLogin(data.user);
    } catch (err) {
      if (err instanceof Error && !err.response) {
        setError(err.message);
      } else {
        const detail = err.response?.data?.detail;
        if (typeof detail === 'string') {
          setError(detail);
        } else if (Array.isArray(detail)) {
          setError(detail.map(d => d.msg || JSON.stringify(d)).join(', '));
        } else {
          setError('Authentication failed. Please check your credentials.');
        }
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#030712] text-slate-100">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(139,92,246,0.18),_transparent_38%),radial-gradient(circle_at_top_right,_rgba(6,182,212,0.14),_transparent_28%),linear-gradient(180deg,_rgba(3,7,18,1),_rgba(3,7,18,0.92))]" />
      <div className="pointer-events-none absolute inset-0 opacity-35 [background-image:linear-gradient(rgba(255,255,255,0.04)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.04)_1px,transparent_1px)] [background-size:64px_64px]" />

      <div className="relative mx-auto flex min-h-screen max-w-7xl items-center px-4 py-10 sm:px-6 lg:px-8">
        <div className="grid w-full gap-8 lg:grid-cols-[1.05fr_0.95fr]">
          <section className="flex flex-col justify-between rounded-[2rem] border border-white/10 bg-slate-950/60 p-8 shadow-2xl shadow-violet-950/20 backdrop-blur-xl sm:p-10">
            <div className="space-y-8">
              <div className="inline-flex items-center gap-3 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.3em] text-emerald-300">
                <Shield className="h-4 w-4" />
                Cerberus Hash
              </div>

              <div className="max-w-2xl space-y-5">
                <h1 className="text-4xl font-semibold tracking-tight text-white sm:text-6xl">
                  Threat intelligence for packet-level hunt operations.
                </h1>
                <p className="max-w-xl text-base leading-7 text-slate-300 sm:text-lg">
                  Authenticate to inspect PCAP evidence, pivot through detections, and move from raw captures to actionable incident context.
                </p>
              </div>

              <div className="grid gap-4 sm:grid-cols-3">
                {[
                  ['YARA cache', 'Warm'],
                  ['Packet pipeline', 'Live'],
                  ['VT enrichment', 'Enabled'],
                ].map(([label, value]) => (
                  <div key={label} className="glass-card rounded-2xl p-4">
                    <p className="text-xs uppercase tracking-[0.28em] text-slate-500">{label}</p>
                    <p className="mt-2 text-lg font-semibold text-white">{value}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-10 grid gap-4 rounded-[1.75rem] border border-emerald-400/15 bg-emerald-400/5 p-5 sm:grid-cols-2">
              <div>
                <p className="text-xs uppercase tracking-[0.32em] text-emerald-300/70">Analyst Console</p>
                <p className="mt-2 text-sm leading-6 text-slate-300">
                  Upload captures, inspect suspicious sessions, and move directly into a packet timeline with forensic context attached.
                </p>
              </div>
              <div className="flex items-start gap-3 rounded-2xl border border-rose-500/20 bg-rose-500/10 p-4">
                <Sparkles className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
                <p className="text-sm text-rose-100/90">
                  Built for a focused cyberpunk workspace with fast switching between login, dashboard, upload, and packet report views.
                </p>
              </div>
            </div>
          </section>

          <section className="flex items-center justify-center">
            <div className="glass-panel w-full max-w-xl rounded-[2rem] p-6 shadow-2xl shadow-black/40 sm:p-8">
              <div className="mb-8 flex items-center justify-between gap-4">
                <div>
                  <p className="text-xs uppercase tracking-[0.35em] text-emerald-300/70">Secure Access</p>
                  <h2 className="mt-2 text-3xl font-semibold text-white">
                    {isLoginMode ? 'Welcome back' : 'Create analyst account'}
                  </h2>
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 p-3">
                  <ArrowRight className="h-5 w-5 text-emerald-400" />
                </div>
              </div>

              <div className="mb-6 grid grid-cols-2 rounded-2xl border border-white/10 bg-slate-950/50 p-1 text-sm font-medium">
                <button
                  type="button"
                  onClick={() => {
                    setMode('login');
                    setError(null);
                  }}
                  className={`rounded-xl px-4 py-3 transition ${isLoginMode ? 'bg-emerald-500/15 text-emerald-300' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  Login
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMode('signup');
                    setError(null);
                  }}
                  className={`rounded-xl px-4 py-3 transition ${!isLoginMode ? 'bg-emerald-500/15 text-emerald-300' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  Sign Up
                </button>
              </div>

              {error && (
                <div className="mb-4 rounded-xl border border-rose-500/20 bg-rose-500/10 p-3.5 text-sm text-rose-400">
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-5">
                <label className="block space-y-2">
                  <span className="text-sm font-medium text-slate-300">Email address</span>
                  <input
                    type="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="analyst@cerberus.local"
                    className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3.5 text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-emerald-400/50 focus:ring-2 focus:ring-emerald-400/20"
                    required
                    disabled={loading}
                  />
                </label>

                <label className="block space-y-2">
                  <span className="text-sm font-medium text-slate-300">Password</span>
                  <input
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="••••••••••"
                    className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3.5 text-slate-100 outline-none transition placeholder:text-slate-500 focus:border-emerald-400/50 focus:ring-2 focus:ring-emerald-400/20"
                    required
                    disabled={loading}
                    minLength={isLoginMode ? undefined : 6}
                  />
                </label>

                <button
                  type="submit"
                  disabled={loading}
                  className="group flex w-full items-center justify-center gap-2 rounded-2xl bg-emerald-500 px-5 py-3.5 font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:opacity-50"
                >
                  {loading ? 'Processing...' : (isLoginMode ? 'Enter workspace' : 'Provision account')}
                  {!loading && <ArrowRight className="h-4 w-4 transition group-hover:translate-x-0.5" />}
                </button>
              </form>

              <p className="mt-6 text-center text-sm text-slate-500">
                Connected to Cerberus Threat Detection backend services.
              </p>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}