import { ChevronRight, ShieldAlert, Activity, CircleCheckBig, TriangleAlert } from 'lucide-react';

function formatDate(value) {
  if (!value) {
    return 'Unknown';
  }

  return value;
}

function getStatusClasses(status) {
  if (status === 'failed') {
    return 'border-rose-500/20 bg-rose-500/10 text-rose-300';
  }

  if (status === 'scanning') {
    return 'border-amber-500/20 bg-amber-500/10 text-amber-300';
  }

  return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300';
}

export default function Dashboard({ scans = [], onOpenScan, title = 'Operational Dashboard' }) {
  const totalThreats = scans.reduce((total, scan) => total + Number(scan.threatCount || 0), 0);
  const systemHealth = 100;
  const orderedScans = [...scans].sort((left, right) => right.startedAt.localeCompare(left.startedAt));

  const metrics = [
    {
      label: 'Total Scans Analyzed',
      value: scans.length,
      icon: CircleCheckBig,
      accent: 'text-emerald-300',
    },
    {
      label: 'Threats Flagged',
      value: totalThreats,
      icon: TriangleAlert,
      accent: 'text-rose-300',
    },
    {
      label: 'System Health',
      value: `${systemHealth}%`,
      icon: Activity,
      accent: 'text-cyan-300',
    },
  ];

  return (
    <div className="space-y-6">
      <section className="glass-panel rounded-[2rem] p-6 sm:p-8">
        <div className="flex flex-col gap-4 border-b border-white/10 pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl space-y-3">
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.3em] text-emerald-300">
              <ShieldAlert className="h-3.5 w-3.5" />
              Mission Control
            </div>
            <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">{title}</h1>
            <p className="max-w-3xl text-sm leading-6 text-slate-400 sm:text-base">
              Review recent captures, inspect flagged sessions, and pivot into packet evidence without leaving the analyst console.
            </p>
          </div>
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {metrics.map((metric) => {
            const Icon = metric.icon;

            return (
              <article key={metric.label} className="glass-card rounded-3xl p-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-xs uppercase tracking-[0.28em] text-slate-500">{metric.label}</p>
                    <p className={`mt-3 text-3xl font-semibold ${metric.accent}`}>{metric.value}</p>
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-white/5 p-3">
                    <Icon className={`h-5 w-5 ${metric.accent}`} />
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      </section>

      <section className="glass-panel overflow-hidden rounded-[2rem]">
        <div className="flex items-center justify-between border-b border-white/10 px-6 py-4">
          <div>
            <h2 className="text-lg font-semibold text-white">Recent Scans</h2>
            <p className="text-sm text-slate-400">Click any row to open the detailed packet report.</p>
          </div>
          <div className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs uppercase tracking-[0.3em] text-slate-400">
            Live inventory
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-white/10">
            <thead className="bg-slate-950/40 text-left text-xs uppercase tracking-[0.28em] text-slate-500">
              <tr>
                <th className="px-6 py-4 font-medium">Filename</th>
                <th className="px-6 py-4 font-medium">Packets</th>
                <th className="px-6 py-4 font-medium">Threats</th>
                <th className="px-6 py-4 font-medium">Started</th>
                <th className="px-6 py-4 font-medium">Completed</th>
                <th className="px-6 py-4 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {orderedScans.map((scan) => (
                <tr
                  key={scan.id}
                  onClick={() => onOpenScan?.(scan.id)}
                  className="cursor-pointer transition-colors hover:bg-white/5"
                >
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="rounded-2xl border border-emerald-400/15 bg-emerald-400/10 p-2">
                        <ShieldAlert className="h-4 w-4 text-emerald-300" />
                      </div>
                      <div>
                        <p className="font-medium text-white">{scan.filename}</p>
                        <p className="text-sm text-slate-500">{scan.fileSize}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-300">{scan.totalPackets.toLocaleString()}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">{scan.threatCount}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">{formatDate(scan.startedAt)}</td>
                  <td className="px-6 py-4 text-sm text-slate-300">{formatDate(scan.completedAt)}</td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.22em] ${getStatusClasses(scan.status)}`}>
                      {scan.status === 'completed' && <CircleCheckBig className="h-3.5 w-3.5" />}
                      {scan.status === 'scanning' && <Activity className="h-3.5 w-3.5" />}
                      {scan.status === 'failed' && <TriangleAlert className="h-3.5 w-3.5" />}
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <span className="inline-flex items-center gap-1 text-sm font-medium text-emerald-300">
                      Open report <ChevronRight className="h-4 w-4" />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}