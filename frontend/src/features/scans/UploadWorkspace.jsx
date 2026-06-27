import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowUpRight, FileUp, UploadCloud, Activity, ShieldAlert, CheckCircle2, Loader2 } from 'lucide-react';
import { scansAPI } from '../../api';

function formatByteSize(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '0 B';
  }

  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatProgressLabel(stageIndex) {
  if (stageIndex === 0) {
    return 'Uploading file...';
  }

  if (stageIndex === 1) {
    return 'Extracting network packets...';
  }

  if (stageIndex === 2) {
    return 'Scanning payload hashes against YARA signatures...';
  }

  return 'Enriching findings via VirusTotal...';
}

export default function UploadWorkspace({ activeWorkspaceId, onUploadComplete }) {
  const inputRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const [currentFile, setCurrentFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [stageIndex, setStageIndex] = useState(0);
  const [isRunning, setIsRunning] = useState(false);
  const [completedScan, setCompletedScan] = useState(null);
  const [error, setError] = useState(null);

  const stageLabel = useMemo(() => formatProgressLabel(stageIndex), [stageIndex]);

  const handleFiles = async (fileList) => {
    const file = fileList?.[0];

    if (!file || isRunning) {
      return;
    }

    const isSupported = file.name.toLowerCase().endsWith('.pcap') || file.name.toLowerCase().endsWith('.pcapng');

    if (!isSupported) {
      setError('Unsupported file type. Please select a .pcap or .pcapng file.');
      return;
    }

    setCurrentFile(file);
    setCompletedScan(null);
    setProgress(0);
    setStageIndex(0);
    setIsRunning(true);
    setError(null);

    try {
      // Stage 0: Uploading (0-40%)
      const scan = await scansAPI.uploadScan(file, activeWorkspaceId, (progressEvent) => {
        const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        setProgress(Math.min(40, Math.round(percentCompleted * 0.4)));
      });

      // Stage 1: Extracting packets (40-60%)
      setStageIndex(1);
      setProgress(50);
      await new Promise((resolve) => setTimeout(resolve, 400));
      setProgress(60);

      // Stage 2: YARA signature scan (60-90%)
      setStageIndex(2);
      setProgress(75);
      await new Promise((resolve) => setTimeout(resolve, 400));
      setProgress(90);

      // Stage 3: VT enrichment (90-100%)
      setStageIndex(3);
      setProgress(95);
      await new Promise((resolve) => setTimeout(resolve, 300));
      setProgress(100);

      await new Promise((resolve) => setTimeout(resolve, 200));
      setIsRunning(false);
      setCompletedScan(scan);
      onUploadComplete?.(scan);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'File upload or analysis failed. Please try again.');
      setIsRunning(false);
      setProgress(0);
      setCurrentFile(null);
    }
  };

  const handleInputChange = (event) => {
    handleFiles(event.target.files);
    event.target.value = '';
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);
    handleFiles(event.dataTransfer.files);
  };

  return (
    <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
      <section className="glass-panel rounded-[2rem] p-6 sm:p-8">
        <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-6">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.3em] text-emerald-300">
              <UploadCloud className="h-3.5 w-3.5" />
              Scan Workspace
            </div>
            <h2 className="mt-4 text-3xl font-semibold text-white">Upload packet capture</h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
              Drop a PCAP or PCAPNG capture to simulate extraction, YARA matching, and enrichment workflows.
            </p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/5 p-3 text-emerald-300">
            <Activity className="h-5 w-5" />
          </div>
        </div>

        {error && (
          <div className="mt-4 rounded-xl border border-rose-500/20 bg-rose-500/10 p-3.5 text-sm text-rose-400">
            {error}
          </div>
        )}

        <div
          onDragOver={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          className={`mt-6 rounded-[1.75rem] border border-dashed p-8 transition sm:p-10 ${isDragging ? 'border-emerald-400 bg-emerald-400/10' : 'border-white/15 bg-slate-950/45'}`}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng"
            onChange={handleInputChange}
            className="hidden"
          />

          <div className="flex flex-col items-center gap-5 text-center">
            <div className="rounded-[1.5rem] border border-emerald-400/15 bg-emerald-400/10 p-5 shadow-lg shadow-emerald-950/20">
              {isRunning ? (
                <Loader2 className="h-10 w-10 animate-spin text-emerald-300" />
              ) : completedScan ? (
                <CheckCircle2 className="h-10 w-10 text-emerald-300" />
              ) : (
                <FileUp className="h-10 w-10 text-emerald-300" />
              )}
            </div>

            <div className="space-y-2">
              <h3 className="text-2xl font-semibold text-white">
                {isRunning ? stageLabel : completedScan ? 'Upload complete' : 'Drag and drop a capture file'}
              </h3>
              <p className="mx-auto max-w-xl text-sm leading-6 text-slate-400">
                {currentFile
                  ? `${currentFile.name} • ${formatByteSize(currentFile.size)}`
                  : 'Supported formats: .pcap and .pcapng'}
              </p>
            </div>

            <div className="w-full max-w-2xl rounded-full border border-white/10 bg-slate-950/60 p-1">
              <div
                className="h-3 rounded-full bg-gradient-to-r from-emerald-500 via-emerald-400 to-emerald-300 transition-all duration-200"
                style={{ width: `${progress}%` }}
              />
            </div>

            <div className="flex flex-wrap items-center justify-center gap-3 text-sm">
              <button
                type="button"
                onClick={() => inputRef.current?.click()}
                className="rounded-full bg-emerald-500 px-5 py-2.5 font-semibold text-slate-950 transition hover:bg-emerald-400"
              >
                Choose file
              </button>
              <span className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-slate-400">
                {progress}% complete
              </span>
            </div>
          </div>
        </div>

        <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[
            ['Uploading file', '0-30%'],
            ['Extracting packets', '30-60%'],
            ['YARA signature scan', '60-90%'],
            ['VirusTotal enrichment', '90-100%'],
          ].map(([label, range]) => (
            <div key={label} className="glass-card rounded-2xl p-4">
              <p className="text-xs uppercase tracking-[0.3em] text-slate-500">{range}</p>
              <p className="mt-2 text-sm font-medium text-white">{label}</p>
            </div>
          ))}
        </div>
      </section>

      <aside className="glass-panel rounded-[2rem] p-6 sm:p-8">
        <div className="flex items-center justify-between border-b border-white/10 pb-5">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Pipeline Summary</p>
            <h3 className="mt-2 text-2xl font-semibold text-white">What happens next</h3>
          </div>
          <ArrowUpRight className="h-5 w-5 text-emerald-300" />
        </div>

        <div className="mt-6 space-y-4">
          {[
            'File is validated and queued for packet extraction.',
            'Payload bytes are compared against cached YARA signatures.',
            'Threat matches are enriched with score and analyst context.',
            'The completed scan is added to history and opened automatically.',
          ].map((item, index) => (
            <div key={item} className="flex gap-4 rounded-2xl border border-white/10 bg-slate-950/50 p-4">
              <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-400/10 text-sm font-semibold text-emerald-300">
                {index + 1}
              </div>
              <p className="text-sm leading-6 text-slate-300">{item}</p>
            </div>
          ))}
        </div>

        <div className="mt-6 rounded-[1.5rem] border border-rose-500/15 bg-rose-500/10 p-5">
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-5 w-5 text-rose-300" />
            <p className="font-semibold text-rose-100">Threat enrichment preview</p>
          </div>
          <p className="mt-3 text-sm leading-6 text-rose-100/80">
            Uploads generate a report-ready packet trail with one highlighted malicious frame so the UI can jump straight into evidence review.
          </p>
        </div>
      </aside>
    </div>
  );
}