import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowUpRight, FileUp, UploadCloud, Activity, ShieldAlert, CheckCircle2, Loader2 } from 'lucide-react';

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

function createThreatProfile(fileName) {
  const loweredName = fileName.toLowerCase();

  if (loweredName.includes('tor')) {
    return {
      packetIndex: 294,
      protocol: 'TLS',
      destIp: '185.165.191.122',
      info: 'Client Hello with Tor bridge negotiation markers',
      ruleName: 'Detect_Tor_Directory_Authority_Request',
      description: 'Detects attempts to bootstrap anonymous routing sessions by contacting directory infrastructure.',
      tags: ['tor', 'anon', 'recon'],
      vtPositives: 4,
      vtTotal: 71,
      rawPayload: '16030100800100007c030357732a5a2680fbeb60e6530ffd79c4966601b1fd4f826521377737a37e8643be4fe49a74bc2668c1f68e756b14258aaed0820a97f193d6d158508f53ec000016002f00350005000a00c00900c01300c01400c00a',
    };
  }

  if (loweredName.includes('smb') || loweredName.includes('blue')) {
    return {
      packetIndex: 911,
      protocol: 'SMB',
      destIp: '10.0.0.25',
      info: 'SMBv1 negotiate request carrying exploit shellcode markers',
      ruleName: 'Detect_EternalBlue_SMB_Payload',
      description: 'Detects the characteristic SMB shellcode buffer pattern associated with EternalBlue exploitation.',
      tags: ['exploit', 'smb', 'eternalblue', 'ms17-010'],
      vtPositives: 64,
      vtTotal: 73,
      rawPayload: '00000085ff534d4272000000001807c8000000000000000000000000000005ff00000000000100ff02001400080001000000000001000000ffff00005400000044b1b326fa901873281772d00ac729285041594c4f4144',
    };
  }

  return {
    packetIndex: 148,
    protocol: 'HTTP',
    destIp: '84.200.69.80',
    info: 'HTTP beacon with ransom payload fingerprint',
    ruleName: 'Detect_WannaCry_Ransomware_Beacon',
    description: 'Detects the outbound command-and-control handshake hash associated with WannaCry ransomware.',
    tags: ['ransomware', 'wannacry', 'c2'],
    vtPositives: 58,
    vtTotal: 72,
    rawPayload: '474554202f6d756d626c656675636b736765677564676f7267686568666e6578742e6f726720485454502f312e310d0a486f73743a207777772e697571657266736f6470706d7067686a6c61777766736f756665727766636f6d2e636f6d0d0a0d0a',
  };
}

function buildUploadedScan(file) {
  const scanId = `scan-${Date.now()}`;
  const profile = createThreatProfile(file.name);
  const now = new Date();
  const later = new Date(now.getTime() + 11000);

  const packets = [
    {
      index: 1,
      timestamp: '11:02:14.006',
      sourceIp: '192.168.1.105',
      destIp: '192.168.1.1',
      protocol: 'DNS',
      length: 74,
      info: 'Standard query 0x31f4 A update.service.local',
      isThreat: false,
    },
    {
      index: 2,
      timestamp: '11:02:14.221',
      sourceIp: '192.168.1.105',
      destIp: profile.destIp,
      protocol: profile.protocol,
      length: 188,
      info: profile.info,
      isThreat: true,
      rawPayload: profile.rawPayload,
    },
    {
      index: 3,
      timestamp: '11:02:14.594',
      sourceIp: '192.168.1.105',
      destIp: '172.16.20.10',
      protocol: 'TLS',
      length: 312,
      info: 'Client Hello with uncommon ciphersuite ordering',
      isThreat: false,
    },
    {
      index: 4,
      timestamp: '11:02:15.044',
      sourceIp: '192.168.1.105',
      destIp: '10.0.0.25',
      protocol: 'SMB',
      length: 152,
      info: 'Negotiate Protocol Request',
      isThreat: profile.protocol === 'SMB',
      rawPayload: profile.protocol === 'SMB' ? profile.rawPayload : undefined,
    },
  ];

  return {
    id: scanId,
    filename: file.name,
    fileSize: formatByteSize(file.size),
    totalPackets: packets.length,
    status: 'completed',
    startedAt: now.toISOString().slice(0, 19).replace('T', ' '),
    completedAt: later.toISOString().slice(0, 19).replace('T', ' '),
    threatCount: packets.filter((packet) => packet.isThreat).length,
    packets,
    detections: [
      {
        id: `${scanId}-det-1`,
        packetIndex: profile.packetIndex,
        md5Hash: 'generated-upload-scan-hash',
        ruleName: profile.ruleName,
        description: profile.description,
        author: 'PRADEESH L',
        tags: profile.tags,
        severity: profile.vtPositives > 30 ? 'high' : 'medium',
        vtPositives: profile.vtPositives,
        vtTotal: profile.vtTotal,
        rawPayload: profile.rawPayload,
      },
    ],
  };
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

export default function UploadWorkspace({ onUploadComplete }) {
  const inputRef = useRef(null);
  const intervalRef = useRef(null);
  const timeoutRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const [currentFile, setCurrentFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [stageIndex, setStageIndex] = useState(0);
  const [isRunning, setIsRunning] = useState(false);
  const [completedScan, setCompletedScan] = useState(null);

  const stageLabel = useMemo(() => formatProgressLabel(stageIndex), [stageIndex]);

  useEffect(() => () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
    }

    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
  }, []);

  const clearTimers = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  };

  const handleFiles = (fileList) => {
    const file = fileList?.[0];

    if (!file || isRunning) {
      return;
    }

    const isSupported = file.name.toLowerCase().endsWith('.pcap') || file.name.toLowerCase().endsWith('.pcapng');

    if (!isSupported) {
      return;
    }

    clearTimers();
    setCurrentFile(file);
    setCompletedScan(null);
    setProgress(0);
    setStageIndex(0);
    setIsRunning(true);

    const targets = [30, 60, 90, 100];
    let stageCursor = 0;

    intervalRef.current = window.setInterval(() => {
      setProgress((currentProgress) => {
        const target = targets[stageCursor];
        const nextProgress = Math.min(currentProgress + 2, target);

        if (nextProgress >= target && stageCursor < targets.length - 1) {
          stageCursor += 1;
          setStageIndex(stageCursor);
        }

        if (nextProgress >= 100) {
          clearTimers();
          setIsRunning(false);
          timeoutRef.current = window.setTimeout(() => {
            const scan = buildUploadedScan(file);
            setCompletedScan(scan);
            onUploadComplete?.(scan);
          }, 350);
        }

        return nextProgress;
      });
    }, 55);
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