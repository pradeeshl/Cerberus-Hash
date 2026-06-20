import { useMemo, useState } from 'react';
import { AlertTriangle, FileText, ShieldAlert, BadgeCheck, Activity } from 'lucide-react';

function hexToBytes(hexValue) {
  const normalized = (hexValue || '').replace(/[^0-9a-fA-F]/g, '');
  const bytes = [];

  for (let index = 0; index < normalized.length; index += 2) {
    const pair = normalized.slice(index, index + 2);
    if (pair.length === 2) {
      bytes.push(Number.parseInt(pair, 16));
    }
  }

  return bytes;
}

function formatHexDump(hexValue) {
  const bytes = hexToBytes(hexValue);

  if (bytes.length === 0) {
    return [];
  }

  const lines = [];

  for (let offset = 0; offset < bytes.length; offset += 16) {
    const slice = bytes.slice(offset, offset + 16);
    const hexPairs = slice.map((byte) => byte.toString(16).padStart(2, '0'));
    const ascii = slice.map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')).join('');

    lines.push({
      offset: offset.toString(16).padStart(8, '0'),
      hex: hexPairs,
      ascii,
    });
  }

  return lines;
}

function getPacketByIndex(packets, packetIndex) {
  return packets.find((packet) => packet.index === packetIndex) ?? packets[0] ?? null;
}

export default function ScanReport({ scan, fallbackPackets = [], fallbackDetections = [] }) {
  const packets = scan?.packets?.length ? scan.packets : fallbackPackets;
  const detections = scan?.detections?.length ? scan.detections : fallbackDetections;
  const [selectedPacketIndex, setSelectedPacketIndex] = useState(packets[0]?.index ?? null);

  const selectedPacket = useMemo(
    () => getPacketByIndex(packets, selectedPacketIndex),
    [packets, selectedPacketIndex],
  );

  const selectedDetection = useMemo(
    () => detections.find((detection) => detection.packetIndex === selectedPacket?.index) ?? detections[0] ?? null,
    [detections, selectedPacket],
  );

  const hexLines = useMemo(
    () => formatHexDump(selectedPacket?.rawPayload || selectedDetection?.rawPayload),
    [selectedPacket, selectedDetection],
  );

  if (!scan) {
    return (
      <div className="glass-panel flex min-h-[28rem] items-center justify-center rounded-[2rem] p-8 text-slate-400">
        No scan is selected.
      </div>
    );
  }

  return (
    <div className="grid min-h-[calc(100vh-3rem)] gap-6 xl:grid-cols-[0.92fr_1.08fr]">
      <section className="glass-panel flex flex-col overflow-hidden rounded-[2rem]">
        <div className="border-b border-white/10 p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.3em] text-emerald-300">
                <FileText className="h-3.5 w-3.5" />
                Packet Timeline
              </div>
              <h2 className="mt-4 text-3xl font-semibold text-white">{scan.filename}</h2>
              <p className="mt-2 text-sm text-slate-400">
                {scan.totalPackets.toLocaleString()} packets inspected, {scan.threatCount} threat hits detected.
              </p>
            </div>
            <div className="rounded-2xl border border-white/10 bg-white/5 p-3 text-emerald-300">
              <Activity className="h-5 w-5" />
            </div>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          <table className="min-w-full divide-y divide-white/8 text-left">
            <thead className="sticky top-0 bg-slate-950/90 text-xs uppercase tracking-[0.28em] text-slate-500 backdrop-blur">
              <tr>
                <th className="px-5 py-4 font-medium">#</th>
                <th className="px-5 py-4 font-medium">Time</th>
                <th className="px-5 py-4 font-medium">Protocol</th>
                <th className="px-5 py-4 font-medium">Source</th>
                <th className="px-5 py-4 font-medium">Destination</th>
                <th className="px-5 py-4 font-medium">Alert</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {packets.map((packet) => {
                const isSelected = packet.index === selectedPacket?.index;

                return (
                  <tr
                    key={packet.index}
                    onClick={() => setSelectedPacketIndex(packet.index)}
                    className={`cursor-pointer transition-colors ${isSelected ? 'bg-emerald-400/10' : 'hover:bg-white/5'}`}
                  >
                    <td className="px-5 py-4 text-sm font-medium text-white">{packet.index}</td>
                    <td className="px-5 py-4 text-sm text-slate-300">{packet.timestamp}</td>
                    <td className="px-5 py-4 text-sm text-slate-300">{packet.protocol}</td>
                    <td className="px-5 py-4 text-sm text-slate-300">{packet.sourceIp}</td>
                    <td className="px-5 py-4 text-sm text-slate-300">{packet.destIp}</td>
                    <td className="px-5 py-4">
                      {packet.isThreat ? <AlertTriangle className="h-4 w-4 text-rose-400" /> : <span className="text-slate-600">-</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="glass-panel flex min-h-0 flex-col overflow-hidden rounded-[2rem]">
        <div className="border-b border-white/10 p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs font-semibold uppercase tracking-[0.3em] text-slate-400">
                <ShieldAlert className="h-3.5 w-3.5" />
                Packet Detail
              </div>
              <h3 className="mt-4 text-3xl font-semibold text-white">
                Packet {selectedPacket?.index ?? '-'}
              </h3>
              <p className="mt-2 text-sm text-slate-400">
                {selectedPacket?.protocol || 'Unknown'} session from {selectedPacket?.sourceIp || '-'} to {selectedPacket?.destIp || '-'}
              </p>
            </div>
            <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/10 p-3 text-emerald-300">
              <BadgeCheck className="h-5 w-5" />
            </div>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-6">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-2xl border border-white/10 bg-slate-950/55 p-5">
              <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Packet Metadata</p>
              <div className="mt-4 space-y-3 text-sm text-slate-300">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-500">Length</span>
                  <span className="font-medium text-white">{selectedPacket?.length ?? '-'} bytes</span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-500">Protocol</span>
                  <span className="font-medium text-white">{selectedPacket?.protocol ?? '-'}</span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-500">Timestamp</span>
                  <span className="font-medium text-white">{selectedPacket?.timestamp ?? '-'}</span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-500">Threat Flagged</span>
                  <span className={`font-medium ${selectedPacket?.isThreat ? 'text-rose-300' : 'text-emerald-300'}`}>
                    {selectedPacket?.isThreat ? 'Yes' : 'No'}
                  </span>
                </div>
              </div>
            </div>

            <div className="rounded-2xl border border-white/10 bg-slate-950/55 p-5">
              <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Threat Intelligence</p>
              {selectedPacket?.isThreat && selectedDetection ? (
                <div className="mt-4 space-y-4">
                  <div>
                    <p className="text-lg font-semibold text-white">{selectedDetection.ruleName}</p>
                    <p className="mt-2 text-sm leading-6 text-slate-300">{selectedDetection.description}</p>
                    <p className="mt-3 text-xs uppercase tracking-[0.28em] text-slate-500">Author</p>
                    <p className="mt-1 text-sm text-slate-200">{selectedDetection.author}</p>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {selectedDetection.tags?.map((tag) => (
                      <span key={tag} className="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1 text-xs font-medium text-emerald-300">
                        {tag}
                      </span>
                    ))}
                  </div>

                  <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3">
                    <p className="text-xs uppercase tracking-[0.28em] text-rose-200/70">VirusTotal Score</p>
                    <p className="mt-2 text-2xl font-semibold text-rose-100">
                      {selectedDetection.vtPositives} / {selectedDetection.vtTotal} detections
                    </p>
                  </div>
                </div>
              ) : (
                <div className="mt-4 rounded-2xl border border-emerald-400/15 bg-emerald-400/10 p-4 text-sm leading-6 text-slate-300">
                  No malicious signature matched for the selected packet. The payload is considered benign by the current mock workflow.
                </div>
              )}
            </div>
          </div>

          <div className="mt-6 rounded-[1.75rem] border border-white/10 bg-slate-950/70 p-5">
            <div className="flex items-center justify-between gap-4 border-b border-white/10 pb-4">
              <div>
                <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Hex Dump Viewer</p>
                <h4 className="mt-2 text-xl font-semibold text-white">Payload bytes and ASCII</h4>
              </div>
              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs uppercase tracking-[0.28em] text-slate-400">
                Monospaced
              </span>
            </div>

            <div className="mt-4 overflow-x-auto rounded-2xl border border-white/10 bg-black/40 p-4">
              {hexLines.length > 0 ? (
                <pre className="hex-dump-editor m-0 text-slate-200">
                  {hexLines.map((line) => (
                    <div key={line.offset} className="grid grid-cols-[7.5rem_minmax(0,1fr)_auto] gap-4 py-1">
                      <span className="text-slate-500">{line.offset}</span>
                      <span className="tracking-[0.08em] text-emerald-200">
                        {line.hex.map((byte, index) => (
                          <span key={`${line.offset}-${index}`} className="inline-block w-7">
                            {byte}
                          </span>
                        ))}
                      </span>
                      <span className="text-slate-400">{line.ascii}</span>
                    </div>
                  ))}
                </pre>
              ) : (
                <div className="rounded-2xl border border-dashed border-white/10 p-8 text-center text-sm text-slate-500">
                  No raw payload bytes are available for this packet.
                </div>
              )}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}