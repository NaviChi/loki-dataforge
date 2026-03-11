import { Server, Activity, ArrowRightLeft, Cpu, Network, Zap } from 'lucide-react';
import { Card } from './ui/card';
import { useEffect, useState } from 'react';
import { getExtractionDiagnostics, type ExtractionDiagnostics } from '../lib/api';

export interface Peer {
  address: string;
  swarmId: string;
  status: 'Connected' | 'Error' | 'Connecting';
  latency?: number;
}

export function QuicSwarmDashboard({ peers }: { peers: Peer[] }) {
  const [diagnosticsMap, setDiagnosticsMap] = useState<Record<string, ExtractionDiagnostics>>({});

  useEffect(() => {
    if (peers.length === 0) return;

    const interval = setInterval(() => {
      peers.forEach(async (peer) => {
        if (peer.status === 'Connected') {
          try {
            const diag = await getExtractionDiagnostics(peer.swarmId);
            setDiagnosticsMap((prev) => ({ ...prev, [peer.swarmId]: diag }));
          } catch (e) {
            console.error('Failed to get diagnostics for peer', peer.swarmId, e);
          }
        }
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [peers]);

  if (peers.length === 0) return null;

  return (
    <Card className="animate-fade-up aerospace-ui-glass mt-4 z-10 w-full relative overflow-hidden ring-1 ring-emerald-500/20">
      <div className="mb-3 flex items-center justify-between z-10 relative">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Activity size={18} className="text-emerald-400" />
          QuicSwarm Mesh Fleet
        </h2>
        <span className="text-xs text-emerald-400/70 font-medium tracking-widest">{peers.length} ACTIVE NODES</span>
      </div>
      <div className="space-y-2 z-10 relative">
        {peers.map((peer, i) => {
          const diag = diagnosticsMap[peer.swarmId];
          const hasMetrics = !!diag;

          return (
            <div key={i} className="flex flex-col p-3 rounded-lg bg-black/40 border border-emerald-500/10 shadow-inner group">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Server size={18} className={peer.status === 'Connected' ? 'text-emerald-400' : 'text-amber-400 animate-pulse'} />
                  <div>
                    <p className="text-sm font-semibold text-emerald-50 shadow-sm">{peer.address}</p>
                    <p className="text-xs text-foreground/50 font-mono tracking-tight mt-0.5">PSK: {peer.swarmId}</p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="flex flex-col items-end">
                    <span className="text-xs text-emerald-300 flex items-center gap-1 font-mono">
                      <ArrowRightLeft size={12} className="opacity-70" />
                      {diag?.average_latency_ms ? `${diag.average_latency_ms.toFixed(2)}ms` : (peer.latency ? `${peer.latency}ms` : '---')}
                    </span>
                    <span className={`text-[10px] font-bold uppercase tracking-wider mt-1 ${peer.status === 'Connected' ? 'text-emerald-500/80 shadow-[0_0_10px_rgba(16,185,129,0.2)]' : 'text-amber-500/80 shadow-[0_0_10px_rgba(245,158,11,0.2)]'}`}>
                      {peer.status}
                    </span>
                  </div>
                </div>
              </div>
              
              {hasMetrics && peer.status === 'Connected' && (
                <div className="mt-3 grid grid-cols-3 gap-2 border-t border-emerald-500/10 pt-3">
                  <div className="flex flex-col">
                    <span className="text-[10px] font-semibold text-emerald-500/70 tracking-widest uppercase flex items-center gap-1">
                      <Network size={10} /> MPQUIC Links
                    </span>
                    <span className="font-mono text-xs text-emerald-100">{diag.active_multipath_links} Active</span>
                  </div>
                  <div className="flex flex-col">
                    <span className="text-[10px] font-semibold text-emerald-500/70 tracking-widest uppercase flex items-center gap-1">
                      <Zap size={10} /> Zero-Copy TX
                    </span>
                    <span className={`font-mono text-xs ${diag.af_xdp_zero_copy_active ? 'text-emerald-300' : 'text-amber-300/80'}`}>
                      {diag.af_xdp_zero_copy_active ? 'AF_XDP (Line-Rate)' : 'Fallback (Kernel)'}
                    </span>
                  </div>
                  <div className="flex flex-col">
                    <span className="text-[10px] font-semibold text-emerald-500/70 tracking-widest uppercase flex items-center gap-1">
                      <Cpu size={10} /> WGPU Markov
                    </span>
                    <span className={`font-mono text-xs ${diag.wgpu_markov_active ? 'text-emerald-300' : 'text-amber-300/80'}`}>
                      {diag.wgpu_markov_active ? 'Offloaded (GPU)' : 'CPU Degrading'}
                    </span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </Card>
  );
}
