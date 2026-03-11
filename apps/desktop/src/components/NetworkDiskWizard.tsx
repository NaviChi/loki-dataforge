import { useState } from 'react';
import { Network, Server, ArrowRight, ShieldCheck, X } from 'lucide-react';
import { Button } from './ui/button';

interface NetworkDiskWizardProps {
  onClose: () => void;
  onAddPeer: (peerAddress: string, swarmId: string) => void;
}

export function NetworkDiskWizard({ onClose, onAddPeer }: NetworkDiskWizardProps) {
  const [peerAddress, setPeerAddress] = useState('');
  const [swarmId, setSwarmId] = useState('loki-mesh');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-md transition-all duration-300">
      <div className="w-full max-w-lg animate-fade-up aerospace-ui-glass relative overflow-hidden rounded-2xl p-6 shadow-2xl glass-accent-glow border border-emerald-500/20">
        <button onClick={onClose} className="absolute top-4 right-4 text-white/50 hover:text-white transition-colors">
          <X size={20} />
        </button>
        <div className="flex items-center gap-3 mb-6">
          <div className="rounded-full bg-emerald-500/20 p-3 text-emerald-400">
            <Network size={24} />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-white">QuicSwarm Mesh Peer</h2>
            <p className="text-sm text-foreground/70">Securely connect to remote Data Forge agents</p>
          </div>
        </div>

        <div className="space-y-4">
          <label className="block">
            <span className="mb-1 block text-sm text-foreground/80">Peer Address (IP:Port)</span>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-emerald-400/50">
                <Server size={16} />
              </div>
              <input
                type="text"
                value={peerAddress}
                onChange={(e) => setPeerAddress(e.target.value)}
                placeholder="192.168.1.100:4433"
                className="w-full rounded-xl border border-emerald-500/30 bg-black/40 py-3 pl-10 pr-4 text-emerald-100 placeholder:text-emerald-900/50 outline-none focus:border-emerald-400 focus:ring-1 focus:ring-emerald-400/50 transition-all"
              />
            </div>
          </label>

          <label className="block">
            <span className="mb-1 block text-sm text-foreground/80">Swarm ID / PSK Context</span>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-emerald-400/50">
                <ShieldCheck size={16} />
              </div>
              <input
                type="text"
                value={swarmId}
                onChange={(e) => setSwarmId(e.target.value)}
                placeholder="loki-mesh"
                className="w-full rounded-xl border border-border/50 bg-black/40 py-3 pl-10 pr-4 text-white placeholder:text-white/20 outline-none focus:border-white/50 transition-all"
              />
            </div>
          </label>

          <div className="pt-4 flex justify-end gap-3">
            <Button variant="secondary" onClick={onClose} className="hover:bg-white/10">
              Cancel
            </Button>
            <Button 
              className="gap-2 bg-emerald-600 hover:bg-emerald-500 text-white animate-pulse-border shadow-[0_0_15px_rgba(16,185,129,0.5)]"
              disabled={!peerAddress.trim()}
              onClick={() => {
                onAddPeer(peerAddress, swarmId);
                onClose();
              }}
            >
              Connect Peer <ArrowRight size={16} />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
