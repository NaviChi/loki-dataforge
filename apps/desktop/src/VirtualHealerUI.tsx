import { useState, useEffect, useRef } from 'react';
import { Database, FileCode2 } from 'lucide-react';
import { Card } from './components/ui/card';
import { VirtualContainer } from './lib/api';
import { previewBytes } from './lib/api';

interface VirtualHealerHexProps {
  container: VirtualContainer | null;
  sourceFilePath: string | undefined;
}

export function VirtualHealerHex({ container, sourceFilePath }: VirtualHealerHexProps) {
  const [hexChunks, setHexChunks] = useState<{ offset: number; hex: string }[]>([]);
  const [currentOffset, setCurrentOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  
  const CHUNK_SIZE = 4096; // 4KB chunks for visibility
  const totalAvailableSize = container?.entries?.[0]?.size || 0;
  const entryOffset = container?.entries?.[0]?.offset || 0;

  const loadNextChunk = async (reset = false) => {
    if (!sourceFilePath || !container || container.entries.length === 0) return;
    
    // Safety boundary
    const targetOffset = reset ? 0 : currentOffset;
    if (targetOffset >= totalAvailableSize && !reset) return;
    
    setLoading(true);
    try {
      const actualByteOffset = entryOffset + targetOffset;
      const readSize = Math.min(CHUNK_SIZE, totalAvailableSize - targetOffset);
      const preview = await previewBytes(sourceFilePath, actualByteOffset, readSize);
      
      setHexChunks(prev => reset ? [{ offset: targetOffset, hex: preview }] : [...prev, { offset: targetOffset, hex: preview }]);
      setCurrentOffset(targetOffset + readSize);
    } catch (err) {
      console.error("Failed to fetch chunk", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (container && container.descriptor?.includes('HEALED')) {
      loadNextChunk(true);
    } else {
      setHexChunks([]);
      setCurrentOffset(0);
    }
  }, [container]);

  const handleScroll = () => {
    if (!scrollRef.current || loading) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
    
    // Trigger when within 100px of bottom
    if (scrollHeight - scrollTop - clientHeight < 100) {
      loadNextChunk();
    }
  };

  if (!container || !container.descriptor?.includes('HEALED')) {
    return null; // Only render when actually in Healed state
  }

  return (
    <Card className="animate-fade-up [animation-delay:160ms] aerospace-ui-glass border-rose-500/30">
      <div className="flex items-center gap-2 mb-3">
        <div className="p-1.5 rounded-lg bg-rose-500/20 text-rose-400">
          <Database size={16} />
        </div>
        <h3 className="text-base font-semibold text-rose-100">Virtual Healer: Recovered Partition Blocks</h3>
      </div>
      <p className="mb-3 text-xs text-rose-200/70">{container.descriptor}</p>
      
      <div 
        ref={scrollRef}
        onScroll={handleScroll}
        className="max-h-[300px] overflow-auto rounded-xl border border-rose-900/50 bg-black/60 p-3 font-mono text-[11px] text-rose-300 shadow-inner scroll-smooth"
      >
        {hexChunks.map((chunk, i) => (
          <div key={i} className="mb-2">
            <div className="text-rose-500 mb-1 border-b border-rose-900/30 pb-1">-- Block Offset: 0x{chunk.offset.toString(16).toUpperCase()} --</div>
            <pre className="whitespace-pre-wrap">{chunk.hex}</pre>
          </div>
        ))}
        {loading && <div className="text-center py-2 text-rose-400 animate-pulse">Loading blocks...</div>}
        {!loading && currentOffset >= totalAvailableSize && <div className="text-center py-2 text-white/30">End of Partition Stream</div>}
      </div>
    </Card>
  );
}
