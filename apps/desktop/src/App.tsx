import { useEffect, useMemo, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { HardDriveDownload, Search, Shield, Sparkles } from 'lucide-react';
import { Button } from './components/ui/button';
import { Card } from './components/ui/card';
import { Tabs } from './components/ui/tabs';
import { InputSelector } from './components/InputSelector';
import {
  mountContainer,
  previewBytes,
  recoverFromLast,
  runScan,
  type FoundFile,
  type RaidDetectionReport,
  type ScanProgress,
  type ScanReport,
  type VirtualContainer,
} from './lib/api';

function isTauriRuntime(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }
  const runtimeWindow = window as Window & {
    __TAURI_INTERNALS__?: unknown;
    isTauri?: boolean;
  };
  return Boolean(runtimeWindow.__TAURI_INTERNALS__) || Boolean(runtimeWindow.isTauri);
}

function errorMessage(error: unknown): string {
  if (typeof error === 'string') {
    return error;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return JSON.stringify(error);
}

export function App() {
  const [theme, setTheme] = useState<'light' | 'dark'>('dark');
  const [inputSources, setInputSources] = useState<string[]>([]);
  const [output, setOutput] = useState('');
  const [raidDetection, setRaidDetection] = useState<RaidDetectionReport | null>(null);
  const [degradedMode, setDegradedMode] = useState(false);
  const [mode, setMode] = useState<'quick' | 'deep' | 'hybrid'>('hybrid');
  const [threads, setThreads] = useState(
    Math.max(1, Math.min((navigator.hardwareConcurrency ?? 8), 64)),
  );
  const [chunkSize, setChunkSize] = useState(8 * 1024 * 1024);
  const [maxCarveSize, setMaxCarveSize] = useState(16 * 1024 * 1024);
  const [synologyMode, setSynologyMode] = useState(false);
  const [includeContainers, setIncludeContainers] = useState(true);
  const [strictContainers, setStrictContainers] = useState(false);
  const [signatureProfile, setSignatureProfile] = useState<'strict' | 'broad'>('strict');
  const [adapterPolicy, setAdapterPolicy] = useState<
    'native-only' | 'hybrid' | 'external-preferred'
  >('hybrid');
  const [unlockProvider, setUnlockProvider] = useState('');
  const [enableBypass, setEnableBypass] = useState(false);
  const [caseId, setCaseId] = useState('');
  const [legalAuthority, setLegalAuthority] = useState('');

  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [container, setContainer] = useState<VirtualContainer | null>(null);
  const [hexPreview, setHexPreview] = useState('');
  const [activeTab, setActiveTab] = useState<'wizard' | 'advanced'>('wizard');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState('Ready. Read-only mode is enabled by default.');

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
  }, [theme]);

  useEffect(() => {
    if (!isTauriRuntime()) {
      return;
    }
    let canceled = false;
    let cleanup: (() => void) | null = null;
    void listen<ScanProgress>('scan-progress', (event) => {
      setProgress(event.payload);
    })
      .then((unlisten) => {
        if (canceled) {
          void unlisten();
          return;
        }
        cleanup = unlisten;
      })
      .catch(() => {});
    return () => {
      canceled = true;
      if (cleanup) {
        void cleanup();
      }
    };
  }, []);

  useEffect(() => {
    if (!isTauriRuntime()) {
      return;
    }
    let canceled = false;
    let cleanup: (() => void) | null = null;
    void listen<RaidDetectionReport>('raid-detection', (event) => {
      setRaidDetection(event.payload);
    })
      .then((unlisten) => {
        if (canceled) {
          void unlisten();
          return;
        }
        cleanup = unlisten;
      })
      .catch(() => {});
    return () => {
      canceled = true;
      if (cleanup) {
        void cleanup();
      }
    };
  }, []);

  const findings = report?.findings ?? [];
  const selected = useMemo(
    () => findings.find((f) => f.id === selectedId) ?? null,
    [findings, selectedId],
  );

  async function handleScan() {
    if (inputSources.length === 0) {
      setStatus('Set a source drive/image path first.');
      return;
    }

    setBusy(true);
    setStatus('Scanning in progress...');
    setReport(null);
    setContainer(null);
    setSelectedId(null);
    setHexPreview('');

    try {
      const scanReport = await runScan({
        source: inputSources[0],
        sources: inputSources,
        mode,
        threads: Math.max(1, Math.floor(threads)),
        chunk_size: Math.max(4096, Math.floor(chunkSize)),
        max_carve_size: Math.max(4096, Math.floor(maxCarveSize)),
        synology_mode: synologyMode,
        include_container_scan: includeContainers,
        degraded_mode: degradedMode,
        strict_containers: strictContainers,
        signature_profile: signatureProfile,
        adapter_policy: adapterPolicy,
        encryption_detect_only: unlockProvider.trim().length === 0,
        unlock_with: unlockProvider.trim() ? unlockProvider.trim() : undefined,
        enable_bypass: enableBypass,
        case_id: caseId.trim() ? caseId.trim() : undefined,
        legal_authority: legalAuthority.trim() ? legalAuthority.trim() : undefined,
      });

      const mounted = includeContainers
        ? await mountContainer(scanReport.source).catch(() => null)
        : null;

      setReport(scanReport);
      setContainer(mounted);
      setStatus(
        `Scan complete: ${scanReport.findings.length} findings${
          raidDetection ? ` | RAID ${raidDetection.detected_members}/${raidDetection.expected_members}` : ''
        }`,
      );
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  async function handlePreview(item: FoundFile) {
    try {
      const previewSource = item.source_path || inputSources[0];
      if (!previewSource) {
        setHexPreview('No source selected.');
        return;
      }
      const preview = await previewBytes(previewSource, item.offset, Math.min(item.size, 512));
      setHexPreview(preview);
      setSelectedId(item.id);
    } catch (error) {
      setHexPreview(errorMessage(error));
    }
  }

  async function handleRecover() {
    if (!output || inputSources.length === 0) {
      setStatus('Set both source and output paths before recovery.');
      return;
    }

    try {
      setBusy(true);
      const recovered = await recoverFromLast({
        source: report?.source || inputSources[0],
        destination: output,
        overwrite: false,
      });
      setStatus(`Recovered ${recovered.length} files to ${output}`);
    } catch (error) {
      setStatus(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#08111d] via-[#0f2230] to-[#1f3142] text-foreground transition-colors dark:from-[#08111d] dark:via-[#0f2230] dark:to-[#1f3142]">
      <div className="mx-auto flex max-w-[1600px] flex-col gap-4 p-4 lg:p-6">
        <header className="grid gap-3 rounded-2xl border border-border/70 bg-black/20 p-4 backdrop-blur-sm md:grid-cols-[1fr_auto] md:items-center">
          <div className="space-y-1">
            <p className="text-xs uppercase tracking-[0.2em] text-foreground/70">Loki Data Forge</p>
            <h1 className="text-2xl font-semibold">Forensic Data Recovery Orchestrator</h1>
            <p className="text-sm text-foreground/70">Quick MFT/inode triage, deep carving, virtual-disk/container inspection, and safe recoveries.</p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="secondary" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
              {theme === 'dark' ? 'Light' : 'Dark'} theme
            </Button>
            <div className="rounded-xl border border-emerald-400/40 bg-emerald-500/20 px-3 py-1 text-xs font-semibold text-emerald-100">
              Read-only Default
            </div>
          </div>
        </header>

        <section className="grid gap-4 lg:grid-cols-[430px_1fr]">
          <Card className="space-y-4 animate-fade-up">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Scan Console</h2>
              <Tabs
                value={activeTab}
                onChange={(value) => setActiveTab(value as 'wizard' | 'advanced')}
                options={[
                  { id: 'wizard', label: 'Wizard' },
                  { id: 'advanced', label: 'Advanced' },
                ]}
              />
            </div>

            {activeTab === 'wizard' ? (
              <div className="space-y-3">
                <InputSelector
                  inputPaths={inputSources}
                  outputPath={output}
                  disabled={busy}
                  onInputPathsChange={setInputSources}
                  onOutputPathChange={setOutput}
                  onRaidUpdate={(report, degraded) => {
                    setRaidDetection(report);
                    setDegradedMode(degraded);
                  }}
                  onStatus={setStatus}
                />

                <div className="grid grid-cols-3 gap-2">
                  <Button variant={mode === 'quick' ? 'default' : 'secondary'} onClick={() => setMode('quick')}>Quick</Button>
                  <Button variant={mode === 'deep' ? 'default' : 'secondary'} onClick={() => setMode('deep')}>Deep</Button>
                  <Button variant={mode === 'hybrid' ? 'default' : 'secondary'} onClick={() => setMode('hybrid')}>Hybrid</Button>
                </div>
              </div>
            ) : (
              <div className="space-y-3 text-sm">
                <label className="block">
                  <span className="mb-1 block text-foreground/80">Threads</span>
                  <input
                    type="number"
                    value={threads}
                    min={1}
                    onChange={(e) => setThreads(Math.max(1, Number(e.target.value) || 1))}
                    className="w-full rounded-xl border border-border bg-black/20 px-3 py-2 outline-none"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-foreground/80">Chunk size (bytes)</span>
                  <input
                    type="number"
                    value={chunkSize}
                    min={4096}
                    onChange={(e) => setChunkSize(Math.max(4096, Number(e.target.value) || 4096))}
                    className="w-full rounded-xl border border-border bg-black/20 px-3 py-2 outline-none"
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-foreground/80">Max carve size (bytes)</span>
                  <input
                    type="number"
                    value={maxCarveSize}
                    min={4096}
                    onChange={(e) => setMaxCarveSize(Math.max(4096, Number(e.target.value) || 4096))}
                    className="w-full rounded-xl border border-border bg-black/20 px-3 py-2 outline-none"
                  />
                </label>

                <label className="flex items-center gap-2 text-foreground/80">
                  <input type="checkbox" checked={synologyMode} onChange={(e) => setSynologyMode(e.target.checked)} />
                  Synology special mode (SHR/rkey hints)
                </label>
                <label className="flex items-center gap-2 text-foreground/80">
                  <input type="checkbox" checked={includeContainers} onChange={(e) => setIncludeContainers(e.target.checked)} />
                  Include VM/backup container scan
                </label>
                <label className="flex items-center gap-2 text-foreground/80">
                  <input type="checkbox" checked={strictContainers} onChange={(e) => setStrictContainers(e.target.checked)} />
                  Strict container parsing (fail on malformed containers)
                </label>
                <label className="block">
                  <span className="mb-1 block text-foreground/80">Signature profile</span>
                  <select
                    value={signatureProfile}
                    onChange={(e) => setSignatureProfile(e.target.value as 'strict' | 'broad')}
                    className="w-full rounded-xl border border-border bg-black/20 px-3 py-2 outline-none"
                  >
                    <option value="strict">strict (curated)</option>
                    <option value="broad">broad (research)</option>
                  </select>
                </label>
                <label className="block">
                  <span className="mb-1 block text-foreground/80">Adapter policy</span>
                  <select
                    value={adapterPolicy}
                    onChange={(e) =>
                      setAdapterPolicy(
                        e.target.value as 'native-only' | 'hybrid' | 'external-preferred',
                      )
                    }
                    className="w-full rounded-xl border border-border bg-black/20 px-3 py-2 outline-none"
                  >
                    <option value="hybrid">hybrid (default)</option>
                    <option value="native-only">native-only</option>
                    <option value="external-preferred">external-preferred</option>
                  </select>
                </label>
                <label className="block">
                  <span className="mb-1 block text-foreground/80">Unlock provider (optional)</span>
                  <input
                    type="text"
                    value={unlockProvider}
                    onChange={(e) => setUnlockProvider(e.target.value)}
                    placeholder="bitlocker, luks, filevault..."
                    className="w-full rounded-xl border border-border bg-black/20 px-3 py-2 outline-none"
                  />
                </label>
                <label className="flex items-center gap-2 text-foreground/80">
                  <input type="checkbox" checked={enableBypass} onChange={(e) => setEnableBypass(e.target.checked)} />
                  Enable bypass mode (audit logged, requires metadata)
                </label>
                {enableBypass && (
                  <>
                    <label className="block">
                      <span className="mb-1 block text-foreground/80">Case ID</span>
                      <input
                        type="text"
                        value={caseId}
                        onChange={(e) => setCaseId(e.target.value)}
                        className="w-full rounded-xl border border-border bg-black/20 px-3 py-2 outline-none"
                      />
                    </label>
                    <label className="block">
                      <span className="mb-1 block text-foreground/80">Legal authority</span>
                      <input
                        type="text"
                        value={legalAuthority}
                        onChange={(e) => setLegalAuthority(e.target.value)}
                        className="w-full rounded-xl border border-border bg-black/20 px-3 py-2 outline-none"
                      />
                    </label>
                  </>
                )}
              </div>
            )}

            <div className="rounded-xl border border-border/70 bg-black/30 p-3 text-xs text-foreground/80">
              <div className="mb-1 flex items-center justify-between">
                <span>Progress</span>
                <span>{progress?.percent ?? 0}%</span>
              </div>
              <div className="h-2 overflow-hidden rounded bg-white/10">
                <div
                  className="h-full bg-accent transition-all"
                  style={{ width: `${progress?.percent ?? 0}%` }}
                />
              </div>
              <p className="mt-2 text-[11px] text-foreground/60">
                {progress?.message ?? 'Awaiting scan start'}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <Button onClick={handleScan} disabled={busy} className="gap-2">
                <Search size={14} /> Run Scan
              </Button>
              <Button onClick={handleRecover} disabled={busy || !report} variant="secondary" className="gap-2">
                <HardDriveDownload size={14} /> Recover
              </Button>
            </div>

            <p className="rounded-xl border border-border/80 bg-black/20 p-3 text-xs text-foreground/80">{status}</p>
          </Card>

          <div className="grid gap-4">
            <Card className="animate-fade-up [animation-delay:80ms]">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-lg font-semibold">Findings</h2>
                <div className="flex items-center gap-2 text-xs text-foreground/70">
                  <Sparkles size={14} />
                  {report ? `${report.findings.length} items` : 'No scan yet'}
                </div>
              </div>
              <div className="max-h-[320px] overflow-auto rounded-xl border border-border/70">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-black/40 text-foreground/80">
                    <tr>
                      <th className="px-3 py-2">Name</th>
                      <th className="px-3 py-2">Type</th>
                      <th className="px-3 py-2">Offset</th>
                      <th className="px-3 py-2">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.slice(0, 500).map((item) => (
                      <tr
                        key={item.id}
                        className={`cursor-pointer border-t border-border/60 ${selectedId === item.id ? 'bg-accent/20' : 'hover:bg-white/5'}`}
                        onClick={() => void handlePreview(item)}
                      >
                        <td className="px-3 py-2">{item.display_name}</td>
                        <td className="px-3 py-2">{item.extension}</td>
                        <td className="px-3 py-2">0x{item.offset.toString(16)}</td>
                        <td className="px-3 py-2">{item.size}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>

            <div className="grid gap-4 xl:grid-cols-2">
              <Card className="animate-fade-up [animation-delay:140ms]">
                <h3 className="mb-2 text-base font-semibold">Preview / Hex</h3>
                {selected ? (
                  <div className="mb-2 text-xs text-foreground/70">
                    <p><strong>{selected.display_name}</strong></p>
                    <p>signature: {selected.signature_id}</p>
                    <p>confidence: {(selected.confidence * 100).toFixed(1)}%</p>
                  </div>
                ) : (
                  <p className="mb-2 text-xs text-foreground/70">Pick a finding to preview bytes.</p>
                )}
                <pre className="max-h-[250px] overflow-auto rounded-xl border border-border bg-black/50 p-3 text-[11px] text-emerald-200">
{hexPreview || 'No preview loaded.'}
                </pre>
              </Card>

              <Card className="animate-fade-up [animation-delay:180ms]">
                <h3 className="mb-2 text-base font-semibold">Container Tree</h3>
                <p className="mb-2 text-xs text-foreground/70">VM/backup virtual mount summary (VMDK, VHDX, VHD, QCOW2, VDI, OVA, VPK, WIM...)</p>
                <div className="max-h-[250px] overflow-auto rounded-xl border border-border bg-black/30 p-2 text-xs">
                  {container ? (
                    <>
                      <p className="mb-2 rounded bg-white/5 px-2 py-1 text-foreground/80">
                        Type: {container.container_type} | entries: {container.entries.length}
                      </p>
                      {container.entries.slice(0, 300).map((entry) => (
                        <div key={`${entry.name}-${entry.offset}`} className="rounded px-2 py-1 hover:bg-white/5">
                          {entry.name} <span className="text-foreground/50">({entry.size} bytes)</span>
                        </div>
                      ))}
                    </>
                  ) : (
                    <p className="px-2 py-1 text-foreground/60">No mounted container.</p>
                  )}
                </div>
              </Card>
            </div>
          </div>
        </section>

        <footer className="grid gap-2 rounded-2xl border border-border/70 bg-black/20 p-3 text-xs text-foreground/70 md:grid-cols-3 md:items-center">
          <div className="flex items-center gap-2"><Shield size={14} /> Recoveries enforced to separate destination</div>
          <div>Progress updates every 1% with ETA</div>
          <div className="text-right">MVP: NTFS quick + deep carving + VMDK virtual mount + Tauri UI</div>
        </footer>
      </div>
    </div>
  );
}
