import { useMemo, useState } from 'react';
import { FolderOpen, HardDrive } from 'lucide-react';
import { Button } from './ui/button';
import {
  browseInputLocations,
  browseOutputLocation,
  detectRaid,
  promptMissingRaidDialog,
  type RaidDetectionReport,
} from '../lib/api';

interface InputSelectorProps {
  inputPaths: string[];
  outputPath: string;
  disabled?: boolean;
  onInputPathsChange: (paths: string[]) => void;
  onOutputPathChange: (path: string) => void;
  onRaidUpdate: (raid: RaidDetectionReport | null, degradedMode: boolean) => void;
  onStatus: (status: string) => void;
}

function dedupePaths(paths: string[]): string[] {
  const out: string[] = [];
  for (const value of paths.map((v) => v.trim()).filter(Boolean)) {
    if (!out.includes(value)) {
      out.push(value);
    }
  }
  return out;
}

export function InputSelector({
  inputPaths,
  outputPath,
  disabled,
  onInputPathsChange,
  onOutputPathChange,
  onRaidUpdate,
  onStatus,
}: InputSelectorProps) {
  const [checkingRaid, setCheckingRaid] = useState(false);
  const [raidReport, setRaidReport] = useState<RaidDetectionReport | null>(null);
  const [degradedMode, setDegradedMode] = useState(false);

  const primarySource = useMemo(() => inputPaths[0] ?? '', [inputPaths]);

  async function runRaidDetection(paths: string[]): Promise<void> {
    const normalized = dedupePaths(paths);

    if (normalized.length < 2) {
      setRaidReport(null);
      setDegradedMode(false);
      onRaidUpdate(null, false);
      return;
    }

    setCheckingRaid(true);
    try {
      const report = await detectRaid(normalized);
      setRaidReport(report);
      onRaidUpdate(report, false);

      if (report.degraded) {
        const action = await promptMissingRaidDialog({
          expected_members: report.expected_members,
          detected_members: report.detected_members,
          missing_members: report.missing_members,
        });

        if (action === 'add_missing_drives') {
          const added = await browseInputLocations();
          if (added.length > 0) {
            const merged = dedupePaths([...normalized, ...added]);
            onInputPathsChange(merged);
            onStatus(`Added ${added.length} source(s). Re-running RAID detection...`);
            await runRaidDetection(merged);
            return;
          }
          onStatus('RAID remains incomplete: no additional drives were selected.');
        } else {
          setDegradedMode(true);
          onRaidUpdate(report, true);
          onStatus('Proceeding in degraded RAID mode with available drives.');
        }
      } else {
        setDegradedMode(false);
        onRaidUpdate(report, false);
      }
    } catch (error) {
      setRaidReport(null);
      setDegradedMode(false);
      onRaidUpdate(null, false);
      onStatus(String(error));
    } finally {
      setCheckingRaid(false);
    }
  }

  async function handleBrowseInput(): Promise<void> {
    try {
      const selected = await browseInputLocations();
      if (selected.length === 0) {
        return;
      }

      const merged = dedupePaths([...inputPaths, ...selected]);
      onInputPathsChange(merged);
      onStatus(`Selected ${merged.length} input source(s).`);
      await runRaidDetection(merged);
    } catch (error) {
      onStatus(String(error));
    }
  }

  async function handleBrowseOutput(): Promise<void> {
    try {
      const selected = await browseOutputLocation();
      if (!selected) {
        return;
      }
      onOutputPathChange(selected);
      onStatus(`Output location set: ${selected}`);
    } catch (error) {
      onStatus(String(error));
    }
  }

  function handleRemoveInput(path: string): void {
    const next = inputPaths.filter((value) => value !== path);
    onInputPathsChange(next);
    onStatus(`Removed input source: ${path}`);
    void runRaidDetection(next);
  }

  return (
    <div className="space-y-3">
      <div className="grid gap-2 md:grid-cols-[1fr_auto] md:items-end">
        <div>
          <label className="block text-sm font-medium text-foreground/80">Input drives/images/folders</label>
          <input
            value={primarySource}
            readOnly
            placeholder="Use Browse to select one or more sources"
            className="mt-1 w-full rounded-xl border border-border bg-black/20 px-3 py-2 text-sm outline-none"
          />
        </div>
        <Button onClick={() => void handleBrowseInput()} disabled={disabled || checkingRaid} className="h-[42px] gap-2">
          <HardDrive size={14} /> Browse
        </Button>
      </div>

      {inputPaths.length > 0 && (
        <div className="max-h-28 overflow-auto rounded-xl border border-border/80 bg-black/20 p-2 text-xs">
          {inputPaths.map((path) => (
            <div key={path} className="mb-1 flex items-center justify-between gap-2 rounded px-2 py-1 hover:bg-white/5">
              <span className="truncate">{path}</span>
              <button
                onClick={() => handleRemoveInput(path)}
                className="rounded bg-white/10 px-2 py-0.5 text-[11px] hover:bg-white/20"
                type="button"
                disabled={disabled}
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="grid gap-2 md:grid-cols-[1fr_auto] md:items-end">
        <div>
          <label className="block text-sm font-medium text-foreground/80">Output location</label>
          <input
            value={outputPath}
            readOnly
            placeholder="Use Browse to select recovery output directory"
            className="mt-1 w-full rounded-xl border border-border bg-black/20 px-3 py-2 text-sm outline-none"
          />
        </div>
        <Button
          onClick={() => void handleBrowseOutput()}
          disabled={disabled}
          variant="secondary"
          className="h-[42px] gap-2"
        >
          <FolderOpen size={14} /> Browse
        </Button>
      </div>

      {raidReport && (
        <div className="rounded-xl border border-amber-400/40 bg-amber-500/10 p-3 text-xs text-amber-100">
          <p className="font-semibold">
            RAID: {raidReport.controller} | {raidReport.detected_members}/{raidReport.expected_members} members
          </p>
          <p className="mt-1">
            Mode: {raidReport.mode ?? 'unknown'} | Stripe: {raidReport.stripe_size ?? 0} bytes
          </p>
          {raidReport.missing_members.length > 0 && (
            <p className="mt-1">
              Missing: {raidReport.missing_members.join(', ')}
              {degradedMode ? ' (degraded mode enabled)' : ''}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
