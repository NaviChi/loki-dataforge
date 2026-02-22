import { invoke } from '@tauri-apps/api/core';

export interface FoundFile {
  id: string;
  display_name: string;
  extension: string;
  signature_id: string;
  source_path: string;
  container_path?: string;
  offset: number;
  size: number;
  confidence: number;
  category: string;
  encrypted: boolean;
  notes?: string;
}

export interface ScanReport {
  scan_id: string;
  started_at: string;
  finished_at: string;
  source: string;
  mode: 'quick' | 'deep' | 'hybrid';
  findings: FoundFile[];
  warnings: string[];
  metadata: {
    bytes_scanned: number;
    elapsed_ms: number;
    quick_hits: number;
    deep_hits: number;
    container_hits: number;
    container_type?: string;
  };
}

export interface ScanProgress {
  phase: string;
  percent: number;
  processed_bytes: number;
  total_bytes: number;
  eta_seconds?: number;
  message: string;
}

export interface VirtualContainer {
  source: string;
  container_type: string;
  entries: Array<{
    name: string;
    path_hint?: string;
    offset: number;
    size: number;
    encrypted: boolean;
    archive_index?: number;
  }>;
  descriptor?: string;
}

export interface RaidMemberInfo {
  source_path: string;
  member_index?: number;
  array_id?: string;
  notes: string[];
}

export interface RaidDetectionReport {
  detected: boolean;
  controller:
    | 'mdadm'
    | 'synology_shr'
    | 'windows_dynamic'
    | 'windows_storage_spaces'
    | 'hardware_ddf'
    | 'apple_raid'
    | 'unknown';
  mode?: 'raid0' | 'raid1' | 'raid5' | 'raid6' | 'raid10' | 'jbod' | 'synology_shr';
  stripe_size?: number;
  parity_layout?:
    | 'left_symmetric'
    | 'right_symmetric'
    | 'left_asymmetric'
    | 'right_asymmetric'
    | 'unknown';
  expected_members: number;
  detected_members: number;
  missing_members: string[];
  degraded: boolean;
  members: RaidMemberInfo[];
  notes: string[];
}

export async function runScan(payload: {
  source?: string;
  sources?: string[];
  mode: 'quick' | 'deep' | 'hybrid';
  threads: number;
  chunk_size: number;
  max_carve_size: number;
  synology_mode: boolean;
  include_container_scan: boolean;
  degraded_mode?: boolean;
}): Promise<ScanReport> {
  return invoke<ScanReport>('scan_command', { request: payload });
}

export async function mountContainer(path: string): Promise<VirtualContainer> {
  return invoke<VirtualContainer>('mount_container_command', { path });
}

export async function recoverFromLast(payload: {
  source: string;
  destination: string;
  overwrite: boolean;
}): Promise<Array<{ source_id: string; output_path: string; bytes_written: number; sha256: string }>> {
  return invoke('recover_command', { request: payload });
}

export async function previewBytes(source: string, offset: number, length: number): Promise<string> {
  return invoke<string>('preview_bytes_command', { source, offset, length });
}

export async function browseInputLocations(): Promise<string[]> {
  return invoke<string[]>('browse_input_locations_command');
}

export async function browseOutputLocation(): Promise<string | null> {
  return invoke<string | null>('browse_output_location_command');
}

export async function detectRaid(inputs: string[]): Promise<RaidDetectionReport> {
  return invoke<RaidDetectionReport>('detect_raid_command', { request: { inputs } });
}

export async function promptMissingRaidDialog(payload: {
  expected_members: number;
  detected_members: number;
  missing_members: string[];
}): Promise<'add_missing_drives' | 'skip_degraded'> {
  return invoke<'add_missing_drives' | 'skip_degraded'>('prompt_missing_raid_dialog_command', {
    request: payload,
  });
}
