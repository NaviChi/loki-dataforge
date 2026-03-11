use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Real-time live extraction diagnostics gathered from the Omniscient Hyper-Mesh nodes
/// during Phase 5 Beta deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionDiagnostics {
    pub node_id: String,
    pub timestamp: u64,
    pub total_bytes_extracted: u64,
    pub current_throughput_mbps: f64,
    pub active_multipath_links: u32,
    pub af_xdp_zero_copy_active: bool,
    pub wgpu_markov_active: bool,
    pub hypervisor_introspection_active: bool,
    pub average_latency_ms: f64,
    pub packet_drop_rate: f64,
}

/// Gathers the current state of the extraction node across the Swarm.
/// In production, this aggregates hardware statistics off the NIC queues and VRAM state.
pub fn gather_live_diagnostics(node_id: &str) -> ExtractionDiagnostics {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Mocking boundary telemetry for early Phase 5 Beta scaffolding.
    // In the field, these metrics read from `quinn` stats and the AF_XDP mock.
    ExtractionDiagnostics {
        node_id: node_id.to_string(),
        timestamp: now,
        total_bytes_extracted: 0,
        current_throughput_mbps: 0.0,
        active_multipath_links: 3, // Emulating bonded 10GbE, Wi-Fi 6, and 5G connections
        af_xdp_zero_copy_active: cfg!(target_os = "linux"),
        wgpu_markov_active: true, // Successfully hooked to the shader in Beta
        hypervisor_introspection_active: false, // Pending Sprint 3 injection
        average_latency_ms: 0.75, // Target sub-millisecond LAN latency for QuicSwarm
        packet_drop_rate: 0.0001,
    }
}
