use quinn::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};

use crate::error::{LokiDataForgeError, Result};

/// Protocol definition for Network Disk Scraping over QUIC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub container_id: String,
    pub offset: u64,
    pub length: usize,
}

/// The DiskScraper utilizes multiplexed QUIC streams to fetch
/// targeted data blocks from a remote mesh peer. This bypasses
/// the need to download massive containers (VMDK/VHDX) locally.
pub struct NetworkDiskScraper {
    connection: Connection,
}

impl NetworkDiskScraper {
    /// Initialize a new scraper tied to a specific remote peer connection.
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// Fetches a specific geometric block from the remote container via a new QUIC stream.
    pub async fn fetch_block(&self, request: &BlockRequest) -> Result<Vec<u8>> {
        // Open a bi-directional stream for this specific block fetch
        let (mut send, mut recv) = self.connection
            .open_bi()
            .await
            .map_err(|e| LokiDataForgeError::NetworkLayer(format!("Failed to open QUIC stream: {e}")))?;

        // Serialize the block request (using a fast binary format like bincode)
        let payload = match bincode::serialize(request) {
            Ok(bytes) => bytes,
            Err(e) => return Err(LokiDataForgeError::NetworkLayer(format!("Failed to serialize request: {e}"))),
        };

        // Write payload length prefix (u32) followed by the payload itself
        send.write_u32(payload.len() as u32)
            .await
            .map_err(|e| LokiDataForgeError::NetworkLayer(e.to_string()))?;
        send.write_all(&payload)
            .await
            .map_err(|e| LokiDataForgeError::NetworkLayer(e.to_string()))?;
        
        // Signal that we're done sending for this stream (half-close)
        send.finish()
            .map_err(|e| LokiDataForgeError::NetworkLayer(e.to_string()))?;

        // Await the binary response stream
        let resp_len = recv.read_u32()
            .await
            .map_err(|e| LokiDataForgeError::NetworkLayer(e.to_string()))? as usize;
            
        // Protect against malicious or accidental massive allocations
        if resp_len > 64 * 1024 * 1024 {
            return Err(LokiDataForgeError::NetworkLayer(format!("Requested block size {} exceeds 64MB hard cap", resp_len)));
        }

        let mut buffer = vec![0u8; resp_len];
        recv.read_exact(&mut buffer)
            .await
            .map_err(|e| LokiDataForgeError::NetworkLayer(e.to_string()))?;

        Ok(buffer)
    }
}
