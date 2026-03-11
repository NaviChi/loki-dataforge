use loki_data_forge_core::network::disk_scraper::{NetworkDiskScraper, BlockRequest};
use loki_data_forge_core::network::quic_swarm::QuicSwarm;
use std::fs::File;
use std::io::Write;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_quic_headless_img_extraction() {
    let mut temp = NamedTempFile::new().unwrap();
    
    // Create a 1MB mock raw .img dataset
    let size = 1024 * 1024;
    let mut buffer = vec![0u8; size];
    
    // Put a distinct forensic watermark at the 512KB bound
    let chunk_magic = b"LOKI_FORENSIC_OK_1234";
    buffer[512 * 1024..512 * 1024 + chunk_magic.len()].copy_from_slice(chunk_magic);
    temp.write_all(&buffer).unwrap();
    temp.flush().unwrap();

    let path = temp.path().to_path_buf();
    
    // Use an unbuffered channel to communicate the dynamic port securely
    let (tx, rx) = tokio::sync::oneshot::channel();

    // Server Task (Headless OS node simulating remote peer)
    let server_task = tokio::spawn(async move {
        let swarm_listener = QuicSwarm::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let local_addr = swarm_listener.endpoint().local_addr().unwrap();
        
        tx.send(local_addr).unwrap();
        
        let mut incoming = swarm_listener.endpoint().accept().await.expect("peer connected");
        let connection = incoming.accept().unwrap().await.unwrap();
        
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let req_len = recv.read_u32().await.unwrap();
        
        let mut req_bytes = vec![0u8; req_len as usize];
        recv.read_exact(&mut req_bytes).await.unwrap();
        
        let request: BlockRequest = bincode::deserialize(&req_bytes).unwrap();
        assert_eq!(request.length, 1024);
        
        // Read directly from the disk image buffer Native OS Caching Bypass Mock
        let mut f = File::open(&path).unwrap();
        use std::io::{Read, Seek};
        f.seek(std::io::SeekFrom::Start(request.offset)).unwrap();
        let mut response_buf = vec![0u8; request.length];
        f.read_exact(&mut response_buf).unwrap();
        
        // Send back over QUIC Multiplexed Stream
        send.write_u32(response_buf.len() as u32).await.unwrap();
        send.write_all(&response_buf).await.unwrap();
        send.finish().unwrap();
    });

    // Client Task (Headless CLI extraction simulator)
    let server_addr = rx.await.unwrap();
    
    let swarm_client = QuicSwarm::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let connection = swarm_client.connect(server_addr, "localhost").await.unwrap();
    
    let scraper = NetworkDiskScraper::new(connection);
    
    // Extract block 512 (containing our watermark)
    let req = BlockRequest {
        container_id: "test-node-1".into(),
        offset: 512 * 1024,
        length: 1024,
    };
    
    let block_data = scraper.fetch_block(&req).await.unwrap();
    
    // Verify Mathematical and Binary Extrapolation
    assert_eq!(block_data.len(), 1024);
    assert_eq!(&block_data[0..chunk_magic.len()], chunk_magic);

    server_task.await.unwrap();
}
