//! Simple relay server for dropctl
//! 
//! This is a minimal relay that helps two peers connect when direct
//! connection is not possible due to firewalls/NAT.

use {
    anyhow::Result,
    tokio::net::{TcpListener, TcpStream},
    tokio::io::{AsyncReadExt, AsyncWriteExt},
    std::collections::HashMap,
    std::sync::Arc,
    tokio::sync::RwLock,
};

type PeerMap = Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<TcpStream>>>>;

/// Relay protocol:
//! 1. Peer A connects to relay
//! 2. Peer A sends: "REGISTER:peerB"
//! 3. Peer B connects to relay  
//! 4. Peer B sends: "READY:peerB"
//! 5. Relay tells A: "CONNECT:peerB"
//! 6. Both peers connect to each other through relay (or relay proxies data)

#[derive(Debug, Clone)]
enum RelayMessage {
    Register { peer_id: String },
    Ready { peer_id: String },
    Connect { peer_id: String },
    Proxy { peer_id: String, data: Vec<u8> },
    Error { message: String },
}

impl RelayMessage {
    fn parse(data: &str) -> Option<Self> {
        if data.starts_with("REGISTER:") {
            let peer_id = data.strip_prefix("REGISTER:")?.to_string();
            Some(RelayMessage::Register { peer_id })
        } else if data.starts_with("READY:") {
            let peer_id = data.strip_prefix("READY:")?.to_string();
            Some(RelayMessage::Ready { peer_id })
        } else if data.starts_with("CONNECT:") {
            let peer_id = data.strip_prefix("CONNECT:")?.to_string();
            Some(RelayMessage::Connect { peer_id })
        } else if data.starts_with("PROXY:") {
            let rest = data.strip_prefix("PROXY:")?;
            let parts: Vec<&str> = rest.splitn(2, ':').collect();
            if parts.len() == 2 {
                Some(RelayMessage::Proxy { 
                    peer_id: parts[0].to_string(), 
                    data: parts[1].as_bytes().to_vec() 
                })
            } else {
                None
            }
        } else if data.starts_with("ERROR:") {
            let message = data.strip_prefix("ERROR:")?.to_string();
            Some(RelayMessage::Error { message })
        } else {
            None
        }
    }
    
    fn to_string(&self) -> String {
        match self {
            RelayMessage::Register { peer_id } => format!("REGISTER:{}", peer_id),
            RelayMessage::Ready { peer_id } => format!("READY:{}", peer_id),
            RelayMessage::Connect { peer_id } => format!("CONNECT:{}", peer_id),
            RelayMessage::Proxy { peer_id, data } => {
                format!("PROXY{}:{}", peer_id, String::from_utf8_lossy(data))
            }
            RelayMessage::Error { message } => format!("ERROR:{}", message),
        }
    }
}

async fn handle_peer(
    mut socket: TcpStream,
    peers: PeerMap,
    peer_id: String,
) -> Result<()> {
    loop {
        let mut buf = [0u8; 4096];
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        
        let data = String::from_utf8_lossy(&buf[..n]);
        
        // Handle relay messages
        if let Some(msg) = RelayMessage::parse(&data) {
            match msg {
                RelayMessage::Ready { peer_id: target } => {
                    // Check if target peer is waiting
                    let peers_read = peers.read().await;
                    if let Some(sender) = peers_read.get(&target) {
                        // Tell both peers to connect
                        socket.write_all(b"CONNECT\n").await?;
                        // Notify waiting peer
                        let _ = sender.send(socket.try_clone().await?);
                    } else {
                        socket.write_all(b"WAITING\n").await?;
                    }
                }
                RelayMessage::Connect { peer_id: target } => {
                    // Direct connection request
                    let peers_read = peers.read().await;
                    if let Some(sender) = peers_read.get(&target) {
                        socket.write_all(b"CONNECT\n").await?;
                    } else {
                        socket.write_all(b"NOT_FOUND\n").await?;
                    }
                }
                _ => {}
            }
        }
    }
    
    // Cleanup
    peers.write().await.remove(&peer_id);
    Ok(())
}

/// Start relay server
pub async fn start_relay(port: u16) -> Result<()> {
    let peers: PeerMap = Arc::new(RwLock::new(HashMap::new()));
    
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    
    println!("Relay server running on port {}", port);
    
    while let Ok((socket, addr)) = listener.accept().await {
        println!("New connection from: {}", addr);
        
        let peers = peers.clone();
        tokio::spawn(async move {
            // Read initial registration message
            let mut buf = [0u8; 256];
            if let Ok(n) = socket.read(&mut buf).await {
                let data = String::from_utf8_lossy(&buf[..n]);
                if let Some(msg) = RelayMessage::parse(&data) {
                    if let RelayMessage::Register { peer_id } = msg {
                        println!("Peer registered: {}", peer_id);
                        
                        // Store peer
                        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
                        peers.write().await.insert(peer_id.clone(), tx);
                        
                        // Handle this peer
                        if let Err(e) = handle_peer(socket, peers, peer_id).await {
                            eprintln!("Error: {}", e);
                        }
                    }
                }
            }
        });
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    start_relay(9999).await
}
