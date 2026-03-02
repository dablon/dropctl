//! Simple relay server - run this on a machine with open port 443
//! Usage: cargo run --example simple_relay

use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};

type Peers = Arc<RwLock<HashMap<String, mpsc::Sender<TcpStream>>>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "443".to_string());
    let addr = format!("0.0.0.0:{}", port);
    
    let listener = TcpListener::bind(&addr).await?;
    println!("Relay server listening on {}", addr);
    
    let peers: Peers = Arc::new(RwLock::new(HashMap::new()));
    
    while let Ok((socket, addr)) = listener.accept().await {
        println!("Connection from: {}", addr);
        let peers = peers.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, peers).await {
                eprintln!("Error: {}", e);
            }
        });
    }
    
    Ok(())
}

async fn handle_connection(mut socket: TcpStream, peers: Peers) -> anyhow::Result<()> {
    // Read room ID
    let mut buf = [0u8; 1024];
    let n = socket.read(&mut buf).await?;
    let room_id = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    
    println!("Room: {}", room_id);
    
    // Check if there's another peer waiting
    let mut peers_write = peers.write().await;
    if let Some(sender) = peers_write.remove(&room_id) {
        // There's a peer waiting - connect them!
        socket.write_all(b"CONNECTED\n").await?;
        // Send the waiting peer's socket to the connector
        let _ = sender.send(socket);
    } else {
        // Wait for another peer to connect
        let (tx, mut rx) = mpsc::channel::<TcpStream>(1);
        peers_write.insert(room_id, tx);
        drop(peers_write);
        
        socket.write_all(b"WAITING\n").await?;
        
        // Wait for connection or timeout
        match tokio::time::timeout(std::time::Duration::from_secs(60), rx.recv()).await {
            Ok(Some(client)) => {
                // Got a client - relay between them
                socket.write_all(b"CONNECTED\n").await?;
                relay(socket, client).await?;
            }
            Ok(None) => {
                socket.write_all(b"DISCONNECTED\n").await?;
            }
            Err(_) => {
                socket.write_all(b"TIMEOUT\n").await?;
            }
        }
    }
    
    Ok(())
}

async fn relay(mut a: TcpStream, mut b: TcpStream) -> anyhow::Result<()> {
    // Simple relay - copy data both ways
    let (mut ra, mut wa) = a.split();
    let (mut rb, mut wb) = b.split();
    
    tokio::select! {
        _ = tokio::io::copy(&mut ra, &mut wb) => {}
        _ = tokio::io::copy(&mut rb, &mut wa) => {}
    }
    
    Ok(())
}
