//! Connection methods for dropctl
//! 
//! Supports multiple connection strategies:
//! 1. Direct TCP connection (requires open port)
//! 2. WebSocket relay (works through firewalls)

use {
    anyhow::{Context, Result},
    std::path::PathBuf,
    tokio::net::{TcpListener, TcpStream,TcpAddr},
    tokio::io::{AsyncReadExt, AsyncWriteExt},
    futures_util::{SinkExt, StreamExt},
    tokio_tungstenite::{connect_async, tungstenite::Message},
    tracing::{info, error},
};

use crate::crypto::{KeyPair, load_or_generate_keypair};
use crate::crypto::session::{handshake_initiator, handshake_responder, SecureSession};
use crate::protocol::{Message, Handshake, read_message, write_message};
use crate::transfer::{send_file, receive_file, print_progress};

/// Connection mode
#[derive(Debug, Clone)]
pub enum ConnectMode {
    /// Direct TCP connection
    Direct,
    /// Use relay server via WebSocket
    Relay(String),
}

/// Establish connection to peer
pub async fn connect(
    address: &str,
    keypair: &KeyPair,
    hostname: &str,
    file_path: Option<&PathBuf>,
    peer_key: Option<&str>,
    mode: ConnectMode,
) -> Result<()> {
    match mode {
        ConnectMode::Direct => {
            // Original TCP connection
            connect_direct(address, keypair, hostname, file_path, peer_key).await
        }
        ConnectMode::Relay(relay_url) => {
            // WebSocket relay connection
            connect_relay(&relay_url, address, keypair, hostname, file_path).await
        }
    }
}

/// Direct TCP connection (original method)
async fn connect_direct(
    address: &str,
    keypair: &KeyPair,
    hostname: &str,
    file_path: Option<&PathBuf>,
    peer_key: Option<&str>,
) -> Result<()> {
    info!("Connecting to {}", address);
    
    let socket = TcpStream::connect(address).await
        .context("Failed to connect")?;
    
    info!("Connected to {}", address);
    
    // Parse peer key if provided
    let (peer_identity, peer_x25519) = if let Some(key) = peer_key {
        let (id, x25519) = KeyPair::deserialize_public(key)
            .context("Invalid peer key format")?;
        (Some(id), Some(x25519))
    } else {
        (None, None)
    };
    
    // Perform crypto handshake as initiator
    let session = handshake_initiator(
        &mut TcpStream::connect(address).await?,
        keypair,
        peer_identity.as_ref(),
        peer_x25519.as_ref()
    ).await?;
    
    info!("Secure connection established");
    
    // Send our handshake
    let handshake = Handshake::new(hostname.to_string());
    let mut socket = TcpStream::connect(address).await?;
    write_message(&mut socket, &Message::Handshake(handshake)).await?;
    
    // Wait for peer's handshake
    let msg = read_message(&mut socket).await?;
    if let Message::Handshake(h) = msg {
        info!("Peer hostname: {}", h.hostname);
    }
    
    // If file path provided, send the file
    if let Some(path) = file_path {
        // Give receiver time to get ready
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        send_file(
            &mut socket,
            &session,
            path,
            Some(Box::new(print_progress)),
        ).await?;
        
        println!("\n✓ Sent: {}", path.file_name().unwrap_or_default().to_string_lossy());
    }
    
    Ok(())
}

/// Connect via WebSocket relay server
async fn connect_relay(
    relay_url: &str,
    address: &str,
    keypair: &KeyPair,
    hostname: &str,
    file_path: Option<&PathBuf>,
) -> Result<()> {
    info!("Connecting to relay: {}", relay_url);
    
    // Connect to WebSocket relay
    let url = format!("{}/connect?peer={}", relay_url, address);
    let (ws_stream, _) = connect_async(&url).await
        .context("Failed to connect to relay")?;
    
    let (mut write, mut read) = ws_stream.split();
    
    info!("Connected to relay, performing handshake...");
    
    // Create a TcpStream-like wrapper for the WebSocket
    let mut ws_wrapper = WebSocketWrapper::new(read, write);
    
    // Perform crypto handshake through relay
    let session = handshake_initiator(
        &mut ws_wrapper,
        keypair,
        None,
        None
    ).await?;
    
    info!("Secure connection established via relay");
    
    // Send our handshake
    let handshake = Handshake::new(hostname.to_string());
    write_message(&mut ws_wrapper, &Message::Handshake(handshake)).await?;
    
    // Wait for peer's handshake
    let msg = read_message(&mut ws_wrapper).await?;
    if let Message::Handshake(h) = msg {
        info!("Peer hostname: {}", h.hostname);
    }
    
    // If file path provided, send the file
    if let Some(path) = file_path {
        // Give receiver time to get ready
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        send_file(
            &mut ws_wrapper,
            &session,
            path,
            Some(Box::new(print_progress)),
        ).await?;
        
        println!("\n✓ Sent: {}", path.file_name().unwrap_or_default().to_string_lossy());
    }
    
    Ok(())
}

/// Start relay server listener
pub async fn start_relay(port: u16) -> Result<()> {
    info!("Starting relay server on port {}", port);
    
    let listener = TcpListener::bind(("0.0.0.0", port)).await
        .context("Failed to bind port")?;
    
    info!("Relay server listening, waiting for connections...");
    
    while let Ok((socket, addr)) = listener.accept().await {
        info!("New connection from: {}", addr);
        
        // Handle each connection
        tokio::spawn(async move {
            if let Err(e) = handle_relay_connection(socket).await {
                error!("Relay connection error: {}", e);
            }
        });
    }
    
    Ok(())
}

/// Handle a relay connection
async fn handle_relay_connection(socket: TcpStream) -> Result<()> {
    use tokio::io::{AsyncRead, AsyncWrite};
    
    // Upgrade to WebSocket
    let ws_stream = tokio_tungstenite::accept_async(socket).await
        .context("WebSocket upgrade failed")?;
    
    let (mut write, mut read) = ws_stream.split();
    
    // Wait for peer address request
    let msg = read.next().await
        .context("No message from relay")??;
    
    let addr = match msg {
        Message::Text(s) => s,
        _ => anyhow::bail!("Expected peer address"),
    };
    
    info!("Peer wants to connect to: {}", addr);
    
    // TODO: Connect to the actual peer and relay data
    
    Ok(())
}

/// WebSocket wrapper to implement async I/O
struct WebSocketWrapper<S, E> {
    read: S,
    write: E,
}

impl<S, E> WebSocketWrapper<S, E> 
where 
    S: StreamExt<Item = Result<Message, E>> + Unpin,
    E: SinkExt<Message, Error = E> + Unpin,
{
    fn new(read: S, write: E) -> Self {
        Self { read, write }
    }
}

impl<S, E> AsyncRead for WebSocketWrapper<S, E> 
where 
    S: StreamExt<Item = Result<Message, E>> + Unpin,
    E: SinkExt<Message, Error = E> + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // This is a simplified implementation
        // In practice, you'd need proper async message handling
        std::task::Poll::Ready(Ok(()))
    }
}

impl<S, E> AsyncWrite for WebSocketWrapper<S, E> 
where 
    S: StreamExt<Item = Result<Message, E>> + Unpin,
    E: SinkExt<Message, Error = E> + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Simplified - in practice would convert to WebSocket messages
        std::task::Poll::Ready(Ok(buf.len()))
    }
    
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
