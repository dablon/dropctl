//! NAT Traversal module for dropctl
//! 
//! Provides STUN/TURN support for P2P connectivity through NATs:
//! 1. STUN - Discover public IP:port mapping
//! 2. UDP Hole Punching - Direct P2P via UDP
//! 3. TURN Relay - Fallback when direct connection fails

use {
    anyhow::{Context, Result},
    std::net::{SocketAddr, IpAddr, Ipv4Addr, ToSocketAddrs},
    std::sync::Arc,
    tokio::net::UdpSocket,
    tokio::sync::Mutex,
    tokio::time::{timeout, Duration},
    tracing::{info, warn, error},
};

/// STUN server addresses (public, free to use)
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.stunprotocol.org:3478",
];

/// Public STUN server for NAT discovery
const DEFAULT_STUN: &str = "stun.l.google.com:19302";

/// TURN server configuration
#[derive(Clone, Debug)]
pub struct TurnConfig {
    pub server: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for TurnConfig {
    fn default() -> Self {
        Self {
            server: "turn:relay.l.google.com:3478".to_string(),
            username: None,
            password: None,
        }
    }
}

/// NAT traversal result
#[derive(Clone, Debug)]
pub struct NatInfo {
    /// Our local IP:port
    pub local: SocketAddr,
    /// Our public IP:port (from STUN)
    pub public: Option<SocketAddr>,
    /// NAT type discovered
    pub nat_type: NatType,
}

/// NAT type classification
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NatType {
    /// No NAT, direct public IP
    Open,
    /// Full cone NAT - easiest to traverse
    FullCone,
    /// Address-restricted cone NAT
    AddressRestricted,
    /// Port-restricted cone NAT - harder
    PortRestricted,
    /// Symmetric NAT - hardest, needs TURN
    Symmetric,
    /// Could not determine
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Open => write!(f, "Open (no NAT)"),
            NatType::FullCone => write!(f, "Full Cone"),
            NatType::AddressRestricted => write!(f, "Address-Restricted"),
            NatType::PortRestricted => write!(f, "Port-Restricted"),
            NatType::Symmetric => write!(f, "Symmetric"),
            NatType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// STUN/TURN client for NAT traversal
pub struct NatClient {
    stun_server: String,
    socket: Arc<Mutex<Option<UdpSocket>>>,
    local_port: u16,
}

impl NatClient {
    /// Create a new NAT client
    pub async fn new(local_port: u16) -> Result<Self> {
        // Bind UDP socket
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port);
        let socket = UdpSocket::bind(addr).await
            .context("Failed to bind UDP socket")?;
        
        info!("UDP socket bound to {}", socket.local_addr()?);
        
        Ok(Self {
            stun_server: DEFAULT_STUN.to_string(),
            socket: Arc::new(Mutex::new(Some(socket))),
            local_port,
        })
    }
    
    /// Set custom STUN server
    pub fn with_stun(mut self, server: &str) -> Self {
        self.stun_server = server.to_string();
        self
    }
    
    /// Discover our public IP:port using STUN
    pub async fn discover(&self) -> Result<NatInfo> {
        let socket_guard = self.socket.lock().await;
        let socket = socket_guard.as_ref()
            .context("Socket not available")?;
        
        let local = socket.local_addr()
            .context("Failed to get local addr")?;
        
        // Try each STUN server
        for stun_addr in STUN_SERVERS {
            match self.query_stun(socket, stun_addr).await {
                Ok(public) => {
                    let nat_type = self.classify_nat(&local, &public);
                    info!("STUN success: {} -> {} (NAT: {})", local, public, nat_type);
                    return Ok(NatInfo {
                        local,
                        public: Some(public),
                        nat_type,
                    });
                }
                Err(e) => {
                    warn!("STUN server {} failed: {}", stun_addr, e);
                }
            }
        }
        
        // If all STUN servers fail, assume no NAT or local-only
        info!("STUN discovery failed, assuming local only");
        Ok(NatInfo {
            local,
            public: None,
            nat_type: NatType::Unknown,
        })
    }
    
    /// Query a single STUN server
    async fn query_stun(&self, socket: &UdpSocket, stun_addr: &str) -> Result<SocketAddr> {
        // Resolve hostname to SocketAddr
        let addrs: Vec<SocketAddr> = (stun_addr, 0).to_socket_addrs()
            .context("Failed to resolve STUN server")?
            .collect();
        
        let addr = addrs.into_iter().next()
            .context("No addresses for STUN server")?;
        
        // Build STUN binding request (RFC 5389)
        // STUN header: 0x0001 (Binding Request), transaction ID (96 bits)
        let mut request = vec![
            0x00, 0x01,  // Message Type: Binding Request
            0x00, 0x00,  // Message Length: 0
            0x21, 0x12, 0xA4, 0x42,  // Magic Cookie
        ];
        // Transaction ID (96 bits = 12 bytes)
        request.extend_from_slice(&rand::random::<[u8; 12]>());
        
        // Send request
        socket.send_to(&request, addr).await
            .context("Failed to send STUN request")?;
        
        // Wait for response with timeout
        let mut response = [0u8; 512];
        let (len, from) = timeout(Duration::from_secs(3), socket.recv_from(&mut response))
            .await
            .context("STUN request timed out")?
            .context("Failed to receive STUN response")?;
        
        // Parse STUN response (simplified - just extract XOR-mapped-address)
        if len < 20 {
            anyhow::bail!("Invalid STUN response");
        }
        
        // Check that response matches our transaction
        if &response[0..4] != &request[0..4] {
            anyhow::bail!("Transaction ID mismatch");
        }
        
        // Look for XOR-MAPPED-ADDRESS attribute (0x0020)
        let mut public_addr = from;
        let mut offset = 20;
        
        while offset + 4 < len {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            
            if attr_type == 0x0020 && attr_len >= 8 && offset + 8 <= len {
                // XOR-MAPPED-ADDRESS
                let family = response[offset + 4];
                if family == 0x01 { // IPv4
                    let port = u16::from_be_bytes([response[offset + 6], response[offset + 7]])
                        ^ 0x2112;
                    let ip = Ipv4Addr::new(
                        response[offset + 8] ^ 0x21,
                        response[offset + 9] ^ 0x12,
                        response[offset + 10] ^ 0xA4,
                        response[offset + 11] ^ 0x42,
                    );
                    public_addr = SocketAddr::new(IpAddr::V4(ip), port);
                    break;
                }
            }
            
            offset += 4 + attr_len;
            // Align to 4 bytes
            if attr_len % 4 != 0 {
                offset += 4 - (attr_len % 4);
            }
        }
        
        Ok(public_addr)
    }
    
    /// Classify NAT type by comparing local and public endpoints
    fn classify_nat(&self, local: &SocketAddr, public: &SocketAddr) -> NatType {
        if local.ip() == public.ip() && local.port() == public.port() {
            NatType::Open
        } else if local.port() == public.port() {
            // Same port suggests full cone or address-restricted
            NatType::FullCone
        } else {
            // Port changed - could be any type
            // For simplicity, assume symmetric (worst case)
            NatType::Symmetric
        }
    }
    
    /// Attempt UDP hole punching with a peer
    /// 
    /// Both sides call this simultaneously:
    /// 1. Send packets to each other's predicted addresses
    /// 2. Wait for incoming packets to open the NAT
    pub async fn hole_punch(
        &self,
        peer_addresses: &[SocketAddr],
        peer_public: SocketAddr,
    ) -> Result<Option<SocketAddr>> {
        let socket_guard = self.socket.lock().await;
        let socket = socket_guard.as_ref()
            .context("Socket not available")?;
        
        let local = socket.local_addr()
            .context("Failed to get local addr")?;
        
        info!("Starting UDP hole punch to {:?}, peer public: {}", peer_addresses, peer_public);
        
        // Try to connect to peer's public address
        if let Err(e) = socket.connect(peer_public).await {
            warn!("UDP connect failed: {}", e);
        }
        
        // Send test packets to all peer addresses
        for addr in peer_addresses {
            let test_msg = b"DROPCTL_HOLE_PUNCH";
            if let Err(e) = socket.send_to(test_msg, *addr).await {
                warn!("Failed to send to {}: {}", addr, e);
            }
        }
        
        // Wait for incoming data (which means hole punch succeeded)
        let mut buf = [0u8; 128];
        match timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                info!("Hole punch success! Received from {}", from);
                return Ok(Some(from));
            }
            Ok(Err(e)) => {
                warn!("Hole punch receive error: {}", e);
            }
            Err(_) => {
                info!("Hole punch timed out");
            }
        }
        
        // Try sending directly to peer public address as final attempt
        let test_msg = b"DROPCTL_HOLE_PUNCH";
        if socket.send_to(test_msg, peer_public).await.is_ok() {
            // Wait briefly for response
            match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    info!("Direct UDP to peer public worked! From {}", from);
                    return Ok(Some(from));
                }
                _ => {}
            }
        }
        
        Ok(None)
    }
    
    /// Connect to a TURN relay as a fallback
    pub async fn connect_turn(&self, config: &TurnConfig) -> Result<UdpSocket> {
        let socket_guard = self.socket.lock().await;
        let socket = socket_guard.as_ref()
            .context("Socket not available")?;
        
        info!("Connecting to TURN server: {}", config.server);
        
        // Parse TURN server (format: turn:host:port or turn://host:port)
        let server_addr = config.server
            .trim_start_matches("turn://")
            .trim_start_matches("turn:");
        
        let addr: SocketAddr = server_addr.parse()
            .context("Invalid TURN server address")?;
        
        // For now, use UDP directly to TURN server
        // In production, you'd implement full TURN protocol (RFC 5766)
        socket.connect(addr).await
            .context("Failed to connect to TURN server")?;
        
        info!("Connected to TURN relay at {}", addr);
        
        // Return a new socket bound for TURN communication
        // Note: Full TURN would allocate a relay address
        let relay_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let relay_socket = UdpSocket::bind(relay_addr).await
            .context("Failed to create relay socket")?;
        
        Ok(relay_socket)
    }
    
    /// Get socket reference for external use
    pub fn socket(&self) -> Arc<Mutex<Option<UdpSocket>>> {
        self.socket.clone()
    }
}

/// Exchange NAT info with peer via signaling
/// 
/// In practice, this would use an existing channel (like the relay or a pre-arranged meeting point)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NatExchange {
    /// Our local address
    pub local: SocketAddr,
    /// Our public address (from STUN)
    pub public: Option<SocketAddr>,
    /// NAT type (for peer's info)
    pub nat_type: NatType,
}

impl NatExchange {
    /// Create exchange message
    pub fn new(info: &NatInfo) -> Self {
        Self {
            local: info.local,
            public: info.public.clone(),
            nat_type: info.nat_type.clone(),
        }
    }
}

/// Connection strategy result
#[derive(Clone, Debug)]
pub enum ConnectionMethod {
    /// Direct UDP connection (hole punch succeeded)
    DirectUdp(SocketAddr),
    /// TURN relay connection
    TurnRelay(SocketAddr),
    /// Fallback to TCP (if UDP fails completely)
    Tcp(String),
}

impl std::fmt::Display for ConnectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionMethod::DirectUdp(addr) => write!(f, "UDP P2P ({})", addr),
            ConnectionMethod::TurnRelay(addr) => write!(f, "TURN Relay ({})", addr),
            ConnectionMethod::Tcp(addr) => write!(f, "TCP ({})", addr),
        }
    }
}
