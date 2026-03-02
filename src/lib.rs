//! DropCtl - Secure peer-to-peer file transfer
//! 
//! A fast, secure CLI tool for transferring files between hosts using
//! X25519 key exchange and ChaCha20-Poly1305 encryption.

pub mod crypto;
pub mod protocol;
pub mod transfer;
pub mod config;

pub use crypto::{KeyPair, load_or_generate_keypair, KnownHost};
pub use crypto::session::{handshake_initiator, handshake_responder, SecureSession};
pub use protocol::{Message, Handshake};

#[cfg(test)]
mod tests {
    use crate::crypto::{KeyPair, derive_session_key};
    use crate::protocol::{Message, serialize_message, parse_message};
    
    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        let serialized = kp.serialize_public();
        let (verify, x25519) = KeyPair::deserialize_public(&serialized).unwrap();
        
        assert_eq!(verify, *kp.identity());
        assert_eq!(x25519, *kp.public_key());
    }
    
    #[test]
    fn test_key_derivation() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        
        let secret_alice = alice.derive_shared_secret(bob.public_key());
        let secret_bob = bob.derive_shared_secret(alice.public_key());
        
        assert_eq!(secret_alice, secret_bob);
    }
    
    #[test]
    fn test_session_keys_directional() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        
        let shared = alice.derive_shared_secret(bob.public_key());
        
        // Alice is initiator (true), Bob is responder (false)
        let alice_send = derive_session_key(&shared, b"dropctl-send");
        let alice_recv = derive_session_key(&shared, b"dropctl-recv");
        
        let bob_send = derive_session_key(&shared, b"dropctl-send");
        let bob_recv = derive_session_key(&shared, b"dropctl-recv");
        
        // Both derive the same keys from same shared secret with same labels
        assert_eq!(alice_send, bob_send);
        assert_eq!(alice_recv, bob_recv);
    }
    
    #[test]
    fn test_message_serialization() {
        let msg = Message::SendFile {
            name: "test.txt".to_string(),
            size: 1024,
            mime_type: Some("text/plain".to_string()),
        };
        
        let data = serialize_message(&msg).unwrap();
        let parsed = parse_message(&data).unwrap();
        
        match parsed {
            Message::SendFile { name, size, mime_type } => {
                assert_eq!(name, "test.txt");
                assert_eq!(size, 1024);
                assert_eq!(mime_type, Some("text/plain".to_string()));
            }
            _ => panic!("Expected SendFile"),
        }
    }
    
    #[test]
    fn test_handshake_messages() {
        let hello = Message::Ping;
        let data = serialize_message(&hello).unwrap();
        let parsed = parse_message(&data).unwrap();
        
        assert!(matches!(parsed, Message::Ping));
        
        let pong = Message::Pong;
        let data = serialize_message(&pong).unwrap();
        let parsed = parse_message(&data).unwrap();
        
        assert!(matches!(parsed, Message::Pong));
    }
    
    #[test]
    fn test_accept_reject_messages() {
        let accept = Message::Accept;
        let data = serialize_message(&accept).unwrap();
        let parsed = parse_message(&data).unwrap();
        
        assert!(matches!(parsed, Message::Accept));
        
        let reject = Message::Reject { reason: "Full disk".to_string() };
        let data = serialize_message(&reject).unwrap();
        let parsed = parse_message(&data).unwrap();
        
        match parsed {
            Message::Reject { reason } => {
                assert_eq!(reason, "Full disk");
            }
            _ => panic!("Expected Reject"),
        }
    }
    
    #[test]
    fn test_done_abort_messages() {
        let done = Message::Done;
        let data = serialize_message(&done).unwrap();
        let parsed = parse_message(&data).unwrap();
        
        assert!(matches!(parsed, Message::Done));
        
        let abort = Message::Abort { reason: "Connection lost".to_string() };
        let data = serialize_message(&abort).unwrap();
        let parsed = parse_message(&data).unwrap();
        
        assert!(matches!(parsed, Message::Abort { .. }));
    }
}
