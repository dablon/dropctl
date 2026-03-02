//! E2E Tests for dropctl
//! 
//! These tests run a full file transfer between two instances.

use std::process::{Command, Child};
use std::time::Duration;
use std::fs;
use std::io::Write;

const TEST_PORT: u16 = 19999;
const TEST_FILE_SIZE: usize = 1024 * 1024; // 1MB

fn start_listener(port: u16, output_dir: &str) -> Child {
    let mut child = Command::new("cargo")
        .args(&["run", "--", "listen", &port.to_string(), "--output", output_dir])
        .spawn()
        .expect("Failed to start listener");
    
    std::thread::sleep(Duration::from_millis(500));
    child
}

fn send_file(port: u16, file_path: &str) -> Child {
    let child = Command::new("cargo")
        .args(&["run", "--", "send", &format!("localhost:{}", port), file_path])
        .spawn()
        .expect("Failed to start sender");
    
    child
}

fn wait_for_child(mut child: Child) -> std::process::Output {
    child.wait().expect("Failed to wait for child")
}

fn create_test_file(path: &str, size: usize) -> Vec<u8> {
    let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    fs::write(path, &data).expect("Failed to create test file");
    data
}

fn calculate_md5(path: &str) -> String {
    let output = Command::new("md5sum")
        .arg(path)
        .output()
        .expect("Failed to run md5sum");
    
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn test_e2e_small_file() {
    let test_file = "/tmp/dropctl_test_small.txt";
    let received_file = "/tmp/dropctl_test_small.txt";
    let content = create_test_file(test_file, 1024); // 1KB
    
    // Start listener
    let mut listener = start_listener(TEST_PORT, "/tmp");
    
    // Send file
    let sender = send_file(TEST_PORT, test_file);
    
    // Wait for both to finish
    let sender_out = wait_for_child(sender);
    let listener_out = wait_for_child(listener);
    
    // Check results
    assert!(sender_out.status.success(), "Sender failed: {:?}", String::from_utf8_lossy(&sender_out.stderr));
    assert!(listener_out.status.success(), "Listener failed: {:?}", String::from_utf8_lossy(&listener_out.stderr));
    
    // Verify file was received
    assert!(fs::metadata(received_file).is_ok(), "Received file doesn't exist");
    
    let received_content = fs::read(received_file).expect("Failed to read received file");
    assert_eq!(content, received_content, "File content mismatch");
    
    // Cleanup
    let _ = fs::remove_file(test_file);
    let _ = fs::remove_file(received_file);
}

#[test]
fn test_e2e_large_file() {
    let test_file = "/tmp/dropctl_test_large.bin";
    let received_file = "/tmp/dropctl_test_large.bin";
    let content = create_test_file(test_file, TEST_FILE_SIZE); // 1MB
    
    // Start listener
    let mut listener = start_listener(TEST_PORT + 1, "/tmp");
    
    // Send file
    let sender = send_file(TEST_PORT + 1, test_file);
    
    // Wait for both to finish
    let sender_out = wait_for_child(sender);
    let listener_out = wait_for_child(listener);
    
    // Check results
    assert!(sender_out.status.success(), "Sender failed: {:?}", String::from_utf8_lossy(&sender_out.stderr));
    assert!(listener_out.status.success(), "Listener failed: {:?}", String::from_utf8_lossy(&listener_out.stderr));
    
    // Verify file was received with correct size
    let metadata = fs::metadata(received_file).expect("Received file doesn't exist");
    assert_eq!(metadata.len(), TEST_FILE_SIZE as u64, "File size mismatch");
    
    // Verify MD5
    let original_md5 = calculate_md5(test_file);
    let received_md5 = calculate_md5(received_file);
    assert_eq!(original_md5, received_md5, "MD5 mismatch");
    
    // Cleanup
    let _ = fs::remove_file(test_file);
    let _ = fs::remove_file(received_file);
}

#[test]
fn test_e2e_key_exchange() {
    // This test verifies that the crypto handshake works
    // by checking that both sides can establish a session
    
    let test_file = "/tmp/dropctl_test_key.txt";
    create_test_file(test_file, 100);
    
    // Start listener
    let mut listener = start_listener(TEST_PORT + 2, "/tmp");
    
    // Send file
    let sender = send_file(TEST_PORT + 2, test_file);
    
    // Wait for both to finish
    let sender_out = wait_for_child(sender);
    let listener_out = wait_for_child(listener);
    
    // Both should succeed
    assert!(sender_out.status.success(), "Sender failed");
    assert!(listener_out.status.success(), "Listener failed");
    
    // Cleanup
    let _ = fs::remove_file(test_file);
    let _ = fs::remove_file("/tmp/dropctl_test_key.txt");
}
