// src/tor_integration.rs
use std::{
    io,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

pub struct TorManager;

impl TorManager {
    pub fn start() -> Self {
        // Start Tor in the background
        Command::new("tor")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start Tor. Make sure Tor is installed.");

        // Wait for Tor to initialize
        thread::sleep(Duration::from_secs(3));
        log::info!("Tor service started");
        TorManager
    }

    pub fn stop(&self) {
        // Gracefully stop Tor
        Command::new("pkill")
            .arg("tor")
            .output()
            .expect("Failed to stop Tor");
        log::info!("Tor service stopped");
    }
}
