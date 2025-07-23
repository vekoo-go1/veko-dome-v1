// src/tor_integration.rs
use std::{
    process::{Command, Stdio},
    thread,
    time::Duration,
};

pub struct TorManager {
    process: Option<std::process::Child>,
}

impl TorManager {
    pub fn start() -> Self {
        log::info!("Starting Tor service...");
        let process = Command::new("tor")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start Tor. Make sure Tor is installed.");

        thread::sleep(Duration::from_secs(2));
        TorManager {
            process: Some(process),
        }
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            child.kill().expect("Failed to stop Tor process");
            child.wait().ok();
            log::info!("Tor service stopped");
        }
    }
}

impl Drop for TorManager {
    fn drop(&mut self) {
        self.stop();
    }
}
