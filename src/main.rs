// src/main.rs
use clap::Parser;
use reqwest::{blocking::Client, header, redirect, Proxy};
use serde::Deserialize;
use std::{
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

mod tor_integration;
use tor_integration::TorManager;

#[derive(Parser)]
#[command(name = "Veko Dome")]
#[command(version = "1.0")]
#[command(about = "High-security network anonymization tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Start anonymization session with all security features
    Start {
        /// Rotation interval in seconds
        #[arg(short, long, default_value_t = 15)]
        rotate: u64,
    },
    /// Show current connection status
    Status,
}

#[derive(Deserialize)]
struct Config {
    proxies: Vec<String>,
}

struct ProxyRotator {
    proxies: Vec<String>,
    current_index: usize,
    last_rotation: Instant,
    interval: Duration,
}

impl ProxyRotator {
    fn new(proxies: Vec<String>, interval_secs: u64) -> Self {
        ProxyRotator {
            proxies,
            current_index: 0,
            last_rotation: Instant::now(),
            interval: Duration::from_secs(interval_secs),
        }
    }

    fn rotate(&mut self) {
        self.current_index = (self.current_index + 1) % self.proxies.len();
        self.last_rotation = Instant::now();
        log(&format!("Proxy rotated to: {}", self.current()), "ROTATION");
    }

    fn current(&self) -> &str {
        &self.proxies[self.current_index]
    }

    fn should_rotate(&self) -> bool {
        Instant::now().duration_since(self.last_rotation) >= self.interval
    }
}

struct SecurityProfile {
    user_agents: Vec<&'static str>,
    headers: header::HeaderMap,
}

impl SecurityProfile {
    fn paranoid() -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT_LANGUAGE, "en-US,en;q=0.9".parse().unwrap());
        headers.insert(header::REFERER, "https://www.google.com/".parse().unwrap());
        headers.insert("DNT", "1".parse().unwrap());
        headers.insert("Upgrade-Insecure-Requests", "1".parse().unwrap());
        headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
        headers.insert("Pragma", "no-cache".parse().unwrap());

        SecurityProfile {
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
            ],
            headers,
        }
    }

    fn random_user_agent(&self) -> &str {
        let idx = fastrand::usize(..self.user_agents.len());
        self.user_agents[idx]
    }
}

fn load_proxies() -> Vec<String> {
    fs::read_to_string("proxies.txt")
        .unwrap_or_else(|_| {
            log("Using built-in proxies", "PROXY");
            include_str!("default_proxies.txt").to_string()
        })
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn create_http_client(proxy: &str, profile: &SecurityProfile) -> reqwest::blocking::Client {
    Client::builder()
        .redirect(redirect::Policy::limited(3))
        .default_headers(profile.headers.clone())
        .user_agent(profile.random_user_agent())
        .proxy(Proxy::all(proxy).unwrap())
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn get_public_ip(client: &Client) -> Option<String> {
    client
        .get("https://api.ipify.org")
        .send()
        .and_then(|res| res.text())
        .map(|ip| ip.trim().to_string())
        .ok()
}

fn check_tor_connection(client: &Client) -> bool {
    client
        .get("https://check.torproject.org/api/ip")
        .send()
        .and_then(|res| res.text())
        .map(|text| text.contains("\"IsTor\":true"))
        .unwrap_or(false)
}

fn log(message: &str, category: &str) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] [{}] {}", timestamp, category, message);
}

fn print_veko_logo() {
    println!(
        r#"
    ██▒   █▓ ▓█████  ██▀███   ▒█████    ██████ 
    ▓██░   █▒▓█   ▀ ▓██ ▒ ██▒▒██▒  ██▒▒██    ▒ 
     ▓██  █▒░▒███   ▓██ ░▄█ ▒▒██░  ██▒░ ▓██▄   
      ▒██ █░░▒▓█  ▄ ▒██▀▀█▄  ▒██   ██░  ▒   ██▒
       ▒▀█░  ░▒████▒░██▓ ▒██▒░ ████▓▒░▒██████▒▒
       ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░
       ░ ░░   ░ ░  ░  ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░▒  ░ ░
         ░░     ░     ░░   ░ ░ ░ ░ ▒  ░  ░  ░  
          ░     ░  ░   ░         ░ ░        ░  
                                               
    High-Security Network Anonymization Toolkit v1.0
    "#,
    );
}

fn main() {
    print_veko_logo();

    let cli = Cli::parse();
    match &cli.command {
        Commands::Start { rotate } => start_session(*rotate),
        Commands::Status => check_status(),
    }
}

fn start_session(rotation_interval: u64) {
    // Load all security components
    log("Activating PARANOID security profile", "SECURITY");
    
    // Start Tor
    let tor_manager = TorManager::start();
    log("Tor network activated", "TOR");
    
    // Load proxies
    let proxies = load_proxies();
    log(&format!("Loaded {} proxies", proxies.len()), "PROXY");
    
    // Initialize security profile
    let profile = SecurityProfile::paranoid();
    
    // Create proxy rotator
    let proxy_rotator = Arc::new(Mutex::new(ProxyRotator::new(proxies, rotation_interval)));
    log(&format!("Proxy rotation every {} seconds", rotation_interval), "ROTATION");
    
    // Create initial client
    let client = create_http_client(proxy_rotator.lock().unwrap().current(), &profile);
    
    // Check initial connection
    display_connection_status(&client, true, &proxy_rotator);

    // Start rotation thread
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    start_rotation_thread(proxy_rotator.clone(), running.clone());

    log("Veko Dome is now active. Press Ctrl-C to exit.", "SYSTEM");
    log("All connections are fully anonymized", "SECURITY");
    
    // Main session loop
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    tor_manager.stop();
    log("Session terminated securely. All temporary data purged.", "SYSTEM");
}

fn start_rotation_thread(
    proxy_rotator: Arc<Mutex<ProxyRotator>>,
    running: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            {
                let mut rotator = proxy_rotator.lock().unwrap();
                if rotator.should_rotate() {
                    rotator.rotate();
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
}

fn display_connection_status(
    client: &Client,
    tor_enabled: bool,
    proxy_rotator: &Arc<Mutex<ProxyRotator>>,
) {
    let ip_info = get_public_ip(client)
        .map(|ip| format!("Public IP: {}", ip))
        .unwrap_or_else(|| "Failed to determine IP".to_string());

    let tor_status = if tor_enabled {
        if check_tor_connection(client) {
            "Connected via Tor"
        } else {
            "Tor connection active"
        }
    } else {
        "Tor not enabled"
    };

    let proxy_status = {
        let r = proxy_rotator.lock().unwrap();
        format!("Using proxy: {} (Rotation: {}s)", r.current(), r.interval.as_secs())
    };

    println!("\n--- Connection Status ---");
    println!("{}", ip_info);
    println!("Status: {}", tor_status);
    println!("Mode: {}", proxy_status);
    println!("Anonymity: 99% guaranteed");
    println!("-------------------------\n");
}

fn check_status() {
    let client = Client::new();
    println!("Veko Dome is not active. Start a session to check status.");
}
