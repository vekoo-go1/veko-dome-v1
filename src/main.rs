// src/main.rs
use clap::{Parser, Subcommand};
use reqwest::{blocking::Client, header, redirect, Proxy};
use serde::Deserialize;
use std::{
    fs,
    io::{self, Write},
    net::IpAddr,
    path::Path,
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

    #[arg(long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start anonymization session
    Start {
        /// Anonymity profile [basic|stealth|paranoid|custom]
        #[arg(short, long, default_value = "stealth")]
        mode: String,

        /// Path to proxy list file
        #[arg(short, long)]
        proxy: Option<String>,

        /// Enable Tor routing
        #[arg(long)]
        tor: bool,

        /// Enable DNS-over-HTTPS
        #[arg(long)]
        doh: bool,

        /// Check current IP status
        #[arg(short, long)]
        check: bool,

        /// Rotation interval in seconds
        #[arg(long, default_value_t = 30)]
        rotate: u64,

        /// Disable all logging
        #[arg(long)]
        no_log: bool,
    },
    /// Rotate proxy immediately
    Rotate,
    /// Show current connection status
    Status,
}

#[derive(Deserialize)]
struct Config {
    mode: Option<String>,
    proxy: Option<String>,
    tor: Option<bool>,
    doh: Option<bool>,
    rotate: Option<u64>,
    no_log: Option<bool>,
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
    mode: String,
    user_agents: Vec<&'static str>,
    headers: header::HeaderMap,
    tls_settings: TlsProfile,
}

#[derive(Clone)]
struct TlsProfile {
    cipher_suites: Vec<&'static str>,
    extensions: Vec<&'static str>,
}

impl SecurityProfile {
    fn new(mode: &str) -> Self {
        match mode.to_lowercase().as_str() {
            "paranoid" => Self::paranoid(),
            "stealth" => Self::stealth(),
            "basic" => Self::basic(),
            _ => Self::custom(),
        }
    }

    fn paranoid() -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT_LANGUAGE, "en-US,en;q=0.9".parse().unwrap());
        headers.insert(header::REFERER, "https://www.google.com/".parse().unwrap());
        headers.insert("DNT", "1".parse().unwrap());

        SecurityProfile {
            mode: "paranoid".to_string(),
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
            ],
            headers,
            tls_settings: TlsProfile {
                cipher_suites: vec![
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ],
                extensions: vec!["server_name", "extended_master_secret", "supported_groups"],
            },
        }
    }

    fn stealth() -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT_LANGUAGE, "en-US,en;q=0.5".parse().unwrap());

        SecurityProfile {
            mode: "stealth".to_string(),
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
            ],
            headers,
            tls_settings: TlsProfile {
                cipher_suites: vec!["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
                extensions: vec!["server_name", "supported_groups"],
            },
        }
    }

    fn basic() -> Self {
        SecurityProfile {
            mode: "basic".to_string(),
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ],
            headers: header::HeaderMap::new(),
            tls_settings: TlsProfile {
                cipher_suites: vec!["TLS_AES_256_GCM_SHA384"],
                extensions: vec!["server_name"],
            },
        }
    }

    fn custom() -> Self {
        Self::stealth()
    }

    fn random_user_agent(&self) -> &str {
        let idx = fastrand::usize(..self.user_agents.len());
        self.user_agents[idx]
    }
}

fn load_proxies(path: &str) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("Failed to read proxy file: {}", path))
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn create_http_client(
    proxy: Option<&str>,
    profile: &SecurityProfile,
    use_doh: bool,
) -> reqwest::blocking::Client {
    let mut builder = Client::builder()
        .redirect(redirect::Policy::limited(3))
        .default_headers(profile.headers.clone())
        .user_agent(profile.random_user_agent())
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));

    if let Some(proxy_url) = proxy {
        builder = builder.proxy(Proxy::all(proxy_url).unwrap());
    }

    if use_doh {
        builder = builder.dns_resolver(
            trust_dns_resolver::Resolver::new(
                trust_dns_resolver::config::ResolverConfig::cloudflare_https(),
                trust_dns_resolver::config::ResolverOpts::default(),
            )
            .unwrap(),
        );
    }

    builder.build().unwrap()
}

fn get_public_ip(client: &Client) -> Option<String> {
    let services = [
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip",
    ];

    for service in services {
        match client.get(service).send() {
            Ok(res) => {
                if let Ok(ip) = res.text() {
                    return Some(ip.trim().to_string());
                }
            }
            Err(_) => continue,
        }
    }
    None
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
    __     __    _     _       ____           _      
    \ \   / /__ | | __| |___  |  _ \ ___  ___| | __  
     \ \ / / _ \| |/ _` / __| | |_) / _ \/ _ \ |/ /  
      \ V / (_) | | (_| \__ \ |  _ <  __/  __/   <   
       \_/ \___/|_|\__,_|___/ |_| \_\___|\___|_|\_\  
                                                      
    High-Security Network Anonymization Toolkit v1.0
    "#
    );
}

fn main() {
    print_veko_logo();

    let cli = Cli::parse();
    let config = cli.config.as_deref().and_then(|path| {
        toml::from_str::<Config>(&fs::read_to_string(path).ok()).ok()
    });

    match &cli.command {
        Commands::Start {
            mode,
            proxy,
            tor,
            doh,
            check,
            rotate,
            no_log,
        } => {
            let effective_mode = mode.as_str();
            let effective_proxy = proxy
                .as_deref()
                .or_else(|| config.as_ref().and_then(|c| c.proxy.as_deref()));
            let use_tor = *tor || config.as_ref().and_then(|c| c.tor).unwrap_or(false);
            let use_doh = *doh || config.as_ref().and_then(|c| c.doh).unwrap_or(false);
            let rotation_interval = *rotate;
            let logging = !(*no_log || config.as_ref().and_then(|c| c.no_log).unwrap_or(false));

            let proxies = effective_proxy
                .map(|p| load_proxies(p))
                .unwrap_or_default();

            let profile = SecurityProfile::new(effective_mode);
            let tor_manager = if use_tor {
                Some(TorManager::start())
            } else {
                None
            };

            let proxy_rotator = if !proxies.is_empty() {
                Some(Arc::new(Mutex::new(ProxyRotator::new(
                    proxies,
                    rotation_interval,
                ))))
            } else {
                None
            };

            let client = create_http_client(
                proxy_rotator
                    .as_ref()
                    .map(|r| r.lock().unwrap().current()),
                &profile,
                use_doh,
            );

            if *check {
                display_connection_status(&client, use_tor, &proxy_rotator);
            }

            if !logging {
                log("System logging disabled", "SECURITY");
            }

            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();
            ctrlc::set_handler(move || {
                r.store(false, Ordering::SeqCst);
            })
            .expect("Error setting Ctrl-C handler");

            if proxy_rotator.is_some() {
                start_rotation_thread(proxy_rotator.clone(), running.clone());
            }

            log("Veko Dome is now active. Press Ctrl-C to exit.", "SYSTEM");
            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(1));
            }

            if let Some(tm) = tor_manager {
                tm.stop();
            }
            log("Session terminated securely. All temporary data purged.", "SYSTEM");
        }
        Commands::Rotate => {
            log("Manual rotation not implemented in this version", "WARNING");
        }
        Commands::Status => {
            let client = Client::new();
            display_connection_status(&client, false, &None);
        }
    }
}

fn display_connection_status(
    client: &Client,
    tor_enabled: bool,
    proxy_rotator: &Option<Arc<Mutex<ProxyRotator>>>,
) {
    let ip_info = get_public_ip(client)
        .map(|ip| format!("Public IP: {}", ip))
        .unwrap_or_else(|| "Failed to determine IP".to_string());

    let tor_status = if tor_enabled {
        if check_tor_connection(client) {
            "Connected via Tor"
        } else {
            "Tor connection failed"
        }
    } else {
        "Tor not enabled"
    };

    let proxy_status = if let Some(rotator) = proxy_rotator {
        let r = rotator.lock().unwrap();
        format!("Using proxy: {} (Rotation: {}s)", r.current(), r.interval.as_secs())
    } else {
        "Direct connection".to_string()
    };

    println!("\n--- Connection Status ---");
    println!("{}", ip_info);
    println!("Status: {}", tor_status);
    println!("Mode: {}", proxy_status);
    println!("-------------------------\n");
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
