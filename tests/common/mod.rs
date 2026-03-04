#![allow(dead_code)]
use std::collections::HashSet;
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use gaunter::{
    CaptchaManager, Config, DefenseMonitor, GaunterProxy, ProxyProtocolConfig, RateLimiter,
    WafEngine, WebhookNotifier, run_proxy_listener,
};
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as TokioTcpListener;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

pub fn new_config(backend_url: Option<&str>, waf_mode: Option<&str>) -> Arc<Config> {
    unsafe {
        std::env::set_var(
            "BACKEND_URL",
            backend_url.unwrap_or("http://127.0.0.1:9999"),
        );
        std::env::set_var("WAF_MODE", waf_mode.unwrap_or("NORMAL"));
        std::env::set_var("TOR_CIRCUIT_PREFIX", "fd87:d87e:eb43");
        std::env::set_var("CAPTCHA_SECRET", "captcha_master_key_v1");
        std::env::set_var("SESSION_SECRET", "session_master_key_v1");
        std::env::set_var("APP_NAME", "gaunter");
        std::env::set_var("DEFENSE_ERROR_RATE_THRESHOLD", "0.5");
        std::env::set_var("DEFENSE_CIRCUIT_FLOOD_THRESHOLD", "5");
        std::env::set_var("RATE_LIMIT_RPS", "100");
        std::env::set_var("RATE_LIMIT_BURST", "200");
        std::env::set_var("KARMA_THRESHOLD", "50");
        std::env::set_var("RESTRICTED_PATHS", "");
        std::env::set_var("CAPTCHA_ENABLED", "true");
        std::env::set_var("WAF_BODY_SCAN_ENABLED", "true");
        std::env::set_var("CAPTCHA_GEN_LIMIT", "3");
    }
    Config::from_env().unwrap()
}

pub fn base_config() -> Arc<Config> {
    let _lock = ENV_MUTEX.lock().unwrap();
    new_config(None, None)
}

pub fn base_waf() -> WafEngine {
    let config = base_config();
    let webhook = Arc::new(WebhookNotifier::new(&config));
    WafEngine::try_new(webhook, vec![]).unwrap()
}

pub fn base_defense() -> (Arc<Config>, Arc<DefenseMonitor>) {
    let config = base_config();
    let monitor = Arc::new(DefenseMonitor::new(config.clone()));
    (config, monitor)
}

pub fn default_restricted_paths() -> HashSet<String> {
    [
        "/.env",
        "/.git",
        "/.git/HEAD",
        "/.git/config",
        "/.aws",
        "/.aws/credentials",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/config.php",
        "/.htaccess",
        "/.htpasswd",
        "/backup.sql",
        "/database.sql",
        "/.vscode",
        "/.idea",
        "/node_modules",
        "/vendor",
        "/.svn",
        "/.hg",
        "/server-status",
        "/server-info",
        "/.DS_Store",
        "/Thumbs.db",
        "/web.config",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/elmah.axd",
        "/trace.axd",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

fn wait_for_port(addr: &str) {
    for _ in 0..50 {
        if StdTcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(50)).is_ok()
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn spawn_mock_backend() -> String {
    let std_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap().to_string();
    std_listener.set_nonblocking(true).unwrap();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listener = TokioTcpListener::from_std(std_listener).unwrap();
            loop {
                if let Ok((mut socket, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0; 1024];
                        let _ = socket.read(&mut buf).await;
                        let response =
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                        let _ = socket.write_all(response.as_bytes()).await;
                    });
                }
            }
        });
    });

    wait_for_port(&addr);
    addr
}

pub fn spawn_proxy_server(backend_addr: &str) -> String {
    spawn_proxy_mode(backend_addr, None)
}

pub fn spawn_proxy_limited(backend_addr: &str) -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let addr = format!("127.0.0.1:{port}");
    let addr_cl = addr.clone();

    let backend_url = format!("http://{backend_addr}");
    let config = {
        let _lock = ENV_MUTEX.lock().unwrap();
        new_config(Some(&backend_url), None)
    };

    thread::spawn(move || {
        let rate_limiter = RateLimiter::new(10, 20);
        let session_limiter = RateLimiter::new(10, 20);
        let defense = Arc::new(DefenseMonitor::new(config.clone()));
        let webhook = Arc::new(WebhookNotifier::new(&config));
        let captcha = Arc::new(CaptchaManager::try_new(&config).unwrap());
        let waf = Arc::new(WafEngine::try_new(webhook.clone(), vec![]).unwrap());

        let proxy = GaunterProxy::new(
            config,
            rate_limiter,
            session_limiter,
            defense,
            webhook,
            captcha,
            waf,
        );

        let mut server = Server::new(None).unwrap();
        server.bootstrap();
        let mut service = http_proxy_service(&server.configuration, proxy);
        service.add_tcp(&addr_cl);
        server.add_service(service);
        server.run_forever();
    });

    wait_for_port(&addr);
    addr
}

pub fn spawn_no_captcha(backend_addr: &str) -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let addr = format!("127.0.0.1:{port}");
    let addr_cl = addr.clone();

    let backend_url = format!("http://{backend_addr}");
    let config = {
        let _lock = ENV_MUTEX.lock().unwrap();
        unsafe {
            std::env::set_var("BACKEND_URL", &backend_url);
            std::env::set_var("WAF_MODE", "DEFENSE");
            std::env::set_var("CAPTCHA_ENABLED", "false");
            std::env::set_var("TOR_CIRCUIT_PREFIX", "fd87:d87e:eb43");
            std::env::set_var("CAPTCHA_SECRET", "captcha_master_key_v1");
            std::env::set_var("SESSION_SECRET", "session_master_key_v1");
            std::env::set_var("APP_NAME", "gaunter");
            std::env::set_var("DEFENSE_ERROR_RATE_THRESHOLD", "0.5");
            std::env::set_var("DEFENSE_CIRCUIT_FLOOD_THRESHOLD", "5");
            std::env::set_var("RATE_LIMIT_RPS", "100");
            std::env::set_var("RATE_LIMIT_BURST", "200");
            std::env::set_var("KARMA_THRESHOLD", "50");
            std::env::set_var("CAPTCHA_GEN_LIMIT", "3");
        }
        Config::from_env().unwrap()
    };

    thread::spawn(move || {
        let rate_limiter = RateLimiter::new(1000, 2000);
        let session_limiter = RateLimiter::new(1000, 2000);
        let defense = Arc::new(DefenseMonitor::new(config.clone()));
        let webhook = Arc::new(WebhookNotifier::new(&config));
        let captcha = Arc::new(CaptchaManager::try_new(&config).unwrap());
        let waf = Arc::new(WafEngine::try_new(webhook.clone(), vec![]).unwrap());

        let proxy = GaunterProxy::new(
            config,
            rate_limiter,
            session_limiter,
            defense,
            webhook,
            captcha,
            waf,
        );

        let mut server = Server::new(None).unwrap();
        server.bootstrap();
        let mut service = http_proxy_service(&server.configuration, proxy);
        service.add_tcp(&addr_cl);
        server.add_service(service);
        server.run_forever();
    });

    wait_for_port(&addr);
    addr
}

pub fn spawn_proxy_mode(backend_addr: &str, waf_mode: Option<&str>) -> String {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let addr = format!("127.0.0.1:{port}");
    let addr_cl = addr.clone();

    let backend_url = format!("http://{backend_addr}");
    let config = {
        let _lock = ENV_MUTEX.lock().unwrap();
        new_config(Some(&backend_url), waf_mode)
    };

    thread::spawn(move || {
        let rate_limiter = RateLimiter::new(
            config.defense.rate_limit_rps,
            config.defense.rate_limit_burst,
        );
        let session_limiter = RateLimiter::new(
            config.session.rate_limit_rps,
            config.session.rate_limit_burst,
        );
        let defense = Arc::new(DefenseMonitor::new(config.clone()));
        let webhook = Arc::new(WebhookNotifier::new(&config));
        let captcha = Arc::new(CaptchaManager::try_new(&config).unwrap());
        let waf = Arc::new(WafEngine::try_new(webhook.clone(), vec![]).unwrap());

        let proxy = GaunterProxy::new(
            config,
            rate_limiter,
            session_limiter,
            defense,
            webhook,
            captcha,
            waf,
        );

        let mut server = Server::new(None).unwrap();
        server.bootstrap();

        let mut service = http_proxy_service(&server.configuration, proxy);
        service.add_tcp(&addr_cl);
        server.add_service(service);
        server.run_forever();
    });

    wait_for_port(&addr);
    addr
}

pub fn spawn_stack(backend_addr: &str) -> (String, Arc<DefenseMonitor>) {
    spawn_stack_mode(backend_addr, None)
}

pub fn spawn_stack_mode(
    backend_addr: &str,
    waf_mode: Option<&str>,
) -> (String, Arc<DefenseMonitor>) {
    let pingora_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let pingora_port = pingora_listener.local_addr().unwrap().port();
    drop(pingora_listener);

    let protocol_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let protocol_port = protocol_listener.local_addr().unwrap().port();
    drop(protocol_listener);

    let backend_url = format!("http://{backend_addr}");
    let internal_addr: SocketAddr = format!("127.0.0.1:{pingora_port}").parse().unwrap();
    let listen_addr: SocketAddr = format!("127.0.0.1:{protocol_port}").parse().unwrap();
    let listen_str = listen_addr.to_string();

    let config = {
        let _lock = ENV_MUTEX.lock().unwrap();
        new_config(Some(&backend_url), waf_mode)
    };

    let defense = Arc::new(DefenseMonitor::new(config.clone()));
    let defense_cl = defense.clone();

    thread::spawn(move || {
        let rate_limiter = RateLimiter::new(1000, 2000);
        let session_limiter = RateLimiter::new(1000, 2000);
        let webhook = Arc::new(WebhookNotifier::new(&config));
        let captcha = Arc::new(CaptchaManager::try_new(&config).unwrap());
        let waf = Arc::new(WafEngine::try_new(webhook.clone(), vec![]).unwrap());

        let proxy = GaunterProxy::new(
            config,
            rate_limiter,
            session_limiter,
            defense_cl.clone(),
            webhook,
            captcha,
            waf,
        );

        let mut server = Server::new(None).unwrap();
        server.bootstrap();

        let mut service = http_proxy_service(&server.configuration, proxy);
        service.add_tcp(&internal_addr.to_string());
        server.add_service(service);

        let protocol_config = ProxyProtocolConfig {
            listen_addr,
            internal_addr,
            circuit_prefix: "fd87:d87e:eb43".to_string(),
            concurrency_limit: 1024,
            defense_monitor: Some(defense_cl),
        };

        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let _ = run_proxy_listener(protocol_config).await;
            });
        });

        server.run_forever();
    });

    wait_for_port(&internal_addr.to_string());
    wait_for_port(&listen_str);
    (listen_str, defense)
}

pub fn get_cookie(res: &reqwest::Response) -> String {
    res.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find(|s| s.starts_with("gaunter_session="))
        .and_then(|s| s.split(';').next())
        .unwrap_or_default()
        .to_string()
}
