#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
#![warn(clippy::panic_in_result_fn)]
#![warn(clippy::indexing_slicing)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::ref_patterns)]
#![warn(clippy::unused_result_ok)]
#![warn(clippy::clone_on_ref_ptr)]

//! `Gaunter` application entry point.
//!
//! Copyright (C) 2026 Maverick
//! SPDX-License-Identifier: AGPL-3.0-only
//!
//! Orchestrates service initialization, logging, and background workers.

use gaunter::{
    CaptchaManager, Config, DefenseMonitor, GaunterProxy, ProxyProtocolConfig, RateLimiter,
    TorObserver, WafEngine, WebhookNotifier, preload_templates, run_proxy_listener,
};

use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());
    let log_format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string());

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,pingora=warn")),
        )
        .with_writer(non_blocking);

    if log_format.eq_ignore_ascii_case("pretty") {
        subscriber.init();
    } else {
        subscriber.json().init();
    }
    guard
}

fn spawn_background(
    config: Arc<gaunter::Config>,
    defense_monitor: Arc<DefenseMonitor>,
    protocol_config: ProxyProtocolConfig,
) {
    let defense_monitor_bg = Arc::clone(&defense_monitor);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| {
            error!("Failed to create tokio runtime: {e}");
            std::process::exit(1);
        });

        rt.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                defense_monitor_bg.tick();
            }
        });

        if let Some(addr) = config.tor.control_addr {
            let observer =
                TorObserver::new(addr, config.tor.control_password.clone(), defense_monitor);
            rt.spawn(async move { observer.run().await });
        }

        if let Err(e) = rt.block_on(run_proxy_listener(protocol_config)) {
            error!("fatal: proxy listener error: {e}");
            std::process::exit(1);
        }
    });
}

#[allow(clippy::print_stdout)]
fn print_banner() {
    let banner = r"
 ██████╗  █████╗ ██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝ ██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

        Hidden Service Reverse Proxy & Web Application Firewall
";
    println!("\x1b[1;36m{banner}\x1b[0m");
}

fn main() {
    print_banner();
    let _ = dotenvy::dotenv();
    let _log_guard = init_logging();

    let config = Config::from_env().unwrap_or_else(|e| {
        error!("Failed to load configuration: {e}");
        std::process::exit(1);
    });
    preload_templates();
    info!(
        listen_addr = %config.network.listen_addr,
        internal_addr = %config.network.internal_addr,
        backend_url = %config.network.backend_url,
        waf_mode = ?config.security.waf_mode,
        log_format = %config.log_format,
        "server ready"
    );

    let rate_limiter = RateLimiter::new(
        config.defense.rate_limit_rps,
        config.defense.rate_limit_burst,
    );
    let session_rate_limiter = RateLimiter::new(
        config.session.rate_limit_rps,
        config.session.rate_limit_burst,
    );

    let defense_monitor = Arc::new(DefenseMonitor::new(Arc::clone(&config)));
    let webhook_notifier = Arc::new(WebhookNotifier::new(&config));
    let captcha_manager = Arc::new(CaptchaManager::try_new(&config).unwrap_or_else(|e| {
        error!("Failed to initialize CaptchaManager: {e}");
        std::process::exit(1);
    }));
    captcha_manager.start_worker();
    let waf_engine = Arc::new(
        WafEngine::try_new(
            Arc::clone(&webhook_notifier),
            config.security.ssrf_allowed_hosts.clone(),
        )
        .unwrap_or_else(|e| {
            error!("Failed to initialize WafEngine: {e}");
            std::process::exit(1);
        }),
    );

    let mut server = Server::new(None).unwrap_or_else(|_| {
        error!("Failed to create Pingora server");
        std::process::exit(1);
    });
    server.bootstrap();

    let proxy = GaunterProxy::new(
        Arc::clone(&config),
        rate_limiter,
        session_rate_limiter,
        Arc::clone(&defense_monitor),
        webhook_notifier,
        captcha_manager,
        waf_engine,
    );

    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.network.internal_addr.to_string());
    server.add_service(proxy_service);

    let protocol_config = ProxyProtocolConfig {
        listen_addr: config.network.listen_addr,
        internal_addr: config.network.internal_addr,
        circuit_prefix: config.tor.circuit_prefix.clone(),
        concurrency_limit: config.network.concurrency_limit,
        defense_monitor: Some(Arc::clone(&defense_monitor)),
    };

    spawn_background(config, defense_monitor, protocol_config);

    server.run_forever();
}
