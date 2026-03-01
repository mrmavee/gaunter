//! HTML template rendering.
//!
//! Provides functions to generate WAF-related HTML pages and manage templates.

use std::fs;
use std::path::Path;
use tracing::error;

use crate::config::Config;
use crate::security::captcha::generator::CharPosition;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, OnceLock};

const TEMPLATE_DIR: &str = "templates";
static TEMPLATES: OnceLock<HashMap<String, Arc<str>>> = OnceLock::new();

fn render_template(template: &str, vars: &[(&str, &str)]) -> String {
    let map: HashMap<&str, &str> = vars.iter().copied().collect();
    let mut result = String::with_capacity(template.len() + 256);
    let mut remaining = template;
    while let Some(start) = remaining.find("{{") {
        result.push_str(&remaining[..start]);
        if let Some(end) = remaining[start + 2..].find("}}") {
            let key = &remaining[start + 2..start + 2 + end];
            if let Some(val) = map.get(key) {
                result.push_str(val);
            }
            remaining = &remaining[start + 2 + end + 2..];
        } else {
            result.push_str(&remaining[start..]);
            remaining = "";
        }
    }
    result.push_str(remaining);
    result
}

/// Preloads HTML templates into memory.
pub fn preload_templates() {
    let _ = template_map();
}

fn template_map() -> &'static HashMap<String, Arc<str>> {
    TEMPLATES.get_or_init(|| {
        let mut m = HashMap::new();
        for name in &["queue.html", "captcha.html", "error.html", "access.html"] {
            let path = Path::new(TEMPLATE_DIR).join(name);
            match fs::read_to_string(&path) {
                Ok(content) => {
                    m.insert(name.to_string(), Arc::from(content));
                }
                Err(e) => {
                    error!(file = name, error = %e, "failed to load ui template: {name}");
                }
            }
        }
        m
    })
}

fn load_template(filename: &str) -> Option<Arc<str>> {
    template_map().get(filename).cloned()
}

/// Generates the rate limit queue page.
#[must_use]
pub fn queue_page(
    wait_time_secs: u64,
    request_id: &str,
    target_url: &str,
    config: &Config,
) -> String {
    let template = load_template("queue.html")
        .map_or_else(|| {
            format!("<html><head><meta http-equiv='refresh' content='{wait_time_secs}'></head><body><h1>Queue: {wait_time_secs}s</h1></body></html>")
        }, |t: Arc<str>| t.to_string());

    let wait_str = wait_time_secs.to_string();
    render_template(
        &template,
        &[
            ("WAIT_TIME", &wait_str),
            ("TARGET_URL", target_url),
            ("REQUEST_ID", request_id),
            ("CIRCUIT_ID", request_id),
            ("APP_NAME", &config.meta.app_name),
            ("FAVICON", &config.meta.favicon_base64),
            ("META_TITLE", &config.meta.title),
            ("META_DESCRIPTION", &config.meta.description),
            ("META_KEYWORDS", &config.meta.keywords),
        ],
    )
}

/// Generates the CAPTCHA challenge page.
#[must_use]
pub fn captcha_page(
    s: &str,
    img_b64: &str,
    ttl_secs: u64,
    show_error: bool,
    positions: &[CharPosition],
    config: &Config,
) -> String {
    let template = load_template("captcha.html").map_or_else(
        || "<html><body><h1>Security Check Error</h1></body></html>".to_string(),
        |t: Arc<str>| t.to_string(),
    );

    let ttl_display = if ttl_secs >= 60 {
        format!("{} minutes", ttl_secs / 60)
    } else {
        format!("{ttl_secs} seconds")
    };

    let error_html = if show_error {
        r#"<div class="err">Incorrect code. Please try again.</div>"#
    } else {
        ""
    };

    let mut captcha_css = String::from("<style>\n");
    for (i, pos) in positions.iter().enumerate() {
        let css_x = 12.00 - pos.x;
        let css_y = 4.00 - pos.y;
        let _ = writeln!(
            captcha_css,
            "input[name=c{}]:focus ~ .image {{ background-position: {:.2}px {:.2}px; transform: rotate({:.2}deg) scale(6) !important; }}",
            i + 1,
            css_x,
            css_y,
            -pos.rotation
        );
    }
    captcha_css.push_str("</style>");

    let inputs_html = r#"
        <input class="ch" type="text" name="c1" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off" autofocus>
        <input class="ch" type="text" name="c2" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
        <input class="ch" type="text" name="c3" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
        <input class="ch" type="text" name="c4" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
        <input class="ch" type="text" name="c5" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
        <input class="ch" type="text" name="c6" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">
    "#;

    render_template(
        &template,
        &[
            ("STATE_TOKEN", s),
            ("CAPTCHA_IMAGE", img_b64),
            ("TTL_DISPLAY", &ttl_display),
            ("ERROR_MESSAGE", error_html),
            ("CAPTCHA_INPUTS", inputs_html),
            ("CAPTCHA_CSS", &captcha_css),
            ("APP_NAME", &config.meta.app_name),
            ("FAVICON", &config.meta.favicon_base64),
            ("META_TITLE", &config.meta.title),
            ("META_DESCRIPTION", &config.meta.description),
            ("META_KEYWORDS", &config.meta.keywords),
        ],
    )
}

/// Generates a generic error page.
#[must_use]
pub fn error_page(
    title: &str,
    description: &str,
    details: Option<Vec<(&str, &str)>>,
    config: Option<&Config>,
) -> String {
    let template = load_template("error.html").map_or_else(|| {
        format!(
            "<html><head><title>{title}</title></head><body><h1>{title}</h1><p>{description}</p></body></html>"
        )
    }, |t: Arc<str>| t.to_string());

    let mut details_html = String::new();
    let dets = details.unwrap_or_else(|| vec![("Status", "Service Unavailable")]);

    for (k, v) in dets {
        let _ = write!(
            details_html,
            "<div class=\"meta-row\"><span class=\"label\">{k}</span><span class=\"value\">{v}</span></div>"
        );
    }

    render_template(
        &template,
        &[
            ("TITLE", title),
            ("DESCRIPTION", description),
            ("DETAILS", &details_html),
            ("APP_NAME", config.map_or("", |c| c.meta.app_name.as_str())),
            (
                "FAVICON",
                config.map_or("", |c| c.meta.favicon_base64.as_str()),
            ),
            (
                "META_TITLE",
                config.map_or("Error", |c| c.meta.title.as_str()),
            ),
            (
                "META_DESCRIPTION",
                config.map_or("", |c| c.meta.description.as_str()),
            ),
            (
                "META_KEYWORDS",
                config.map_or("", |c| c.meta.keywords.as_str()),
            ),
        ],
    )
}

/// Generates the access denied block page.
#[must_use]
pub fn block_page(_reason: &str, _request_id: &str, config: &Config) -> String {
    let details = vec![("Reason", "Security Violation")];
    error_page(
        "Bad Request",
        "Violation detected. Your request has been blocked.",
        Some(details),
        Some(config),
    )
}

/// Generates the initial access check page.
#[must_use]
pub fn access_page(s: &str, config: &Config) -> String {
    let template = load_template("access.html").map_or_else(
        || "<html><body><h1>Security Check</h1></body></html>".to_string(),
        |t: Arc<str>| t.to_string(),
    );

    render_template(
        &template,
        &[
            ("STATE_TOKEN", s),
            ("APP_NAME", &config.meta.app_name),
            ("FAVICON", &config.meta.favicon_base64),
            ("META_TITLE", &config.meta.title),
            ("META_DESCRIPTION", &config.meta.description),
            ("META_KEYWORDS", &config.meta.keywords),
        ],
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            meta: crate::config::settings::MetaSettings {
                app_name: "gaunter".to_string(),
                favicon_base64: "data:image/x-icon;base64,AA".to_string(),
                title: "Security Check".to_string(),
                description: "Protected by Gaunter".to_string(),
                keywords: "security,gaunter".to_string(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn rendering() {
        let res = render_template("Hello {{NAME}}!", &[("NAME", "World")]);
        assert_eq!(res, "Hello World!");

        assert!(render_template("", &[("key", "val")]).is_empty());

        let c = cfg();

        let err = error_page("Bad Gateway", "Service unreachable", None, None);
        assert!(err.contains("Bad Gateway"));
        assert!(err.contains("Service unreachable"));

        let blk = block_page("any", "any", &c);
        assert!(blk.contains("Bad Request"));
        assert!(blk.contains("Violation detected."));

        let q = queue_page(30, "circuit_id", "/target", &c);
        assert!(q.contains("30") || q.contains("Queue"));

        let cap = captcha_page("token_id", "data:image/png;base64,A", 300, false, &[], &c);
        assert!(cap.contains("Check"));

        let cap_err = captcha_page("token_id", "data:image/png;base64,B", 300, true, &[], &c);
        assert!(cap_err.contains("Incorrect") || cap_err.contains("err"));

        let pos = vec![CharPosition {
            x: 1.0,
            y: 1.0,
            rotation: 0.0,
        }];
        let cap_p = captcha_page("token_id", "data:image/png;base64,C", 60, false, &pos, &c);
        assert!(cap_p.contains("c1") || cap_p.contains("Check"));

        let acc = access_page("token_id", &c);
        assert!(acc.contains("token_id") || acc.contains("Check"));
    }
}
