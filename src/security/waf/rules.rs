//! WAF rule engine.
//!
//! Manages literal and regex signatures using Aho-Corasick and `RegexSet`.

use aho_corasick::AhoCorasick;
use percent_encoding::percent_decode_str;
use regex::RegexSet;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tracing::{debug, trace};

use crate::error::{Error, Result};

const BLOCK_SCORE: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Zone {
    Path,
    Query,
    Body,
    Cookie,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,
    pub zones: Vec<Zone>,
    pub scores: Vec<(String, u32)>,
}

#[derive(Clone)]
/// Inner WAF rule evaluation engine.
pub struct RuleEngine {
    literal_rules: Arc<Vec<Rule>>,
    regex_rules: Arc<Vec<Rule>>,
    ac: Arc<AhoCorasick>,
    regex_set: Arc<RegexSet>,
    thresholds: HashMap<String, u32>,
}

#[derive(Debug)]
pub struct EvalResult {
    pub blocked: bool,
    pub scores: HashMap<String, u32>,
    pub matched_rules: Vec<u32>,
}

type CachedRules = (
    Arc<Vec<Rule>>,
    Arc<Vec<Rule>>,
    Arc<AhoCorasick>,
    Arc<RegexSet>,
);

static CACHED_RULES: OnceLock<std::result::Result<CachedRules, String>> = OnceLock::new();

impl RuleEngine {
    /// Instantiates rule engine internal structures.
    ///
    /// # Errors
    /// Returns error if rule compilation fails.
    pub fn try_new() -> Result<Self> {
        let (lit_rules, rx_rules, ac, regex_set) = CACHED_RULES
            .get_or_init(|| {
                let (lit_patterns, lit_rules, rx_patterns, rx_rules) = Self::default_rules();
                debug!(
                    literals = lit_rules.len(),
                    regexes = rx_rules.len(),
                    "rule engine ready"
                );

                let ac = AhoCorasick::new(lit_patterns)
                    .map_err(|e| format!("Failed to build Aho-Corasick automaton: {e}"))?;
                let regex_set = RegexSet::new(rx_patterns)
                    .map_err(|e| format!("Failed to build RegexSet: {e}"))?;

                Ok((
                    Arc::new(lit_rules),
                    Arc::new(rx_rules),
                    Arc::new(ac),
                    Arc::new(regex_set),
                ))
            })
            .as_ref()
            .map_err(|e: &String| Error::Rule(e.clone()))?
            .clone();

        let thresholds = HashMap::from([
            ("SQL".into(), 12),
            ("XSS".into(), 12),
            ("RFI".into(), 8),
            ("TRAVERSAL".into(), 4),
            ("EVADE".into(), 4),
        ]);

        Ok(Self {
            literal_rules: lit_rules,
            regex_rules: rx_rules,
            ac,
            regex_set,
            thresholds,
        })
    }

    /// Evaluates input fields against WAF rules.
    #[must_use]
    pub fn eval(&self, path: &str, query: &str, body: &str, cookie: &str) -> EvalResult {
        let mut scores: HashMap<String, u32> = HashMap::new();
        let mut matched_rules = Vec::new();

        let path_dec = percent_decode_str(path).decode_utf8_lossy();
        let query_dec = percent_decode_str(query)
            .decode_utf8_lossy()
            .replace('+', " ");
        let body_dec = percent_decode_str(body)
            .decode_utf8_lossy()
            .replace('+', " ");
        let cookie_dec = percent_decode_str(cookie).decode_utf8_lossy();

        let inputs = [
            (Zone::Path, path_dec.as_ref()),
            (Zone::Query, query_dec.as_ref()),
            (Zone::Body, body_dec.as_ref()),
            (Zone::Cookie, cookie_dec.as_ref()),
        ];

        for (zone, content) in inputs {
            if content.is_empty() {
                continue;
            }

            for mat in self.ac.find_iter(content) {
                let rule_idx = mat.pattern().as_usize();
                if let Some(rule) = self
                    .literal_rules
                    .get(rule_idx)
                    .filter(|r| r.zones.contains(&zone))
                {
                    if !matched_rules.contains(&rule.id) {
                        matched_rules.push(rule.id);
                        trace!(id = rule.id, "rule match: literal");
                    }
                    for (cat, score) in &rule.scores {
                        *scores.entry(cat.clone()).or_default() += *score;
                    }
                }
            }

            for idx in self.regex_set.matches(content) {
                if let Some(rule) = self
                    .regex_rules
                    .get(idx)
                    .filter(|r| r.zones.contains(&zone))
                {
                    if !matched_rules.contains(&rule.id) {
                        matched_rules.push(rule.id);
                        trace!(id = rule.id, "rule match: regex");
                    }
                    for (cat, score) in &rule.scores {
                        *scores.entry(cat.clone()).or_default() += *score;
                    }
                }
            }
        }

        let blocked = scores.values().any(|&s| s >= BLOCK_SCORE)
            || self
                .thresholds
                .iter()
                .any(|(cat, thresh)| scores.get(cat).copied().unwrap_or(0) >= *thresh);

        EvalResult {
            blocked,
            scores,
            matched_rules,
        }
    }

    fn default_rules() -> (Vec<String>, Vec<Rule>, Vec<String>, Vec<Rule>) {
        let mut lit_patterns = Vec::new();
        let mut lit_rules = Vec::new();
        let mut rx_patterns = Vec::new();
        let mut rx_rules = Vec::new();

        let all_rules = [
            Self::sql_rules(),
            Self::xss_rules(),
            Self::rfi_rules(),
            Self::traversal_rules(),
            Self::evade_rules(),
        ]
        .concat();

        for (pattern, rule, is_regex) in all_rules {
            if is_regex {
                rx_patterns.push(pattern);
                rx_rules.push(rule);
            } else {
                lit_patterns.push(pattern);
                lit_rules.push(rule);
            }
        }

        (lit_patterns, lit_rules, rx_patterns, rx_rules)
    }

    fn sql_rules() -> Vec<(String, Rule, bool)> {
        vec![
            Self::lit(1010, "(", &[Zone::Cookie], &[("SQL", 4), ("XSS", 4)]),
            Self::lit(1011, ")", &[Zone::Cookie], &[("SQL", 4), ("XSS", 4)]),
            Self::rx(
                2001,
                r"(?i)\b(union\s+(all\s+)?select)\b",
                &[Zone::Query, Zone::Body],
                &[("SQL", 5)],
            ),
            Self::rx(
                2101,
                r"(?i)(?:'|\)|@@)\s*(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|#|/\*)",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("SQL", 4)],
            ),
            Self::rx(
                2102,
                r"(?i);\s*(?:--|#|/\*|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|UNION|TRUNCATE|DECLARE)",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("SQL", 4)],
            ),
            Self::rx(
                2103,
                r"(?i)(?:'|\d|\)|@@)\s*\|\||\|\|\s*(?:'|\d|@)|'\s*\||\|\s*'",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("SQL", 3)],
            ),
            Self::rx(
                2104,
                r"(?i)(?:'|\d|\)|@@)\s*&&|&&\s*(?:'|\d|@|!|\()|'\s*&|&\s*'",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("SQL", 3)],
            ),
            Self::rx(
                2105,
                r"(?i)@@[a-z_][a-z0-9_]*",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("SQL", 4)],
            ),
            Self::rx(
                2106,
                r"(?i)/\*!.*(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("SQL", 5)],
            ),
        ]
    }

    fn rfi_rules() -> Vec<(String, Rule, bool)> {
        vec![
            Self::lit(
                1102,
                "ftp://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
            Self::lit(
                1103,
                "php://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
            Self::lit(
                1108,
                "phar://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
            Self::lit(
                1109,
                "file://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
            Self::lit(
                1110,
                "gopher://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
        ]
    }

    fn traversal_rules() -> Vec<(String, Rule, bool)> {
        vec![
            Self::rx(
                2200,
                r"(?:\.\.[/|\\])",
                &[Zone::Query, Zone::Path, Zone::Cookie, Zone::Body],
                &[("TRAVERSAL", 4)],
            ),
            Self::rx(
                2201,
                r"(?:[a-zA-Z]:\\)",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 4)],
            ),
            Self::rx(
                2202,
                r"(?:\.{2,}/+)+",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 8)],
            ),
            Self::rx(
                2203,
                r"\.\.;/",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 8)],
            ),
            Self::rx(
                2204,
                r"(?i)%2e%2e",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 8)],
            ),
            Self::lit(
                1202,
                "/etc/passwd",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 4)],
            ),
            Self::lit(
                1203,
                "c:\\",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 4)],
            ),
            Self::lit(
                1204,
                "cmd.exe",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 4)],
            ),
        ]
    }

    fn xss_rules() -> Vec<(String, Rule, bool)> {
        vec![
            Self::rx(
                2300,
                r"(?i)<[a-z/!?]",
                &[Zone::Query, Zone::Path, Zone::Cookie, Zone::Body],
                &[("XSS", 4)],
            ),
            Self::rx(
                2301,
                r"(?i)String\.from(Char|Code)",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("XSS", 5)],
            ),
            Self::rx(
                2302,
                r"(?i)javascript:\s*//",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("XSS", 5)],
            ),
            Self::rx(
                2303,
                r"(?i)data:[^,]+;base64",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("XSS", 5)],
            ),
            Self::rx(
                2003,
                r"(?i)<script[^>]*>",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("XSS", 5)],
            ),
            Self::rx(
                2004,
                r"(?i)(on\w+\s*=)",
                &[Zone::Query, Zone::Body],
                &[("XSS", 3)],
            ),
            Self::rx(
                2005,
                r"(?i)(javascript|vbscript|data):",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("XSS", 4)],
            ),
        ]
    }

    fn evade_rules() -> Vec<(String, Rule, bool)> {
        vec![Self::lit(
            1401,
            "%U",
            &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
            &[("EVADE", 4)],
        )]
    }

    fn lit(id: u32, pattern: &str, zones: &[Zone], scores: &[(&str, u32)]) -> (String, Rule, bool) {
        (
            pattern.into(),
            Rule {
                id,
                zones: zones.to_vec(),
                scores: scores.iter().map(|(k, v)| ((*k).into(), *v)).collect(),
            },
            false,
        )
    }

    fn rx(id: u32, pattern: &str, zones: &[Zone], scores: &[(&str, u32)]) -> (String, Rule, bool) {
        (
            pattern.into(),
            Rule {
                id,
                zones: zones.to_vec(),
                scores: scores.iter().map(|(k, v)| ((*k).into(), *v)).collect(),
            },
            true,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rule_accumulation() {
        let e = RuleEngine::try_new().unwrap();

        let r = e.eval(
            "/",
            "id=1' OR 1=1-- ; SELECT * FROM users; @@version",
            "",
            "",
        );
        assert!(r.blocked);
        assert!(r.scores.get("SQL").unwrap_or(&0) >= &12);

        let r = e.eval(
            "/",
            "",
            "<script>alert(1)</script><img onerror=x onload=y><svg onload=z>",
            "",
        );
        assert!(r.blocked);
        assert!(r.scores.get("XSS").unwrap_or(&0) >= &12);

        let r = e.eval(
            "/",
            "file=php://filter&url=data://text&include=php://input",
            "",
            "",
        );
        assert!(r.blocked);
        assert!(r.scores.get("RFI").unwrap_or(&0) >= &8);

        let r = e.eval("/../../../etc/passwd", "", "", "");
        assert!(r.blocked);
        assert!(r.scores.get("TRAVERSAL").unwrap_or(&0) >= &4);

        let r = e.eval("/", "%U0041", "", "");
        assert!(r.blocked);
        assert!(r.scores.get("EVADE").unwrap_or(&0) >= &4);

        let r = e.eval("/", "", "", "()()(SELECT 1)");
        assert!(r.blocked);
        assert!(r.scores.get("SQL").unwrap_or(&0) >= &12);

        let r = e.eval("/about", "page=2&sort=name", "", "session=active_session");
        assert!(!r.blocked);
    }
}
