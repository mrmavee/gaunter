//! Rate limit key resolution.
//!
//! Determines the identity key used for request throttling.

#[must_use]
pub fn rate_limit_key(circuit_id: Option<&str>, session_id: Option<&str>) -> Option<String> {
    circuit_id
        .or(session_id)
        .map(std::string::ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_resolution() {
        assert_eq!(rate_limit_key(None, None), None);
        assert_eq!(
            rate_limit_key(Some("circuit_id"), None),
            Some("circuit_id".to_string())
        );
        assert_eq!(
            rate_limit_key(None, Some("session_id")),
            Some("session_id".to_string())
        );
        assert_eq!(
            rate_limit_key(Some("circuit_id"), Some("session_id")),
            Some("circuit_id".to_string())
        );
    }
}
