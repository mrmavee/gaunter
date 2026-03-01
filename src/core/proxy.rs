//! Proxy service implementation.
//!
//! Provides request filtering, peer selection, and service integration.

pub mod challenge;
pub mod headers;
pub mod protocol;
pub mod response;
pub mod router;
pub mod service;

pub use service::GaunterProxy;
