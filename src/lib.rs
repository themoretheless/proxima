//! Proxima: an HTTPS interception proxy and API client.
//!
//! The pieces fit together like this:
//!
//! - [`ca`] mints the certificates that let us read TLS.
//! - [`capture`] holds captured traffic and broadcasts live events.
//! - [`proxy`] is the port the phone points at.
//! - [`api`] serves the inspector UI, the REST API and the device setup page.
//! - [`replay`] re-sends captured requests and composes new ones.

pub mod api;
pub mod ca;
pub mod capture;
pub mod config;
pub mod proxy;
pub mod replay;
pub mod runtime;
pub mod types;

#[cfg(feature = "gui")]
pub mod gui;

pub use config::Config;
