//! Device-join documentation types (no crypto, no config export).
//!
//! A real WireGuard mode would show the phone a peer config: endpoint, server
//! public key, client address CIDR, and DNS. This module only describes that
//! shape so UI/status copy and future exporters share one struct. Values are
//! either absent or clearly labeled as scaffold placeholders.
//!
//! **Never log private keys.** Public keys are safe to show once they exist;
//! until crypto is shipped, [`DeviceJoinInfo::server_public_key`] stays unset
//! or an explicit "unavailable" string, never a fake base64 blob.

/// What a device-join card would show once WireGuard crypto exists.
///
/// Docs and status honesty notes only in P9. Serialisable so a future setup
/// page can reuse the same fields without inventing a second shape.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceJoinInfo {
    /// Public UDP endpoint `host:port` the phone would dial (WG listen port).
    pub endpoint: String,
    /// Server public key (base64) when generated. Scaffold: `None` or a note
    /// that keys are unavailable, never a fabricated key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_public_key: Option<String>,
    /// Client tunnel address CIDR (e.g. `10.0.0.2/32`) when assigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_address_cidr: Option<String>,
    /// Operator-facing honesty lines (crypto not shipped, proxy path separate).
    #[serde(default)]
    pub notes: Vec<String>,
}

impl DeviceJoinInfo {
    /// Example card for docs and tests: endpoint only, no fake keys.
    pub fn scaffold_example(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            server_public_key: None,
            client_address_cidr: None,
            notes: vec![
                "WireGuard userspace mode is a scaffold: the UDP port may bind, \
                 but Noise/WG crypto and a working device tunnel are not shipped."
                    .into(),
                "Phone Wi-Fi HTTP proxy settings do not feed the WireGuard path; \
                 device join is a separate VPN-style configuration (not available yet)."
                    .into(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_example_serializes_without_fake_keys() {
        let info = DeviceJoinInfo::scaffold_example("192.0.2.1:51820");
        let json = serde_json::to_value(&info).expect("serialize");
        assert_eq!(json["endpoint"], "192.0.2.1:51820");
        assert!(json.get("serverPublicKey").is_none());
        assert!(json.get("clientAddressCidr").is_none());
        let notes = json["notes"].as_array().expect("notes");
        assert!(!notes.is_empty());
    }
}
