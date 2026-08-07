//! Device-join card: endpoint, keys, and operator notes.
//!
//! When crypto is present, [`DeviceJoinInfo::with_keys`] exposes real public
//! keys and a sample client private key for the preconfigured peer. Private
//! keys must never be logged at info level.

/// What a device-join card shows for WireGuard mode.
///
/// Serialisable so the setup page / status API can reuse the same fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceJoinInfo {
    /// Public UDP endpoint `host:port` the phone dials.
    pub endpoint: String,
    /// Server public key (base64) when generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_public_key: Option<String>,
    /// Client private key (base64) for the preconfigured peer. Sensitive:
    /// only for the operator's first-run join card, never log at info.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_private_key: Option<String>,
    /// Client public key (base64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_public_key: Option<String>,
    /// Client tunnel address CIDR (e.g. `10.0.0.2/32`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_address_cidr: Option<String>,
    /// DNS inside the tunnel when assigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    /// Operator-facing honesty lines.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl DeviceJoinInfo {
    /// Scaffold-only card: endpoint, no fake keys.
    pub fn scaffold_example(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            server_public_key: None,
            client_private_key: None,
            client_public_key: None,
            client_address_cidr: None,
            dns: None,
            notes: vec![
                "WireGuard crypto is not linked in this build (rebuild with --features wireguard)."
                    .into(),
                "Phone Wi-Fi HTTP proxy settings do not feed the WireGuard path; \
                 device join is a separate VPN-style configuration."
                    .into(),
            ],
        }
    }

    /// Live join card after key generation.
    pub fn with_keys(
        endpoint: impl Into<String>,
        server_public_key: String,
        client_private_key: String,
        client_public_key: String,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            server_public_key: Some(server_public_key),
            client_private_key: Some(client_private_key),
            client_public_key: Some(client_public_key),
            client_address_cidr: Some("10.0.0.2/32".into()),
            dns: Some("10.0.0.1".into()),
            notes: vec![
                "WireGuard Noise_IK handshake and transport AEAD are enabled.".into(),
                "Inner UDP is demuxed toward UdpIngress; full TCP reassembly \
                 of tunnel traffic is not shipped yet."
                    .into(),
                "Phone Wi-Fi HTTP proxy settings do not feed this path; install \
                 the peer config as a VPN profile."
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

    #[test]
    fn with_keys_includes_public_material() {
        let info = DeviceJoinInfo::with_keys(
            "203.0.113.10:51820",
            "serverpub".into(),
            "clientpriv".into(),
            "clientpub".into(),
        );
        assert_eq!(info.server_public_key.as_deref(), Some("serverpub"));
        assert_eq!(info.client_address_cidr.as_deref(), Some("10.0.0.2/32"));
    }
}
