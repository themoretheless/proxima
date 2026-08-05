//! The certificate authority that makes TLS readable.
//!
//! On first run this generates a root CA and stores it in the data directory.
//! For every host the proxy talks to, it mints a leaf certificate signed by
//! that root, reusing one key pair across all leaves. Key generation is the
//! expensive step, so sharing the key turns a new host from hundreds of
//! milliseconds into a signature.
//!
//! The leaf constraints here are not stylistic. iOS 13 and later reject server
//! certificates that live longer than 398 days or that identify the host only
//! by common name, and a repeated serial number is a hard failure in several
//! clients. Getting these wrong produces a proxy that silently fails to
//! intercept anything, which is the worst possible outcome to debug.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine as _;
use parking_lot::Mutex;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// Apple rejects TLS server certificates with a lifetime over 398 days.
const LEAF_VALID_DAYS: i64 = 397;
const ROOT_VALID_DAYS: i64 = 3650;
/// Leaf certificates are cheap to mint but not free; keep the hot hosts warm.
const CACHE_CAPACITY: usize = 1000;

pub struct CertAuthority {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    sha256: String,
    not_after: OffsetDateTime,
    cert_path: PathBuf,
    issuer: Issuer<'static, KeyPair>,
    /// One key pair shared by every leaf we mint.
    leaf_key: KeyPair,
    leaf_signing_key: Arc<dyn rustls::sign::SigningKey>,
    cache: Mutex<LeafCache>,
}

#[derive(Default)]
struct LeafCache {
    map: HashMap<String, Arc<CertifiedKey>>,
    order: VecDeque<String>,
}

impl LeafCache {
    fn get(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        self.map.get(host).cloned()
    }

    fn insert(&mut self, host: String, key: Arc<CertifiedKey>) {
        if self.map.insert(host.clone(), key).is_none() {
            self.order.push_back(host);
        }
        while self.order.len() > CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
    }
}

impl CertAuthority {
    /// Loads the CA from `data_dir/ca`, generating it when absent, unreadable
    /// or expired.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.join("ca");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        restrict_dir(&dir);

        let cert_path = dir.join("proxima-ca.crt");
        let key_path = dir.join("proxima-ca.key");
        let leaf_key_path = dir.join("proxima-leaf.key");

        let existing = load_existing(&cert_path, &key_path);
        let (cert_pem, ca_key) = match existing {
            Some(pair) => pair,
            None => {
                let generated = generate_root()?;
                std::fs::write(&cert_path, &generated.0).context("writing CA certificate")?;
                write_private(&key_path, &generated.1.serialize_pem())?;
                (generated.0, generated.1)
            }
        };

        let leaf_key = match std::fs::read_to_string(&leaf_key_path)
            .ok()
            .and_then(|pem| KeyPair::from_pem(&pem).ok())
        {
            Some(key) => key,
            None => {
                let key = KeyPair::generate().context("generating leaf key")?;
                write_private(&leaf_key_path, &key.serialize_pem())?;
                key
            }
        };

        let cert_der = pem_to_der(&cert_pem).context("parsing CA certificate")?;
        let sha256 = fingerprint(&cert_der);
        let not_after = parse_not_after(&cert_der).unwrap_or_else(|| {
            OffsetDateTime::now_utc() + Duration::days(ROOT_VALID_DAYS)
        });

        let issuer = Issuer::from_ca_cert_pem(&cert_pem, ca_key)
            .context("loading CA as an issuer")?;

        let leaf_key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| anyhow::anyhow!("leaf key is not a usable private key: {e}"))?;
        let leaf_signing_key = rustls::crypto::ring::sign::any_supported_type(&leaf_key_der)
            .context("leaf key is not supported by the TLS provider")?;

        Ok(Self {
            cert_pem,
            cert_der,
            sha256,
            not_after,
            cert_path,
            issuer,
            leaf_key,
            leaf_signing_key,
            cache: Mutex::new(LeafCache::default()),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// Uppercase hex, colon separated, over the DER. This is what the setup
    /// page shows so a user can check what they are about to trust.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// Certificate rustls can serve for `host`, minted on demand and cached.
    pub fn certified_key(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let host = normalise_host(host);
        if let Some(hit) = self.cache.lock().get(&host) {
            return Ok(hit);
        }

        let leaf = self.mint(&host)?;
        let certified = Arc::new(CertifiedKey::new(
            // Sending the root alongside the leaf costs one certificate and
            // saves clients that will not build the chain themselves.
            vec![leaf, self.cert_der.clone()],
            self.leaf_signing_key.clone(),
        ));
        self.cache.lock().insert(host, certified.clone());
        Ok(certified)
    }

    fn mint(&self, host: &str) -> Result<CertificateDer<'static>> {
        // CertificateParams::new decides between a DNS and an IP SAN by
        // parsing the string, which is exactly the rule clients apply.
        let mut params = CertificateParams::new(vec![host.to_string()])
            .with_context(|| format!("{host} is not a usable certificate subject"))?;

        let now = OffsetDateTime::now_utc();
        // A little slack behind us absorbs clock skew on the device.
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(LEAF_VALID_DAYS);
        params.serial_number = Some(random_serial());

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;

        params.is_ca = IsCa::ExplicitNoCa;
        // ECDSA leaves sign the handshake; keyEncipherment would be meaningless
        // here and some validators object to it.
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let cert = params
            .signed_by(&self.leaf_key, &self.issuer)
            .with_context(|| format!("signing a certificate for {host}"))?;
        Ok(cert.der().clone())
    }

    /// An Apple configuration profile that installs the root as a trusted CA.
    /// iOS treats a bare .crt as an opaque download, so the profile is what
    /// makes the install flow work on a phone.
    pub fn mobileconfig(&self, display_name: &str) -> String {
        let der = base64::engine::general_purpose::STANDARD.encode(self.cert_der.as_ref());
        // Stable UUIDs derived from the certificate mean reinstalling replaces
        // the profile instead of stacking copies of it.
        let profile_uuid = derive_uuid(self.cert_der.as_ref(), b"profile");
        let payload_uuid = derive_uuid(self.cert_der.as_ref(), b"payload");
        let name = escape_xml(display_name);
        let fingerprint = escape_xml(&self.sha256);

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>ma.proxi.ca</string>
      <key>PayloadUUID</key>
      <string>{payload_uuid}</string>
      <key>PayloadDisplayName</key>
      <string>{name} root certificate</string>
      <key>PayloadDescription</key>
      <string>SHA-256 {fingerprint}</string>
      <key>PayloadCertificateFileName</key>
      <string>proxima-ca.crt</string>
      <key>PayloadContent</key>
      <data>{der}</data>
    </dict>
  </array>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>ma.proxi.profile</string>
  <key>PayloadUUID</key>
  <string>{profile_uuid}</string>
  <key>PayloadDisplayName</key>
  <string>{name}</string>
  <key>PayloadDescription</key>
  <string>Lets {name} read HTTPS traffic from this device. Remove this profile when you are done debugging.</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
</dict>
</plist>
"#
        )
    }
}

/// A rustls certificate resolver that mints per host on the fly from SNI.
pub struct SniResolver {
    ca: Arc<CertAuthority>,
    /// Used when the client sends no SNI at all, which older clients do. The
    /// host from the CONNECT line is the only hint available then.
    fallback_host: String,
}

impl SniResolver {
    pub fn new(ca: Arc<CertAuthority>, fallback_host: impl Into<String>) -> Self {
        Self {
            ca,
            fallback_host: fallback_host.into(),
        }
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver")
            .field("fallback_host", &self.fallback_host)
            .finish()
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello
            .server_name()
            .map(|n| n.to_string())
            .unwrap_or_else(|| self.fallback_host.clone());
        match self.ca.certified_key(&host) {
            Ok(key) => Some(key),
            Err(err) => {
                tracing::warn!(%host, error = %err, "could not mint a certificate");
                None
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

fn generate_root() -> Result<(String, KeyPair)> {
    let key = KeyPair::generate().context("generating CA key")?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    // A random tag keeps two Proxima roots distinguishable in a device's
    // certificate list, which happens as soon as anyone reinstalls.
    let mut tag = [0u8; 4];
    rand::rng().fill_bytes(&mut tag);
    let tag = hex_lower(&tag);
    dn.push(DnType::CommonName, format!("Proxima CA ({tag})"));
    dn.push(DnType::OrganizationName, "Proxima");
    params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(ROOT_VALID_DAYS);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(random_serial());

    let cert = params.self_signed(&key).context("self signing the CA")?;
    Ok((cert.pem(), key))
}

fn load_existing(cert_path: &Path, key_path: &Path) -> Option<(String, KeyPair)> {
    let cert_pem = std::fs::read_to_string(cert_path).ok()?;
    let key_pem = std::fs::read_to_string(key_path).ok()?;
    let key = KeyPair::from_pem(&key_pem).ok()?;
    let der = pem_to_der(&cert_pem)?;

    if let Some(not_after) = parse_not_after(&der) {
        if not_after <= OffsetDateTime::now_utc() {
            tracing::warn!("the stored CA expired, generating a new one");
            return None;
        }
    }
    Some((cert_pem, key))
}

/// 16 random bytes with the top bit cleared, so the integer stays positive and
/// stays inside the 20 byte limit RFC 5280 sets.
fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    SerialNumber::from_slice(&bytes)
}

fn pem_to_der(pem: &str) -> Option<CertificateDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let first = rustls_pemfile::certs(&mut cursor).next()?.ok();
    first
}

fn parse_not_after(der: &CertificateDer<'_>) -> Option<OffsetDateTime> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    OffsetDateTime::from_unix_timestamp(parsed.validity().not_after.timestamp()).ok()
}

fn fingerprint(der: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(der.as_ref());
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic UUID-shaped identifier so profiles replace rather than stack.
fn derive_uuid(seed: &[u8], salt: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(seed);
    let d = hasher.finalize();
    format!(
        "{}-{}-{}-{}-{}",
        hex_lower(&d[0..4]),
        hex_lower(&d[4..6]),
        hex_lower(&d[6..8]),
        hex_lower(&d[8..10]),
        hex_lower(&d[10..16])
    )
    .to_uppercase()
}

fn normalise_host(host: &str) -> String {
    crate::config::strip_port(host.trim()).to_ascii_lowercase()
}

fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)
        .with_context(|| format!("writing {}", path.display()))?;
    restrict_file(path);
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn generates_and_reloads_the_same_root() {
        let dir = temp_dir();
        let first = CertAuthority::open(dir.path()).expect("open");
        let second = CertAuthority::open(dir.path()).expect("reopen");
        assert_eq!(first.sha256(), second.sha256(), "reopening minted a new CA");
        assert!(first.cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn root_is_a_ca_and_the_leaf_is_not() {
        let dir = temp_dir();
        let ca = CertAuthority::open(dir.path()).expect("open");

        let (_, root) = x509_parser::parse_x509_certificate(ca.cert_der().as_ref()).unwrap();
        let basic = root.basic_constraints().unwrap().expect("root basicConstraints");
        assert!(basic.value.ca, "root must assert cA:true");
        assert!(basic.critical, "root basicConstraints must be critical");

        let key = ca.certified_key("example.com").expect("mint");
        let (_, leaf) = x509_parser::parse_x509_certificate(key.cert[0].as_ref()).unwrap();
        let leaf_basic = leaf.basic_constraints().unwrap().expect("leaf basicConstraints");
        assert!(!leaf_basic.value.ca, "leaf must not be a CA");
    }

    #[test]
    fn leaf_lifetime_stays_inside_the_apple_limit() {
        let dir = temp_dir();
        let ca = CertAuthority::open(dir.path()).expect("open");
        let key = ca.certified_key("example.com").expect("mint");
        let (_, leaf) = x509_parser::parse_x509_certificate(key.cert[0].as_ref()).unwrap();

        let not_before = leaf.validity().not_before.timestamp();
        let not_after = leaf.validity().not_after.timestamp();
        let days = (not_after - not_before) / 86_400;
        assert!(days < 398, "leaf lived {days} days, Apple rejects 398 or more");
        assert!(
            not_before <= OffsetDateTime::now_utc().unix_timestamp(),
            "notBefore must not be in the future"
        );
    }

    #[test]
    fn leaf_carries_a_dns_san_and_server_auth() {
        let dir = temp_dir();
        let ca = CertAuthority::open(dir.path()).expect("open");
        let key = ca.certified_key("api.example.com").expect("mint");
        let (_, leaf) = x509_parser::parse_x509_certificate(key.cert[0].as_ref()).unwrap();

        let san = leaf
            .subject_alternative_name()
            .unwrap()
            .expect("a leaf without a SAN is ignored by every modern client");
        let names: Vec<String> = san
            .value
            .general_names
            .iter()
            .map(|n| format!("{n:?}"))
            .collect();
        assert!(
            names.iter().any(|n| n.contains("api.example.com")),
            "SAN did not name the host: {names:?}"
        );

        let eku = leaf.extended_key_usage().unwrap().expect("EKU");
        assert!(eku.value.server_auth, "leaf must be usable for serverAuth");
    }

    #[test]
    fn ip_hosts_get_an_ip_san() {
        let dir = temp_dir();
        let ca = CertAuthority::open(dir.path()).expect("open");
        let key = ca.certified_key("127.0.0.1").expect("mint");
        let (_, leaf) = x509_parser::parse_x509_certificate(key.cert[0].as_ref()).unwrap();

        let san = leaf.subject_alternative_name().unwrap().expect("SAN");
        let has_ip = san
            .value
            .general_names
            .iter()
            .any(|n| matches!(n, x509_parser::extensions::GeneralName::IPAddress(_)));
        assert!(has_ip, "an IP host needs an IP SAN, a DNS SAN will not validate");
    }

    #[test]
    fn serials_do_not_repeat() {
        let dir = temp_dir();
        let ca = CertAuthority::open(dir.path()).expect("open");
        let a = ca.certified_key("one.example.com").expect("mint");
        let b = ca.certified_key("two.example.com").expect("mint");

        let (_, ca_a) = x509_parser::parse_x509_certificate(a.cert[0].as_ref()).unwrap();
        let (_, cb) = x509_parser::parse_x509_certificate(b.cert[0].as_ref()).unwrap();
        assert_ne!(
            ca_a.raw_serial(),
            cb.raw_serial(),
            "repeated serials break TLS in several clients"
        );
    }

    #[test]
    fn certificates_are_cached_per_host() {
        let dir = temp_dir();
        let ca = CertAuthority::open(dir.path()).expect("open");
        let a = ca.certified_key("cache.example.com").expect("mint");
        let b = ca.certified_key("cache.example.com").expect("mint");
        assert!(Arc::ptr_eq(&a, &b), "second call re-minted instead of using the cache");
    }

    #[test]
    fn host_normalisation_strips_ports_and_case() {
        assert_eq!(normalise_host("API.Example.com:8443"), "api.example.com");
        assert_eq!(normalise_host("example.com"), "example.com");
        assert_eq!(normalise_host("[::1]:443"), "::1");
    }

    #[test]
    fn private_keys_are_not_world_readable() {
        let dir = temp_dir();
        let _ = CertAuthority::open(dir.path()).expect("open");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key = dir.path().join("ca").join("proxima-ca.key");
            let mode = std::fs::metadata(&key).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "CA private key is readable by others");
        }
    }

    #[test]
    fn mobileconfig_is_stable_and_escaped() {
        let dir = temp_dir();
        let ca = CertAuthority::open(dir.path()).expect("open");
        let first = ca.mobileconfig("Proxima <test> & co");
        let second = ca.mobileconfig("Proxima <test> & co");
        assert_eq!(first, second, "profile UUIDs must be stable across calls");
        assert!(first.contains("com.apple.security.root"));
        assert!(first.contains("&lt;test&gt;"), "display name was not escaped");
        assert!(!first.contains("Proxima <test>"), "raw angle brackets leaked into the plist");
    }
}
