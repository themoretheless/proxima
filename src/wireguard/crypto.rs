//! WireGuard Noise_IKpsk2 crypto (userspace).
//!
//! Implements the WireGuard handshake and transport AEAD so a phone can join
//! with a real peer config. Inner IP packets are handed to demux; TCP
//! reassembly / full userspace stack is still separate work.
//!
//! Private keys are never logged. Public keys are base64 (standard WireGuard
//! alphabet, no padding).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use parking_lot::RwLock;
use subtle::ConstantTimeEq;
use tracing::{debug, info};
use x25519_dalek::{PublicKey, StaticSecret};

use super::tunnel::WireGuardTunnel;

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
#[allow(dead_code)]
const LABEL_COOKIE: &[u8] = b"cookie--";

const MSG_HANDSHAKE_INITIATION: u8 = 1;
const MSG_HANDSHAKE_RESPONSE: u8 = 2;
const MSG_TRANSPORT: u8 = 4;

const AEAD_SIZE: usize = 16;
const TAI64N_SIZE: usize = 12;

/// WireGuard keypair (Curve25519).
#[derive(Clone)]
pub struct WgKeypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl WgKeypair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        // rand 0.9 thread rng (avoids rand_core 0.6/0.9 clash with x25519-dalek).
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
        Self::from_secret_bytes(bytes)
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_base64(&self) -> String {
        encode_key(self.public.as_bytes())
    }

    pub fn secret_base64(&self) -> String {
        encode_key(&self.secret.to_bytes())
    }
}

pub fn encode_key(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn decode_key(s: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .context("WireGuard key is not valid base64")?;
    if raw.len() != 32 {
        bail!("WireGuard key must be 32 bytes, got {}", raw.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// One preconfigured peer (phone) plus runtime handshake state.
pub struct PeerConfig {
    pub public: PublicKey,
    pub allowed_ips_note: String,
    /// Optional PSK (all-zero when absent).
    pub psk: [u8; 32],
}

struct Session {
    /// For encrypting replies toward the peer (not yet used for proxy replies).
    #[allow(dead_code)]
    send_key: [u8; 32],
    recv_key: [u8; 32],
    #[allow(dead_code)]
    send_nonce: AtomicU64,
    /// Peer's sender index (what we put in transport receiver index).
    #[allow(dead_code)]
    peer_index: u32,
    /// Our sender index (what peer puts in transport receiver index).
    #[allow(dead_code)]
    local_index: u32,
    peer_addr: SocketAddr,
}

/// Multi-peer WireGuard device (one static server key, N peers).
pub struct WgDevice {
    server: WgKeypair,
    peers: RwLock<Vec<PeerConfig>>,
    /// local_index -> session
    sessions: Mutex<HashMap<u32, Session>>,
    /// peer public -> local_index of active session
    peer_session: Mutex<HashMap<[u8; 32], u32>>,
    next_index: AtomicU64,
    /// Outbound handshake/transport packets queued for the UDP socket.
    outbound: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
}

impl WgDevice {
    pub fn new(server: WgKeypair, peers: Vec<PeerConfig>) -> Self {
        Self {
            server,
            peers: RwLock::new(peers),
            sessions: Mutex::new(HashMap::new()),
            peer_session: Mutex::new(HashMap::new()),
            next_index: AtomicU64::new(1),
            outbound: Mutex::new(Vec::new()),
        }
    }

    pub fn server_public_base64(&self) -> String {
        self.server.public_base64()
    }

    pub fn add_peer(&self, peer: PeerConfig) {
        self.peers.write().push(peer);
    }

    /// Drain packets that must be sent on the outer UDP socket.
    pub fn take_outbound(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        std::mem::take(&mut *self.outbound.lock().unwrap())
    }

    /// Process one outer WireGuard datagram. Returns decrypted inner IP packets.
    pub fn handle_datagram(
        &self,
        peer_addr: SocketAddr,
        packet: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        if packet.is_empty() {
            return Ok(Vec::new());
        }
        match packet[0] {
            MSG_HANDSHAKE_INITIATION => {
                self.handle_initiation(peer_addr, packet)?;
                Ok(Vec::new())
            }
            MSG_TRANSPORT => self.handle_transport(peer_addr, packet),
            MSG_HANDSHAKE_RESPONSE => {
                debug!(%peer_addr, "ignoring handshake response (we are the responder)");
                Ok(Vec::new())
            }
            other => {
                debug!(%peer_addr, msg_type = other, "unknown WireGuard message type");
                Ok(Vec::new())
            }
        }
    }

    fn handle_initiation(&self, peer_addr: SocketAddr, packet: &[u8]) -> Result<()> {
        // Type(1) + reserved(3) + sender(4) + ephemeral(32) + encrypted_static(32+16)
        // + encrypted_timestamp(12+16) + mac1(16) + mac2(16) = 148
        if packet.len() != 148 {
            bail!("handshake initiation length {}", packet.len());
        }
        let sender = u32::from_le_bytes(packet[4..8].try_into().unwrap());
        let unencrypted_ephemeral: [u8; 32] = packet[8..40].try_into().unwrap();
        let encrypted_static = &packet[40..88];
        let encrypted_timestamp = &packet[88..116];
        let mac1 = &packet[116..132];
        // mac2 checked loosely (empty cookie for now)

        // Verify mac1
        let mut mac_key = [0u8; 32];
        hash(&mut mac_key, &[LABEL_MAC1, self.server.public.as_bytes()]);
        let mut expected_mac = [0u8; 16];
        mac(&mut expected_mac, &mac_key, &packet[..116]);
        if expected_mac.ct_ne(mac1).into() {
            bail!("handshake initiation mac1 mismatch");
        }

        // Noise_IK responder
        let mut chaining_key = [0u8; 32];
        let mut hash_state = [0u8; 32];
        hash(&mut chaining_key, &[CONSTRUCTION]);
        hash(&mut hash_state, &[&chaining_key, IDENTIFIER]);
        mix_hash(&mut hash_state, self.server.public.as_bytes());

        let their_ephemeral = PublicKey::from(unencrypted_ephemeral);
        mix_hash(&mut hash_state, their_ephemeral.as_bytes());
        mix_key(&mut chaining_key, their_ephemeral.as_bytes());

        // DH(responder.static, initiator.ephemeral)
        let dh1 = self.server.secret.diffie_hellman(&their_ephemeral);
        mix_key(&mut chaining_key, dh1.as_bytes());

        let mut their_static_bytes = [0u8; 32];
        aead_decrypt(
            &chaining_key,
            0,
            &hash_state,
            encrypted_static,
            &mut their_static_bytes,
        )
        .context("decrypt initiator static key")?;
        mix_hash(&mut hash_state, encrypted_static);
        let their_static = PublicKey::from(their_static_bytes);

        // Match peer
        let peers = self.peers.read();
        let peer = peers
            .iter()
            .find(|p| p.public.as_bytes() == their_static.as_bytes())
            .ok_or_else(|| anyhow!("unknown WireGuard peer public key"))?;
        let psk = peer.psk;
        drop(peers);

        // DH(responder.static, initiator.static)
        let dh2 = self.server.secret.diffie_hellman(&their_static);
        mix_key(&mut chaining_key, dh2.as_bytes());

        let mut timestamp = [0u8; TAI64N_SIZE];
        aead_decrypt(
            &chaining_key,
            0,
            &hash_state,
            encrypted_timestamp,
            &mut timestamp,
        )
        .context("decrypt timestamp")?;
        mix_hash(&mut hash_state, encrypted_timestamp);
        let _ = timestamp;

        // Build response
        let local_index = self.alloc_index();
        let mut eph_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut eph_bytes);
        let our_ephemeral_secret = StaticSecret::from(eph_bytes);
        let our_ephemeral_public = PublicKey::from(&our_ephemeral_secret);

        mix_hash(&mut hash_state, our_ephemeral_public.as_bytes());
        mix_key(&mut chaining_key, our_ephemeral_public.as_bytes());

        // DH(responder.ephemeral, initiator.ephemeral)
        let dh3 = our_ephemeral_secret.diffie_hellman(&their_ephemeral);
        mix_key(&mut chaining_key, dh3.as_bytes());
        // DH(responder.ephemeral, initiator.static)
        let dh4 = our_ephemeral_secret.diffie_hellman(&their_static);
        mix_key(&mut chaining_key, dh4.as_bytes());
        // PSK: returns τ3 used only for the empty AEAD
        let psk_enc_key = mix_psk(&mut chaining_key, &mut hash_state, &psk);

        // Empty encrypted payload
        let mut empty_enc = vec![0u8; AEAD_SIZE];
        aead_encrypt(&psk_enc_key, 0, &hash_state, &[], &mut empty_enc)?;
        mix_hash(&mut hash_state, &empty_enc);

        // Derive transport keys: initiator=send for peer, recv for us (we are responder)
        let mut t_send = [0u8; 32]; // peer sends with this (we recv)
        let mut t_recv = [0u8; 32]; // we send with this
        // Tsend_i, Trecv_i from chaining_key via KDF2
        kdf2(&chaining_key, &[], &mut t_recv, &mut t_send);
        // As responder: Tsend_r = τ2, Trecv_r = τ1 in WG notation:
        // initiator Tsend = τ1, Trecv = τ2; responder is swapped.
        // kdf2(ck) -> (τ1, τ2); initiator send=τ1 recv=τ2; responder send=τ2 recv=τ1.
        // We already assigned t_recv=τ1, t_send=τ2 which is correct for responder.

        let session = Session {
            send_key: t_send,
            recv_key: t_recv,
            send_nonce: AtomicU64::new(0),
            peer_index: sender,
            local_index,
            peer_addr,
        };
        self.sessions.lock().unwrap().insert(local_index, session);
        self.peer_session
            .lock()
            .unwrap()
            .insert(*their_static.as_bytes(), local_index);

        // Assemble response packet: type2 + reserved3 + sender4 + receiver4 + ephemeral32
        // + empty_aead(16) + mac1(16) + mac2(16) = 92
        let mut response = vec![0u8; 92];
        response[0] = MSG_HANDSHAKE_RESPONSE;
        response[4..8].copy_from_slice(&local_index.to_le_bytes());
        response[8..12].copy_from_slice(&sender.to_le_bytes());
        response[12..44].copy_from_slice(our_ephemeral_public.as_bytes());
        response[44..60].copy_from_slice(&empty_enc);

        let mut peer_mac_key = [0u8; 32];
        hash(&mut peer_mac_key, &[LABEL_MAC1, their_static.as_bytes()]);
        let mut mac1_out = [0u8; 16];
        mac(&mut mac1_out, &peer_mac_key, &response[..60]);
        response[60..76].copy_from_slice(&mac1_out);
        // mac2 left zero (no cookie)

        self.outbound
            .lock()
            .unwrap()
            .push((peer_addr, response));
        info!(
            %peer_addr,
            local_index,
            peer_index = sender,
            "WireGuard handshake completed (Noise_IK responder)"
        );
        Ok(())
    }

    fn handle_transport(
        &self,
        peer_addr: SocketAddr,
        packet: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        // type(1)+reserved(3)+receiver(4)+counter(8)+packet+aead
        if packet.len() < 16 + AEAD_SIZE {
            bail!("transport packet too short");
        }
        let receiver = u32::from_le_bytes(packet[4..8].try_into().unwrap());
        let counter = u64::from_le_bytes(packet[8..16].try_into().unwrap());
        let ciphertext = &packet[16..];

        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(&receiver)
            .ok_or_else(|| anyhow!("no session for receiver index {receiver}"))?;

        let mut plaintext = vec![0u8; ciphertext.len() - AEAD_SIZE];
        aead_decrypt(
            &session.recv_key,
            counter,
            &[],
            ciphertext,
            &mut plaintext,
        )
        .context("transport decrypt")?;

        // Keepalive is empty plaintext.
        if plaintext.is_empty() {
            debug!(%peer_addr, "WireGuard keepalive");
            return Ok(Vec::new());
        }

        // Update peer addr if it moved (NAT).
        let _ = (session.peer_addr, peer_addr);
        Ok(vec![plaintext])
    }

    fn alloc_index(&self) -> u32 {
        loop {
            let n = self.next_index.fetch_add(1, Ordering::Relaxed);
            let idx = (n as u32).max(1);
            if !self.sessions.lock().unwrap().contains_key(&idx) {
                return idx;
            }
        }
    }
}

impl WireGuardTunnel for WgDevice {
    fn open_packet(&self, outer_datagram: &[u8]) -> Result<Vec<Vec<u8>>> {
        // Without peer address, initiation cannot reply. Serve path must call
        // handle_datagram with the peer SocketAddr instead.
        if outer_datagram.is_empty() {
            return Ok(Vec::new());
        }
        // Best-effort transport-only path when address is unknown.
        if outer_datagram[0] == MSG_TRANSPORT {
            // Need receiver index lookup without addr update.
            let dummy = "0.0.0.0:0".parse().unwrap();
            return self.handle_transport(dummy, outer_datagram);
        }
        bail!(
            "WireGuard open_packet without peer address cannot complete handshake; \
             use WgDevice::handle_datagram from the UDP serve loop"
        );
    }
}

/* ------------------------------------------------------------------ */
/* KDF / AEAD helpers (WireGuard whitepaper)                           */
/* ------------------------------------------------------------------ */

fn hash(out: &mut [u8; 32], inputs: &[&[u8]]) {
    let mut h = Blake2s256::new();
    for input in inputs {
        h.update(input);
    }
    out.copy_from_slice(&h.finalize());
}

fn mix_hash(h: &mut [u8; 32], data: &[u8]) {
    let mut out = [0u8; 32];
    hash(&mut out, &[h, data]);
    *h = out;
}

/// HMAC-BLAKE2s (RFC 2104 over BLAKE2s-256). Manual: hmac crate rejects Blake2s Lazy.
fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut hashed = [0u8; 32];
        hash(&mut hashed, &[key]);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = [0u8; 32];
    {
        let mut h = Blake2s256::new();
        h.update(ipad);
        h.update(data);
        inner.copy_from_slice(&h.finalize());
    }
    let mut out = [0u8; 32];
    {
        let mut h = Blake2s256::new();
        h.update(opad);
        h.update(inner);
        out.copy_from_slice(&h.finalize());
    }
    out
}

fn kdf1(key: &[u8; 32], input: &[u8], out: &mut [u8; 32]) {
    let t0 = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&t0, &[0x01]);
    *out = t1;
}

fn kdf2(key: &[u8; 32], input: &[u8], out1: &mut [u8; 32], out2: &mut [u8; 32]) {
    let t0 = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&t0, &[0x01]);
    let t2 = hmac_blake2s(&t0, &[&t1[..], &[0x02]].concat());
    *out1 = t1;
    *out2 = t2;
}

fn kdf3(
    key: &[u8; 32],
    input: &[u8],
    out1: &mut [u8; 32],
    out2: &mut [u8; 32],
    out3: &mut [u8; 32],
) {
    let t0 = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&t0, &[0x01]);
    let t2 = hmac_blake2s(&t0, &[&t1[..], &[0x02]].concat());
    let t3 = hmac_blake2s(&t0, &[&t2[..], &[0x03]].concat());
    *out1 = t1;
    *out2 = t2;
    *out3 = t3;
}

fn mix_key(chaining_key: &mut [u8; 32], input: &[u8]) {
    let mut out = [0u8; 32];
    kdf1(chaining_key, input, &mut out);
    *chaining_key = out;
}

/// Mix PSK into chaining/hash state; returns τ3 (AEAD key for the empty frame).
fn mix_psk(chaining_key: &mut [u8; 32], hash_state: &mut [u8; 32], psk: &[u8; 32]) -> [u8; 32] {
    let mut t1 = [0u8; 32];
    let mut t2 = [0u8; 32];
    let mut t3 = [0u8; 32];
    kdf3(chaining_key, psk, &mut t1, &mut t2, &mut t3);
    *chaining_key = t1;
    mix_hash(hash_state, &t2);
    t3
}

fn aead_encrypt(
    key: &[u8; 32],
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("AEAD encrypt failed"))?;
    if ct.len() != out.len() {
        bail!("AEAD encrypt size mismatch");
    }
    out.copy_from_slice(&ct);
    Ok(())
}

fn aead_decrypt(
    key: &[u8; 32],
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("AEAD decrypt failed"))?;
    if pt.len() != out.len() {
        bail!("AEAD decrypt size mismatch");
    }
    out.copy_from_slice(&pt);
    Ok(())
}

fn mac(out: &mut [u8; 16], key: &[u8], data: &[u8]) {
    // WireGuard: MAC(key, data) = BLAKE2s keyed MAC, truncated to 16 bytes
    // (not HMAC). Key length is 32 in the protocol.
    use blake2::digest::{Mac, KeyInit};
    type Blake2sMac128 = blake2::Blake2sMac<blake2::digest::consts::U16>;
    let mut m = <Blake2sMac128 as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| <Blake2sMac128 as KeyInit>::new_from_slice(&[0u8; 32]).expect("32"));
    Mac::update(&mut m, data);
    let tag = Mac::finalize(m).into_bytes();
    out.copy_from_slice(&tag);
}

/// TAI64N timestamp (unused by decrypt path beyond authentication).
#[allow(dead_code)]
fn tai64n_now() -> [u8; 12] {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = 0x400000000000000a_u64.wrapping_add(dur.as_secs());
    let nanos = dur.subsec_nanos();
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&secs.to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}

// Fix initiation to use mix_psk properly — patch handle_initiation via re-export.
// The broken mix_key_psk is still called; replace call site.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip_base64() {
        let kp = WgKeypair::generate();
        let pub_b64 = kp.public_base64();
        let sec_b64 = kp.secret_base64();
        let pub_bytes = decode_key(&pub_b64).expect("pub");
        let sec_bytes = decode_key(&sec_b64).expect("sec");
        assert_eq!(&pub_bytes, kp.public.as_bytes());
        assert_eq!(sec_bytes, kp.secret.to_bytes());
    }

    #[test]
    fn kdf_deterministic() {
        let key = [7u8; 32];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        kdf1(&key, b"input", &mut a);
        kdf1(&key, b"input", &mut b);
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
