//! In-memory storage for captured request and response bodies.
//!
//! Bodies are the only part of a capture whose size the user does not control,
//! so this module is where a long session lives or dies. Two ceilings apply: a
//! per body limit enforced while streaming (the rest of the body is counted but
//! thrown away), and a global ceiling enforced on insert by dropping the oldest
//! bodies. `bytes_held` is the number that must stay honest through both, plus
//! explicit removal when a flow is evicted.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use tracing::debug;

use crate::types::BodyMeta;

use super::new_id;

pub struct BodyStore {
    inner: Arc<Inner>,
}

impl Clone for BodyStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct Inner {
    state: Mutex<State>,
    max_total_bytes: u64,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    /// Creation sequence to body id, so the oldest body is always the first
    /// key. A plain deque would leave tombstones behind on removal.
    order: BTreeMap<u64, String>,
    next_seq: u64,
    bytes_held: u64,
}

struct Entry {
    seq: u64,
    bytes: Bytes,
}

impl BodyStore {
    pub fn new(max_total_bytes: u64) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                max_total_bytes,
            }),
        }
    }

    /// Starts a body, retaining at most `limit` bytes of it.
    pub fn writer(&self, limit: u64) -> BodyWriter {
        BodyWriter {
            id: new_id(),
            limit,
            buf: Vec::new(),
            seen: 0,
            truncated: false,
            store: Arc::clone(&self.inner),
        }
    }

    /// Returns the retained bytes, or `None` when the body was never stored or
    /// has since been evicted.
    pub fn read(&self, id: &str) -> Option<Bytes> {
        self.inner
            .state
            .lock()
            .entries
            .get(id)
            .map(|e| e.bytes.clone())
    }

    pub fn remove(&self, id: &str) {
        let mut state = self.inner.state.lock();
        if let Some(entry) = state.entries.remove(id) {
            state.order.remove(&entry.seq);
            let len = entry.bytes.len() as u64;
            state.bytes_held = state.bytes_held.saturating_sub(len);
        }
    }

    pub fn clear(&self) {
        let mut state = self.inner.state.lock();
        state.entries.clear();
        state.order.clear();
        state.bytes_held = 0;
    }

    pub fn bytes_held(&self) -> u64 {
        self.inner.state.lock().bytes_held
    }

    pub fn len(&self) -> usize {
        self.inner.state.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Inner {
    fn insert(&self, id: String, bytes: Bytes) {
        let len = bytes.len() as u64;
        let mut evicted = 0usize;
        {
            let mut state = self.state.lock();
            // Ids come from a CSPRNG so this never fires in practice, but an
            // overwrite that forgot the old length would leak the difference.
            if let Some(previous) = state.entries.remove(&id) {
                state.order.remove(&previous.seq);
                let old_len = previous.bytes.len() as u64;
                state.bytes_held = state.bytes_held.saturating_sub(old_len);
            }

            let seq = state.next_seq;
            state.next_seq = state.next_seq.wrapping_add(1);
            state.order.insert(seq, id.clone());
            state.entries.insert(id, Entry { seq, bytes });
            state.bytes_held = state.bytes_held.saturating_add(len);

            while state.bytes_held > self.max_total_bytes {
                let Some((_, victim)) = state.order.pop_first() else {
                    break;
                };
                if let Some(entry) = state.entries.remove(&victim) {
                    let victim_len = entry.bytes.len() as u64;
                    state.bytes_held = state.bytes_held.saturating_sub(victim_len);
                }
                evicted += 1;
            }
        }
        if evicted > 0 {
            debug!(
                evicted,
                ceiling = self.max_total_bytes,
                "body store over its ceiling, dropped the oldest bodies"
            );
        }
    }
}

/// Accumulates a body as it streams past, stopping at the limit.
pub struct BodyWriter {
    id: String,
    limit: u64,
    buf: Vec<u8>,
    /// Every byte offered, including the ones dropped past the limit.
    seen: u64,
    truncated: bool,
    store: Arc<Inner>,
}

impl BodyWriter {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Appends up to the remaining allowance. Past the limit the chunk is
    /// counted and dropped: a body being too big to keep is not an error, and
    /// the flow must keep streaming to the client either way.
    pub fn write(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.seen = self.seen.saturating_add(chunk.len() as u64);

        let held = self.buf.len() as u64;
        if held >= self.limit {
            self.truncated = true;
            return;
        }
        let room = (self.limit - held).min(chunk.len() as u64) as usize;
        self.buf.extend_from_slice(&chunk[..room]);
        if room < chunk.len() {
            self.truncated = true;
        }
    }

    /// Total bytes offered to this writer, which exceeds the retained size
    /// once truncation kicks in.
    pub fn seen(&self) -> u64 {
        self.seen
    }

    /// Commits the retained bytes to the store and describes them.
    pub fn finish(
        self,
        content_encoding: Option<String>,
        content_type: Option<String>,
    ) -> BodyMeta {
        let size = self.buf.len() as u64;
        if self.truncated {
            debug!(
                id = %self.id,
                kept = size,
                seen = self.seen,
                "body truncated at the capture limit"
            );
        }
        self.store.insert(self.id.clone(), Bytes::from(self.buf));
        BodyMeta {
            id: self.id,
            size,
            truncated: self.truncated,
            content_encoding,
            content_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_accounting() {
        let store = BodyStore::new(1024);
        let mut writer = store.writer(64);
        writer.write(b"hello ");
        writer.write(b"world");
        let id = writer.id().to_string();
        let meta = writer.finish(None, Some("text/plain".into()));

        assert_eq!(meta.id, id);
        assert_eq!(meta.size, 11);
        assert!(!meta.truncated);
        assert_eq!(store.read(&id).as_deref(), Some(&b"hello world"[..]));
        assert_eq!(store.bytes_held(), 11);

        store.remove(&id);
        assert!(store.read(&id).is_none());
        assert_eq!(store.bytes_held(), 0);
    }

    #[test]
    fn per_body_limit_truncates_and_is_accounted_once() {
        let store = BodyStore::new(1024);
        let mut writer = store.writer(8);
        writer.write(b"0123456789");
        writer.write(b"more bytes that never land");
        let meta = writer.finish(None, None);

        assert!(meta.truncated);
        assert_eq!(meta.size, 8);
        assert_eq!(store.read(&meta.id).map(|b| b.len()), Some(8));
        assert_eq!(store.bytes_held(), 8);
    }

    #[test]
    fn zero_limit_keeps_nothing() {
        let store = BodyStore::new(1024);
        let mut writer = store.writer(0);
        writer.write(b"anything");
        let meta = writer.finish(None, None);
        assert!(meta.truncated);
        assert_eq!(meta.size, 0);
        assert_eq!(store.bytes_held(), 0);
    }

    #[test]
    fn global_ceiling_evicts_oldest_first() {
        let store = BodyStore::new(20);
        let mut ids = Vec::new();
        for _ in 0..3 {
            let mut writer = store.writer(64);
            writer.write(&[b'x'; 8]);
            ids.push(writer.finish(None, None).id);
        }
        // 24 bytes offered against a 20 byte ceiling: the first body goes.
        assert_eq!(store.bytes_held(), 16);
        assert!(store.read(&ids[0]).is_none());
        assert!(store.read(&ids[1]).is_some());
        assert!(store.read(&ids[2]).is_some());
    }

    #[test]
    fn a_single_body_larger_than_the_ceiling_does_not_leak() {
        let store = BodyStore::new(10);
        let mut writer = store.writer(1000);
        writer.write(&[b'y'; 100]);
        let meta = writer.finish(None, None);

        assert!(store.read(&meta.id).is_none());
        assert_eq!(store.bytes_held(), 0);
    }

    #[test]
    fn clear_returns_bytes_held_to_zero() {
        let store = BodyStore::new(1_000_000);
        for _ in 0..10 {
            let mut writer = store.writer(64);
            writer.write(&[b'z'; 32]);
            writer.finish(None, None);
        }
        assert_eq!(store.bytes_held(), 320);
        store.clear();
        assert_eq!(store.bytes_held(), 0);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn removing_an_unknown_id_is_a_no_op() {
        let store = BodyStore::new(1024);
        let mut writer = store.writer(64);
        writer.write(b"kept");
        let meta = writer.finish(None, None);

        store.remove("does-not-exist");
        store.remove("does-not-exist");
        assert_eq!(store.bytes_held(), 4);
        assert!(store.read(&meta.id).is_some());
    }
}
