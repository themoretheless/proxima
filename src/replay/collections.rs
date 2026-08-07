//! Saved requests, folders of them, and reusable variable sets.
//!
//! Everything lives in a single `collections.json` under the data directory.
//! One file keeps the on-disk story simple: it can be copied, diffed and
//! checked into a repository, and there is exactly one thing to write
//! atomically. The in-memory copy is authoritative while the process runs; the
//! file is rewritten in full after every mutation.

use std::collections::HashMap;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

const FILE_NAME: &str = "collections.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedRequest {
    pub id: String,
    pub name: String,
    /// A [`crate::replay::SendSpec`] shaped value, kept opaque here so the
    /// composer can grow fields without a migration of everybody's saved work.
    pub spec: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub id: String,
    pub name: String,
    pub requests: Vec<SavedRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: String,
    pub name: String,
    pub variables: HashMap<String, String>,
}

/// The whole file. `#[serde(default)]` on both fields means a file written by
/// an older build that only knew about collections still loads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Persisted {
    #[serde(default)]
    collections: Vec<Collection>,
    #[serde(default)]
    environments: Vec<Environment>,
    /// Environment applied by default when a send omits `environmentId`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_environment_id: Option<String>,
}

pub struct CollectionStore {
    path: PathBuf,
    state: Mutex<Persisted>,
    /// Held for the whole of a mutation and the write that follows it. The
    /// state lock alone is not enough: it is released before `persist` runs, so
    /// two writers could take their snapshots in one order and reach the disk in
    /// the other, leaving the file showing a state that was already superseded.
    writes: Mutex<()>,
}

impl CollectionStore {
    /// Loads `<data_dir>/collections.json`. A missing file is an empty store,
    /// and so is an unparseable one: losing saved requests is bad, but refusing
    /// to start the whole proxy over a stray byte is worse. The bad file is
    /// left on disk untouched until the next write so it can be recovered by
    /// hand.
    pub fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("could not create {}", data_dir.display()))?;
        let path = data_dir.join(FILE_NAME);

        let state = match std::fs::read(&path) {
            Ok(raw) => match serde_json::from_slice::<Persisted>(&raw) {
                Ok(parsed) => {
                    debug!(
                        collections = parsed.collections.len(),
                        environments = parsed.environments.len(),
                        "loaded saved requests"
                    );
                    parsed
                }
                Err(error) => {
                    warn!(
                        path = %path.display(),
                        %error,
                        "collections file could not be parsed, starting empty"
                    );
                    Persisted::default()
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Persisted::default(),
            Err(error) => {
                warn!(path = %path.display(), %error, "collections file could not be read, starting empty");
                Persisted::default()
            }
        };

        Ok(Self {
            path,
            state: Mutex::new(state),
            writes: Mutex::new(()),
        })
    }

    pub fn collections(&self) -> Vec<Collection> {
        self.state.lock().collections.clone()
    }

    /// Inserts or replaces by id. An empty id means "new", and the generated id
    /// comes back in the returned value so the caller can address it later.
    pub fn upsert_collection(&self, mut c: Collection) -> Result<Collection> {
        if c.id.trim().is_empty() {
            c.id = new_id();
        }
        for request in &mut c.requests {
            if request.id.trim().is_empty() {
                request.id = new_id();
            }
        }

        let _writing = self.writes.lock();
        let snapshot = {
            let mut state = self.state.lock();
            match state.collections.iter_mut().find(|e| e.id == c.id) {
                Some(existing) => *existing = c.clone(),
                None => state.collections.push(c.clone()),
            }
            state.clone()
        };
        self.persist(&snapshot)?;
        Ok(c)
    }

    pub fn delete_collection(&self, id: &str) -> Result<bool> {
        let _writing = self.writes.lock();
        let (removed, snapshot) = {
            let mut state = self.state.lock();
            let before = state.collections.len();
            state.collections.retain(|c| c.id != id);
            (state.collections.len() != before, state.clone())
        };
        if removed {
            self.persist(&snapshot)?;
        }
        Ok(removed)
    }

    pub fn environments(&self) -> Vec<Environment> {
        self.state.lock().environments.clone()
    }

    pub fn upsert_environment(&self, mut e: Environment) -> Result<Environment> {
        if e.id.trim().is_empty() {
            e.id = new_id();
        }

        let _writing = self.writes.lock();
        let snapshot = {
            let mut state = self.state.lock();
            match state.environments.iter_mut().find(|x| x.id == e.id) {
                Some(existing) => *existing = e.clone(),
                None => state.environments.push(e.clone()),
            }
            state.clone()
        };
        self.persist(&snapshot)?;
        Ok(e)
    }

    pub fn delete_environment(&self, id: &str) -> Result<bool> {
        let _writing = self.writes.lock();
        let (removed, snapshot) = {
            let mut state = self.state.lock();
            let before = state.environments.len();
            state.environments.retain(|e| e.id != id);
            if state.active_environment_id.as_deref() == Some(id) {
                state.active_environment_id = None;
            }
            (state.environments.len() != before, state.clone())
        };
        if removed {
            self.persist(&snapshot)?;
        }
        Ok(removed)
    }

    pub fn active_environment_id(&self) -> Option<String> {
        self.state.lock().active_environment_id.clone()
    }

    /// Sets or clears the active environment. An unknown id is an error.
    pub fn set_active_environment(&self, id: Option<String>) -> Result<Option<String>> {
        let _writing = self.writes.lock();
        let snapshot = {
            let mut state = self.state.lock();
            if let Some(ref want) = id {
                if !state.environments.iter().any(|e| e.id == *want) {
                    anyhow::bail!("no environment with id {want}");
                }
            }
            state.active_environment_id = id;
            state.clone()
        };
        self.persist(&snapshot)?;
        Ok(snapshot.active_environment_id)
    }

    /// Variables for `environment_id`, or the active environment when `None`.
    pub fn variables_for(&self, environment_id: Option<&str>) -> HashMap<String, String> {
        let state = self.state.lock();
        let id = environment_id
            .map(|s| s.to_string())
            .or_else(|| state.active_environment_id.clone());
        let Some(id) = id else {
            return HashMap::new();
        };
        state
            .environments
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.variables.clone())
            .unwrap_or_default()
    }

    /// Writes a sibling temporary file, flushes it to the platter and renames
    /// it over the real one. Rename within a directory is atomic, so a crash
    /// mid-write leaves either the previous file or the new one, never a
    /// half-written mixture of the two.
    fn persist(&self, data: &Persisted) -> Result<()> {
        let json = serde_json::to_vec_pretty(data).context("could not serialise collections")?;
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;

        let tmp = dir.join(format!(".{FILE_NAME}.{}.tmp", new_id()));
        let write = (|| -> io::Result<()> {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(&json)?;
            file.sync_all()
        })();
        if let Err(error) = write {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow::Error::new(error)
                .context(format!("could not write {}", tmp.display())));
        }

        if let Err(error) = std::fs::rename(&tmp, &self.path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow::Error::new(error)
                .context(format!("could not replace {}", self.path.display())));
        }

        // The rename is a change to the directory, and the directory has its own
        // metadata still sitting in the page cache. Without this a crash right
        // after a save can come back up with the old file, having fsynced the
        // new contents but not the entry that points at them. Not being able to
        // open a directory is a platform difference rather than a failure to
        // save, so it is logged and not returned.
        match std::fs::File::open(dir) {
            Ok(handle) => {
                if let Err(error) = handle.sync_all() {
                    debug!(path = %dir.display(), %error, "could not flush the data directory");
                }
            }
            Err(error) => {
                debug!(path = %dir.display(), %error, "could not open the data directory to flush it");
            }
        }
        Ok(())
    }
}

fn new_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(16);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    fn collection(id: &str, name: &str) -> Collection {
        Collection {
            id: id.to_string(),
            name: name.to_string(),
            requests: vec![SavedRequest {
                id: String::new(),
                name: "list users".to_string(),
                spec: serde_json::json!({ "method": "GET", "url": "https://api.test/users" }),
            }],
        }
    }

    #[test]
    fn round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = CollectionStore::open(dir.path()).unwrap();
        assert!(store.collections().is_empty());
        assert!(store.environments().is_empty());

        let saved = store.upsert_collection(collection("", "Users API")).unwrap();
        assert!(!saved.id.is_empty(), "an empty id should be filled in");
        assert!(
            !saved.requests[0].id.is_empty(),
            "nested requests should get ids too"
        );

        store
            .upsert_environment(Environment {
                id: "staging".to_string(),
                name: "Staging".to_string(),
                variables: HashMap::from([("host".to_string(), "api.staging.test".to_string())]),
            })
            .unwrap();

        drop(store);

        let reopened = CollectionStore::open(dir.path()).unwrap();
        let collections = reopened.collections();
        assert_eq!(collections.len(), 1);
        assert_eq!(collections[0].name, "Users API");
        assert_eq!(collections[0].id, saved.id);
        assert_eq!(collections[0].requests.len(), 1);

        let envs = reopened.environments();
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].variables.get("host").map(String::as_str), Some("api.staging.test"));
    }

    #[test]
    fn upsert_replaces_rather_than_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let store = CollectionStore::open(dir.path()).unwrap();

        store.upsert_collection(collection("fixed", "First")).unwrap();
        store.upsert_collection(collection("fixed", "Second")).unwrap();

        let all = store.collections();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Second");
    }

    #[test]
    fn delete_reports_whether_anything_went() {
        let dir = tempfile::tempdir().unwrap();
        let store = CollectionStore::open(dir.path()).unwrap();
        store.upsert_collection(collection("gone", "Gone")).unwrap();

        assert!(store.delete_collection("gone").unwrap());
        assert!(!store.delete_collection("gone").unwrap());
        assert!(store.collections().is_empty());

        assert!(!store.delete_environment("never existed").unwrap());
    }

    #[test]
    fn no_temporary_files_are_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = CollectionStore::open(dir.path()).unwrap();
        store.upsert_collection(collection("a", "A")).unwrap();
        store.upsert_collection(collection("b", "B")).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left temporary files: {leftovers:?}");
    }

    #[test]
    fn concurrent_writes_all_survive_on_disk() {
        // The mutation and the write that follows it have to be one step. If
        // they are not, two writers can take their snapshots in one order and
        // reach the disk in the other, and the file ends up missing whatever
        // the slower one had already committed to memory.
        // Every writer in a round has returned before the file is read, and
        // `upsert_collection` does not return until its own write is on disk, so
        // a short file means one write overwrote a newer one.
        const WRITERS: usize = 8;
        const ROUNDS: usize = 16;

        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(CollectionStore::open(dir.path()).unwrap());

        for round in 0..ROUNDS {
            std::thread::scope(|scope| {
                for writer in 0..WRITERS {
                    let store = store.clone();
                    scope.spawn(move || {
                        let id = format!("c-{round}-{writer}");
                        store
                            .upsert_collection(collection(&id, &id))
                            .expect("saving a collection");
                    });
                }
            });

            let expected = (round + 1) * WRITERS;
            assert_eq!(store.collections().len(), expected, "in memory, round {round}");

            let on_disk = CollectionStore::open(dir.path()).unwrap().collections();
            assert_eq!(
                on_disk.len(),
                expected,
                "round {round} left {} of {expected} saved collections on disk",
                on_disk.len()
            );
        }
    }

    #[test]
    fn a_corrupt_file_starts_empty_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), b"{ this is not json").unwrap();

        let store = CollectionStore::open(dir.path()).unwrap();
        assert!(store.collections().is_empty());

        // Still usable afterwards: the next write replaces the broken file.
        store.upsert_collection(collection("fresh", "Fresh")).unwrap();
        let reopened = CollectionStore::open(dir.path()).unwrap();
        assert_eq!(reopened.collections().len(), 1);
    }
}
