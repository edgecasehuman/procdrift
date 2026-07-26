use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::mpsc::{self, Sender};
use std::thread;

pub const CACHE_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SelectionKey {
    pub pid: u32,
    pub created: u64,
}

#[derive(Clone, Debug)]
pub struct DetailRequest {
    pub key: SelectionKey,
    pub name: String,
    pub path: String,
}

pub use crate::signature::SignatureState;

#[derive(Clone, Debug)]
pub struct DetailResult {
    pub key: SelectionKey,
    pub name: String,
    pub path: String,
    pub file_size: Option<u64>,
    pub modified_unix_seconds: Option<u64>,
    pub signature: SignatureState,
    pub signer: Option<String>,
}

impl DetailResult {
    pub fn summary(&self) -> String {
        let size = self.file_size.map_or_else(
            || "Unavailable".to_owned(),
            |value| format!("{value} bytes"),
        );
        let description = crate::knowledge::describe(&self.name)
            .map(|text| format!("\n\nAbout {}: {text}", self.name))
            .unwrap_or_default();
        format!(
            "File: {}\nSize: {}\nModified (Unix seconds): {}\nAuthenticode: {}\nSigner: {}{description}",
            if self.path.is_empty() {
                "Unavailable"
            } else {
                &self.path
            },
            size,
            self.modified_unix_seconds
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or("Unavailable"),
            self.signature.label(),
            self.signer.as_deref().unwrap_or("Unavailable")
        )
    }
}

enum Command {
    Inspect(DetailRequest),
    Stop,
}

pub struct DetailWorker {
    sender: Sender<Command>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DetailWorker {
    pub fn start(deliver: impl Fn(DetailResult) + Send + 'static) -> Result<Self, String> {
        let (sender, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("procdrift-details".to_owned())
            // WinVerifyTrust and the catalog providers recurse through the
            // certificate chain and need considerably more room than the
            // metadata-only lookups this worker started out doing.
            .stack_size(1024 * 1024)
            .spawn(move || {
                let mut cache = BoundedCache::default();
                while let Ok(command) = receiver.recv() {
                    match command {
                        Command::Inspect(request) => {
                            let result = cache.get(&request.key).unwrap_or_else(|| {
                                let result = inspect(request);
                                cache.insert(result.clone());
                                result
                            });
                            deliver(result);
                        }
                        Command::Stop => break,
                    }
                }
            })
            .map_err(|error| format!("could not start details worker: {error}"))?;
        Ok(Self {
            sender,
            thread: Some(thread),
        })
    }

    pub fn inspect(&self, request: DetailRequest) -> Result<(), String> {
        self.sender
            .send(Command::Inspect(request))
            .map_err(|_| "details worker stopped".to_owned())
    }
}

impl Drop for DetailWorker {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Default)]
struct BoundedCache {
    entries: HashMap<SelectionKey, DetailResult>,
    order: VecDeque<SelectionKey>,
}

impl BoundedCache {
    fn get(&mut self, key: &SelectionKey) -> Option<DetailResult> {
        let result = self.entries.get(key).cloned()?;
        self.order.retain(|candidate| candidate != key);
        self.order.push_back(*key);
        Some(result)
    }

    fn insert(&mut self, result: DetailResult) {
        self.order.retain(|key| key != &result.key);
        self.order.push_back(result.key);
        self.entries.insert(result.key, result);
        while self.entries.len() > CACHE_LIMIT {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }
}

fn inspect(request: DetailRequest) -> DetailResult {
    let metadata = (!request.path.is_empty())
        .then(|| fs::metadata(&request.path).ok())
        .flatten();
    let file_size = metadata.as_ref().map(fs::Metadata::len);
    let modified_unix_seconds = metadata
        .and_then(|value| value.modified().ok())
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| value.as_secs());
    // Authenticode verification runs on this worker thread, never the UI
    // thread: resolving a catalog can touch the disk and take tens of
    // milliseconds on a cold cache.
    let verdict = crate::signature::verify(std::path::Path::new(&request.path));
    DetailResult {
        key: request.key,
        name: request.name,
        path: request.path,
        file_size,
        modified_unix_seconds,
        signature: verdict.state,
        signer: verdict.signer,
    }
}

pub fn is_current_selection(expected: Option<SelectionKey>, result: &DetailResult) -> bool {
    expected == Some(result.key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(pid: u32) -> DetailResult {
        DetailResult {
            key: SelectionKey {
                pid,
                created: pid.into(),
            },
            name: "test".into(),
            path: String::new(),
            file_size: None,
            modified_unix_seconds: None,
            signature: SignatureState::Unavailable,
            signer: None,
        }
    }

    #[test]
    fn cache_is_bounded_and_recently_used_entries_survive() {
        let mut cache = BoundedCache::default();
        for pid in 0..=CACHE_LIMIT as u32 {
            cache.insert(result(pid));
        }
        assert_eq!(cache.entries.len(), CACHE_LIMIT);
        assert!(
            !cache
                .entries
                .contains_key(&SelectionKey { pid: 0, created: 0 })
        );
    }

    #[test]
    fn stale_enrichment_is_rejected_by_pid_and_creation_time() {
        let value = result(8);
        assert!(is_current_selection(Some(value.key), &value));
        assert!(!is_current_selection(
            Some(SelectionKey {
                pid: 8,
                created: 999
            }),
            &value
        ));
    }

    #[test]
    fn signature_states_are_explicit() {
        // "Unavailable" must stay distinct from "Unsigned" in the text the
        // detail pane shows, because collapsing them would read as a claim
        // about a file that was never successfully checked.
        let labels = [
            SignatureState::Trusted.label(),
            SignatureState::Unsigned.label(),
            SignatureState::Invalid.label(),
            SignatureState::Unavailable.label(),
        ];
        assert_eq!(labels, ["Trusted", "Unsigned", "Invalid", "Unavailable"]);
    }
}
