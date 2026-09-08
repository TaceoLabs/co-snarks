//! Shared bookkeeping for the blocking session-based transports (ephemeral TCP/TLS sessions).
//!
//! Incoming connections announce a key (e.g. `(session_id, party_id)`) and are parked here
//! until the matching `init_session` call picks them up (or vice versa: `init_session` may
//! register a waiter before the connection arrives). Header parsing is up to the caller.

use std::{
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crossbeam_channel::Sender;
use eyre::Context as _;

#[derive(Debug)]
enum MaybeStream<S> {
    Stream(S),
    Waiter(Sender<S>),
}

/// Map of parked incoming streams / waiters, keyed by `K`.
#[derive(Debug)]
pub(crate) struct SessionStreams<K, S> {
    #[expect(clippy::type_complexity)]
    streams: Arc<Mutex<HashMap<K, (MaybeStream<S>, Instant)>>>,
}

impl<K, S> Clone for SessionStreams<K, S> {
    fn clone(&self) -> Self {
        Self {
            streams: self.streams.clone(),
        }
    }
}

impl<K: Hash + Eq + Copy + Debug + Send + 'static, S: Send + 'static> SessionStreams<K, S> {
    pub(crate) fn new() -> Self {
        Self {
            streams: Arc::default(),
        }
    }

    /// Take the parked stream for `key`, or wait (at most `timeout`) until one arrives.
    pub(crate) fn get(&self, key: K, timeout: Option<Duration>) -> eyre::Result<S> {
        let mut streams = self.streams.lock().expect("not poisoned");
        match streams.remove(&key) {
            Some((MaybeStream::Stream(stream), _)) => Ok(stream),
            x @ (None | Some((MaybeStream::Waiter(_), _))) => {
                if x.is_some() {
                    tracing::warn!(
                        "got duplicate connection waiter for {key:?}, replacing old waiter"
                    );
                }
                drop(x); // drop old waiter if it exists, so that old waiter doesn't block forever
                let (tx, rx) = crossbeam_channel::bounded(1);
                streams.insert(key, (MaybeStream::Waiter(tx), Instant::now()));
                drop(streams); // drop to release lock
                if let Some(timeout) = timeout {
                    rx.recv_timeout(timeout)
                        .context("while waiting for incoming connection")
                } else {
                    rx.recv().context("while waiting for incoming connection")
                }
            }
        }
    }

    /// Park `stream` under `key`, or hand it to a waiter already registered for `key`.
    pub(crate) fn insert(&self, key: K, stream: S) {
        let mut streams = self.streams.lock().expect("not poisoned");
        match streams.remove(&key) {
            Some((MaybeStream::Stream(_), _)) => {
                tracing::warn!(
                    "got duplicate incoming connection for {key:?}, replacing old connection"
                );
                streams.insert(key, (MaybeStream::Stream(stream), Instant::now()));
            }
            Some((MaybeStream::Waiter(tx), _)) => {
                tracing::trace!("found waiter, sending stream");
                if tx.send(stream).is_err() {
                    tracing::warn!("failed to send stream to waiter, receiver dropped");
                }
            }
            None => {
                tracing::trace!("no waiter found, inserting stream");
                streams.insert(key, (MaybeStream::Stream(stream), Instant::now()));
            }
        }
    }

    /// Spawn a background thread that periodically drops entries idle for longer than `time_to_idle`.
    pub(crate) fn spawn_cleanup(&self, time_to_idle: Duration) {
        let streams = self.streams.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(time_to_idle * 2);
                let mut streams = streams.lock().expect("not poisoned");
                let now = Instant::now();
                let before_cleanup = streams.len();
                streams.retain(|_, (_, last_used)| now.duration_since(*last_used) < time_to_idle);
                let removed = before_cleanup - streams.len();
                if removed > 0 {
                    tracing::warn!(
                        "cleaned up {removed} idle streams - this means that some some MPC operations likely failed"
                    );
                }
            }
        });
    }
}
