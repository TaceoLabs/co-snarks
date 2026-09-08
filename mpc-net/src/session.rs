//! Shared bookkeeping for the session-based async transports (ephemeral TCP/TLS sessions).
//!
//! Incoming connections announce a `(session_id, party_id)` pair and are parked here until
//! the matching `init_session` call picks them up (or vice versa: `init_session` may register
//! a waiter before the connection arrives).

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{io::AsyncReadExt as _, sync::oneshot};

#[derive(Debug)]
enum MaybeStream<S> {
    Stream(S),
    Waiter(oneshot::Sender<S>),
}

/// Map of parked incoming streams / waiters, keyed by `(session_id, party_id)`.
#[derive(Debug)]
pub(crate) struct SessionStreams<S> {
    #[expect(clippy::type_complexity)]
    streams: Arc<tokio::sync::Mutex<HashMap<(u128, usize), (MaybeStream<S>, Instant)>>>,
}

impl<S> Clone for SessionStreams<S> {
    fn clone(&self) -> Self {
        Self {
            streams: self.streams.clone(),
        }
    }
}

impl<S: Send + 'static> SessionStreams<S> {
    pub(crate) fn new() -> Self {
        Self {
            streams: Arc::default(),
        }
    }

    /// Take the parked stream for `(session_id, party_id)`, or wait until one arrives.
    pub(crate) async fn get(&self, session_id: u128, party_id: usize) -> eyre::Result<S> {
        let mut streams = self.streams.lock().await;
        match streams.remove(&(session_id, party_id)) {
            Some((MaybeStream::Stream(stream), _)) => Ok(stream),
            x @ (None | Some((MaybeStream::Waiter(_), _))) => {
                if x.is_some() {
                    tracing::warn!(
                        "got duplicate connection waiter for session_id {session_id} and party_id {party_id}, replacing old waiter"
                    );
                }
                drop(x); // drop old waiter if it exists, so that old waiter doesn't block forever
                let (tx, rx) = oneshot::channel();
                streams.insert(
                    (session_id, party_id),
                    (MaybeStream::Waiter(tx), Instant::now()),
                );
                drop(streams); // drop to release lock
                Ok(rx.await?)
            }
        }
    }

    /// Read the `(session_id, party_id)` header from `stream` and park it (or hand it to a waiter).
    pub(crate) async fn insert(&self, mut stream: S) -> eyre::Result<()>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        tracing::trace!("reading session id..");
        let session_id = stream.read_u128().await?;
        tracing::trace!("got session id: {session_id:?}");

        tracing::trace!("reading party id..");
        let party_id = stream.read_u64().await? as usize;
        tracing::trace!("got party id: {party_id}");

        let mut streams = self.streams.lock().await;
        match streams.remove(&(session_id, party_id)) {
            Some((MaybeStream::Stream(_), _)) => {
                tracing::warn!(
                    "got duplicate incoming connection for session_id {session_id} and party_id {party_id}, replacing old connection"
                );
                streams.insert(
                    (session_id, party_id),
                    (MaybeStream::Stream(stream), Instant::now()),
                );
            }
            Some((MaybeStream::Waiter(tx), _)) => {
                tracing::trace!("found waiter, sending stream");
                if tx.send(stream).is_err() {
                    tracing::warn!("failed to send stream to waiter, receiver dropped");
                }
            }
            None => {
                tracing::trace!("no waiter found, inserting stream");
                streams.insert(
                    (session_id, party_id),
                    (MaybeStream::Stream(stream), Instant::now()),
                );
            }
        }
        Ok(())
    }

    /// Spawn a background task that periodically drops entries idle for longer than `time_to_idle`.
    pub(crate) fn spawn_cleanup(&self, time_to_idle: Duration) {
        let streams = self.streams.clone();
        let mut interval = tokio::time::interval(time_to_idle * 2);
        tokio::spawn(async move {
            loop {
                interval.tick().await;
                let mut streams = streams.lock().await;
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
