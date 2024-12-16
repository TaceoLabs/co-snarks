//! A queue implementation that uses actors to creat new channels.

use std::collections::{HashMap, VecDeque};

use bytes::{Bytes, BytesMut};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};

use crate::{channel::ChannelHandle, MpcNetworkHandler};

pub(crate) struct CreateJob;

pub(crate) enum QueueJob {
    GetChannels(oneshot::Sender<HashMap<usize, ChannelHandle<Bytes, BytesMut>>>),
    PutChannels(HashMap<usize, ChannelHandle<Bytes, BytesMut>>),
}

/// A queue of channels with each party.
#[derive(Debug, Clone)]
pub struct ChannelQueue {
    sender: Sender<QueueJob>,
}

impl ChannelQueue {
    pub(crate) fn new(sender: Sender<QueueJob>) -> Self {
        Self { sender }
    }

    /// Get a channels from the queue. New connections will be created in the background.
    pub fn get_channels(&self) -> eyre::Result<HashMap<usize, ChannelHandle<Bytes, BytesMut>>> {
        let (send, recv) = oneshot::channel();
        self.sender.blocking_send(QueueJob::GetChannels(send))?;
        Ok(recv.blocking_recv()?)
    }
}

/// Spawn connection creating actor that holds net_handler
pub(crate) async fn create_channel_actor(
    net_handler: MpcNetworkHandler,
    mut receiver: Receiver<CreateJob>,
    queue_sender: Sender<QueueJob>,
) -> eyre::Result<()> {
    while (receiver.recv().await).is_some() {
        let handles = net_handler.get_byte_channels_managed().await?;
        queue_sender.send(QueueJob::PutChannels(handles)).await?;
    }
    Ok(())
}

/// Spawn queue actor that holds connection and requests new ones
pub(crate) async fn get_channel_actor(
    init_queue: Vec<HashMap<usize, ChannelHandle<Bytes, BytesMut>>>,
    create_sender: Sender<CreateJob>,
    mut receiver: Receiver<QueueJob>,
) -> eyre::Result<()> {
    let mut queue = VecDeque::from(init_queue);
    let mut open_get_jobs = VecDeque::new();
    while let Some(job) = receiver.recv().await {
        match job {
            QueueJob::GetChannels(sender) => {
                if let Some(handles) = queue.pop_back() {
                    sender.send(handles).expect("recv is alive");
                } else {
                    open_get_jobs.push_front(sender);
                }
                create_sender.send(CreateJob).await?;
            }
            QueueJob::PutChannels(handles) => {
                if let Some(sender) = open_get_jobs.pop_back() {
                    sender.send(handles).expect("recv is alive");
                } else {
                    queue.push_front(handles);
                }
            }
        }
    }
    Ok(())
}
