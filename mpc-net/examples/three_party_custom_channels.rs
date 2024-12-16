use std::path::PathBuf;

use bytes::{Buf, BufMut};
use clap::Parser;
use color_eyre::{
    eyre::{eyre, Context, ContextCompat},
    Result,
};
use futures::{SinkExt, StreamExt};
use mpc_net::{
    config::{NetworkConfig, NetworkConfigFile},
    MpcNetworkHandler,
};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Parser)]
struct Args {
    /// The config file path
    #[clap(short, long, value_name = "FILE")]
    config_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("Could not install default rustls crypto provider"))?;

    let config: NetworkConfigFile =
        toml::from_str(&std::fs::read_to_string(args.config_file).context("opening config file")?)
            .context("parsing config file")?;
    let config = NetworkConfig::try_from(config).context("converting network config")?;
    let my_id = config.my_id;

    let mut network = MpcNetworkHandler::establish(config).await?;

    let codec = MessageCodec;
    let mut channels = network.get_custom_channels(codec).context("get channels")?;

    // send to all channels
    for (&i, channel) in channels.iter_mut() {
        let mes = Message::Ping([i as u8; 1024]);
        channel.send(mes).await?;
    }
    // recv from all channels
    for (&_, channel) in channels.iter_mut() {
        let buf = channel.next().await;
        if let Some(Ok(Message::Ping(b))) = buf {
            assert!(b.iter().all(|&x| x == my_id as u8))
        } else {
            panic!("could not receive message");
        }
    }
    // send to all channels
    for (&i, channel) in channels.iter_mut() {
        let mes = Message::Pong([i as u8; 512]);
        channel.send(mes).await?;
    }
    // recv from all channels
    for (&_, channel) in channels.iter_mut() {
        let buf = channel.next().await;
        if let Some(Ok(Message::Pong(b))) = buf {
            assert!(b.iter().all(|&x| x == my_id as u8))
        } else {
            panic!("could not receive message");
        }
    }

    network.print_connection_stats(&mut std::io::stdout())?;

    Ok(())
}

// A message type that can be sent over the network

#[expect(clippy::large_enum_variant)]
enum Message {
    Ping([u8; 1024]),
    Pong([u8; 512]),
}

impl Message {
    fn id(&self) -> u8 {
        match self {
            Message::Ping(_) => 0,
            Message::Pong(_) => 1,
        }
    }
}

// A codec for the message type
// This is a very inefficient implementation of a codec, but it is just for demonstration purposes

#[derive(Clone, Copy)]
struct MessageCodec;

impl Encoder<Message> for MessageCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        dst.put_u8(item.id());
        match item {
            Message::Ping(buf) => {
                dst.extend_from_slice(&buf);
            }
            Message::Pong(buf) => {
                dst.extend_from_slice(&buf);
            }
        }
        Ok(())
    }
}

impl Decoder for MessageCodec {
    type Item = Message;

    type Error = std::io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }
        let id = src[0];
        match id {
            // ping
            0 => {
                if src.len() < 1025 {
                    return Ok(None);
                }
                let mut buf = [0u8; 1024];
                src.advance(1);
                src.copy_to_slice(&mut buf);
                Ok(Some(Message::Ping(buf)))
            }
            // pong
            1 => {
                if src.len() < 512 + 1 {
                    return Ok(None);
                }
                let mut buf = [0u8; 512];
                src.advance(1);
                src.copy_to_slice(&mut buf);
                Ok(Some(Message::Pong(buf)))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid message id",
            )),
        }
    }
}
