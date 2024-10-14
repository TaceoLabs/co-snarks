use bytes::Bytes;
use std::sync::mpsc::Receiver;

pub mod rep3_network;
pub mod shamir_network;

#[derive(Debug)]
pub enum Msg {
    Data(Bytes),
    Recv(Receiver<Msg>),
}

impl Msg {
    fn into_recv(self) -> Option<Receiver<Msg>> {
        if let Msg::Recv(x) = self {
            Some(x)
        } else {
            None
        }
    }

    fn into_data(self) -> Option<Bytes> {
        if let Msg::Data(x) = self {
            Some(x)
        } else {
            None
        }
    }
}
