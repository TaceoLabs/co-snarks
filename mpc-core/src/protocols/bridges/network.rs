use std::collections::HashMap;

use crate::protocols::{
    rep3::network::{Rep3MpcNet, Rep3Network},
    shamir::network::{ShamirMpcNet, ShamirNetwork},
};

pub trait RepToShamirNetwork<N: ShamirNetwork>: Rep3Network {
    fn to_shamir_net(self) -> N;
}

impl RepToShamirNetwork<ShamirMpcNet> for Rep3MpcNet {
    fn to_shamir_net(self) -> ShamirMpcNet {
        let Self {
            id,
            runtime,
            net_handler,
            chan_next,
            chan_prev,
        } = self;

        let mut channels = HashMap::with_capacity(2);
        channels.insert(id.next_id().into(), chan_next);
        channels.insert(id.prev_id().into(), chan_prev);

        ShamirMpcNet {
            id: id.into(),
            num_parties: 3,
            runtime,
            net_handler,
            channels,
        }
    }
}
