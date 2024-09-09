use super::rep3::PartyTestNetwork as Rep3TestNetworkParty;
use super::shamir::PartyTestNetwork as ShamirTestNetworkParty;
use mpc_core::protocols::bridges::network::RepToShamirNetwork;
use mpc_core::protocols::rep3new::id::PartyID;

impl RepToShamirNetwork<ShamirTestNetworkParty> for Rep3TestNetworkParty {
    fn to_shamir_net(self) -> ShamirTestNetworkParty {
        let Self {
            id,
            send_prev,
            send_next,
            recv_prev,
            recv_next,
            _stats,
        } = self;

        let mut send = Vec::with_capacity(2);
        let mut recv = Vec::with_capacity(2);

        match id {
            PartyID::ID0 => {
                send.push(send_next);
                send.push(send_prev);
                recv.push(recv_next);
                recv.push(recv_prev);
            }
            PartyID::ID1 => {
                send.push(send_prev);
                send.push(send_next);
                recv.push(recv_prev);
                recv.push(recv_next);
            }
            PartyID::ID2 => {
                send.push(send_next);
                send.push(send_prev);
                recv.push(recv_next);
                recv.push(recv_prev);
            }
        }

        ShamirTestNetworkParty {
            id: id.into(),
            num_parties: 3,
            send,
            recv,
        }
    }
}

mod translate_share {
    use crate::protocols::rep3::Rep3TestNetwork;
    use ark_std::UniformRand;
    use itertools::Itertools;
    use mpc_core::protocols::{
        rep3new::{self, network::IoContext},
        shamirnew::{self, ShamirProtocol},
    };
    use rand::thread_rng;
    use std::thread;
    use tokio::sync::oneshot;

    const VEC_SIZE: usize = 10;

    #[tokio::test]
    async fn fieldshare() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3new::share_field_element(x, &mut rng);
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let rep3 = futures::executor::block_on(IoContext::init(net)).unwrap();
                let mut shamir = ShamirProtocol::try_from(rep3).unwrap();
                let share = futures::executor::block_on(shamir.translate_primefield_repshare(x));
                tx.send(share.unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();

        let is_result = shamirnew::combine_field_element(
            &[result1, result2, result3],
            &(1..=3).collect_vec(),
            1,
        )
        .unwrap();

        assert_eq!(is_result, x);
    }

    #[tokio::test]
    async fn fieldshare_vec() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3new::share_field_elements(&x, &mut rng);
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let rep3 = futures::executor::block_on(IoContext::init(net)).unwrap();
                let mut shamir = ShamirProtocol::try_from(rep3).unwrap();
                let share =
                    futures::executor::block_on(shamir.translate_primefield_repshare_vec(x));
                tx.send(share.unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();

        let is_result = shamirnew::combine_field_elements(
            &[result1, result2, result3],
            &(1..=3).collect_vec(),
            1,
        )
        .unwrap();

        assert_eq!(is_result, x);
    }

    #[tokio::test]
    async fn pointshare() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rep3new::share_curve_point(x, &mut rng);
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let rep3 = futures::executor::block_on(IoContext::init(net)).unwrap();
                let mut shamir = ShamirProtocol::try_from(rep3).unwrap();
                let share = futures::executor::block_on(shamir.translate_point_repshare(x));
                tx.send(share.unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();

        let is_result =
            shamirnew::combine_curve_point(&[result1, result2, result3], &(1..=3).collect_vec(), 1)
                .unwrap();

        assert_eq!(is_result, x);
    }
}
