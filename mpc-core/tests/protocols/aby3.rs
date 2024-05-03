use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::{Bytes, BytesMut};
use mpc_core::protocols::aby3::id::PartyID;
use mpc_core::protocols::aby3::network::Aby3Network;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

pub struct Aby3TestNetwork {
    p1_p2_sender: UnboundedSender<Bytes>,
    p1_p3_sender: UnboundedSender<Bytes>,
    p2_p3_sender: UnboundedSender<Bytes>,
    p2_p1_sender: UnboundedSender<Bytes>,
    p3_p1_sender: UnboundedSender<Bytes>,
    p3_p2_sender: UnboundedSender<Bytes>,
    p1_p2_receiver: UnboundedReceiver<Bytes>,
    p1_p3_receiver: UnboundedReceiver<Bytes>,
    p2_p3_receiver: UnboundedReceiver<Bytes>,
    p2_p1_receiver: UnboundedReceiver<Bytes>,
    p3_p1_receiver: UnboundedReceiver<Bytes>,
    p3_p2_receiver: UnboundedReceiver<Bytes>,
}

impl Default for Aby3TestNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl Aby3TestNetwork {
    pub fn new() -> Self {
        // AT Most 1 message is buffered before they are read so this should be fine
        let p1_p2 = mpsc::unbounded_channel();
        let p1_p3 = mpsc::unbounded_channel();
        let p2_p3 = mpsc::unbounded_channel();
        let p2_p1 = mpsc::unbounded_channel();
        let p3_p1 = mpsc::unbounded_channel();
        let p3_p2 = mpsc::unbounded_channel();

        Self {
            p1_p2_sender: p1_p2.0,
            p1_p3_sender: p1_p3.0,
            p2_p1_sender: p2_p1.0,
            p2_p3_sender: p2_p3.0,
            p3_p1_sender: p3_p1.0,
            p3_p2_sender: p3_p2.0,
            p1_p2_receiver: p1_p2.1,
            p1_p3_receiver: p1_p3.1,
            p2_p1_receiver: p2_p1.1,
            p2_p3_receiver: p2_p3.1,
            p3_p1_receiver: p3_p1.1,
            p3_p2_receiver: p3_p2.1,
        }
    }

    pub fn get_party_networks(self) -> [PartyTestNetwork; 3] {
        let party1 = PartyTestNetwork {
            id: PartyID::ID0,
            send_prev: self.p1_p3_sender,
            recv_prev: self.p3_p1_receiver,
            send_next: self.p1_p2_sender,
            recv_next: self.p2_p1_receiver,
            _stats: [0; 4],
        };

        let party2 = PartyTestNetwork {
            id: PartyID::ID1,
            send_prev: self.p2_p1_sender,
            recv_prev: self.p1_p2_receiver,
            send_next: self.p2_p3_sender,
            recv_next: self.p3_p2_receiver,
            _stats: [0; 4],
        };

        let party3 = PartyTestNetwork {
            id: PartyID::ID2,
            send_prev: self.p3_p2_sender,
            recv_prev: self.p2_p3_receiver,
            send_next: self.p3_p1_sender,
            recv_next: self.p1_p3_receiver,
            _stats: [0; 4],
        };

        [party1, party2, party3]
    }
}

pub struct PartyTestNetwork {
    id: PartyID,
    send_prev: UnboundedSender<Bytes>,
    send_next: UnboundedSender<Bytes>,
    recv_prev: UnboundedReceiver<Bytes>,
    recv_next: UnboundedReceiver<Bytes>,
    _stats: [usize; 4], // [sent_prev, sent_next, recv_prev, recv_next]
}

impl Aby3Network<ark_bn254::Fr> for PartyTestNetwork {
    fn get_id(&self) -> PartyID {
        self.id
    }

    fn send_many(&mut self, target: PartyID, data: &[ark_bn254::Fr]) -> std::io::Result<()> {
        let mut to_send = Vec::with_capacity(data.len() * 32);
        data.serialize_uncompressed(&mut to_send).unwrap();
        if self.id.next_id() == target {
            self.send_next
                .send(Bytes::from(to_send))
                .expect("can send to next")
        } else if self.id.prev_id() == target {
            self.send_prev
                .send(Bytes::from(to_send))
                .expect("can send to next");
        } else {
            panic!("You want to send to yourself?")
        }
        Ok(())
    }

    fn recv_many(&mut self, from: PartyID) -> std::io::Result<Vec<ark_bn254::Fr>> {
        if self.id.next_id() == from {
            let data = Vec::from(self.recv_next.blocking_recv().unwrap());
            Ok(Vec::<ark_bn254::Fr>::deserialize_uncompressed(data.as_slice()).unwrap())
        } else if self.id.prev_id() == from {
            let data = Vec::from(self.recv_prev.blocking_recv().unwrap());
            Ok(Vec::<ark_bn254::Fr>::deserialize_uncompressed(data.as_slice()).unwrap())
        } else {
            panic!("You want to read from yourself?")
        }
    }

    fn send_and_receive_seed(&mut self, seed: Bytes) -> std::io::Result<BytesMut> {
        self.send_next.send(seed).expect("can send to next");
        let mut their_seed = BytesMut::new();
        their_seed.extend(self.recv_prev.blocking_recv().unwrap().to_vec());
        Ok(their_seed)
    }
}
mod field_share {
    use ark_std::UniformRand;
    use std::{collections::HashSet, thread};

    use mpc_core::protocols::aby3::{self, Aby3Protocol};
    use rand::thread_rng;
    use tokio::sync::oneshot;

    use crate::protocols::aby3::Aby3TestNetwork;
    use mpc_core::traits::PrimeFieldMpcProtocol;

    #[tokio::test]
    async fn aby3_add() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = aby3::utils::share_field_element(x, &mut rng);
        let y_shares = aby3::utils::share_field_element(y, &mut rng);
        let should_result = x + y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = Aby3Protocol::new(net).unwrap();
                tx.send(aby3.add(&x, &y))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = aby3::utils::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn aby3_sub() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = aby3::utils::share_field_element(x, &mut rng);
        let y_shares = aby3::utils::share_field_element(y, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = Aby3Protocol::new(net).unwrap();
                tx.send(aby3.sub(&x, &y))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = aby3::utils::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }
    #[tokio::test]
    async fn aby3_mul_then_add() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = aby3::utils::share_field_element(x, &mut rng);
        let y_shares = aby3::utils::share_field_element(y, &mut rng);
        let should_result = (x * y) + y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = Aby3Protocol::new(net).unwrap();
                let mul = aby3.mul(&x, &y).unwrap();
                tx.send(aby3.add(&mul, &y))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = aby3::utils::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn aby3_neg() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = aby3::utils::share_field_element(x, &mut rng);
        let should_result = -x;
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
                let mut aby3 = Aby3Protocol::new(net).unwrap();
                tx.send(aby3.neg(&x))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = aby3::utils::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn aby3_random() {
        let test_network = Aby3TestNetwork::default();
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (net, tx) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
        {
            thread::spawn(move || {
                let mut aby3 = Aby3Protocol::new(net).unwrap();
                tx.send((0..10).map(|_| aby3.rand()).collect::<Vec<_>>())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        assert_eq!(result1.iter().collect::<HashSet<_>>().len(), 10);
        assert_eq!(result2.iter().collect::<HashSet<_>>().len(), 10);
        assert_eq!(result3.iter().collect::<HashSet<_>>().len(), 10);
        for ((s1, s2), s3) in result1.into_iter().zip(result2).zip(result3) {
            let (s1a, s1b) = s1.ab();
            let (s2a, s2b) = s2.ab();
            let (s3a, s3b) = s3.ab();
            assert_eq!(s1a, s2b);
            assert_eq!(s2a, s3b);
            assert_eq!(s3a, s1b);
        }
    }
}

mod curve_share {
    use ark_std::UniformRand;
    use std::thread;

    use mpc_core::protocols::aby3::{self, Aby3Protocol};
    use rand::thread_rng;
    use tokio::sync::oneshot;

    use crate::protocols::aby3::Aby3TestNetwork;
    use mpc_core::traits::EcMpcProtocol;

    #[tokio::test]
    async fn aby3_add() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let y = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = aby3::utils::share_curve_point(x, &mut rng);
        let y_shares = aby3::utils::share_curve_point(y, &mut rng);
        let should_result = x + y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = Aby3Protocol::new(net).unwrap();
                tx.send(aby3.add_points(&x, &y))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = aby3::utils::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn aby3_sub() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let y = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = aby3::utils::share_curve_point(x, &mut rng);
        let y_shares = aby3::utils::share_curve_point(y, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = Aby3Protocol::new(net).unwrap();
                tx.send(aby3.sub_points(&x, &y))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = aby3::utils::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn aby3_scalar_mul_public_point() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let public_point = ark_bn254::G1Projective::rand(&mut rng);
        let scalar = ark_bn254::Fr::rand(&mut rng);
        let scalar_shares = aby3::utils::share_field_element(scalar, &mut rng);
        let should_result = public_point * scalar;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), scalar) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(scalar_shares.into_iter())
        {
            thread::spawn(move || {
                let mut aby3 = Aby3Protocol::new(net).unwrap();
                tx.send(aby3.scalar_mul_public_point(&public_point, &scalar))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = aby3::utils::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn aby3_scalar_mul_public_scalar() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let point = ark_bn254::G1Projective::rand(&mut rng);
        let public_scalar = ark_bn254::Fr::rand(&mut rng);
        let point_shares = aby3::utils::share_curve_point(point, &mut rng);
        let should_result = point * public_scalar;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), point) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(point_shares.into_iter())
        {
            thread::spawn(move || {
                let mut aby3 = Aby3Protocol::new(net).unwrap();
                tx.send(aby3.scalar_mul_public_scalar(&point, &public_scalar))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = aby3::utils::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }
}
