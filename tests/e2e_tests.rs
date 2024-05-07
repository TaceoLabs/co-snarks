#[cfg(test)]
mod tests {

    use ark_bn254::Bn254;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use bytes::{Bytes, BytesMut};
    use circom_types::{
        groth16::{witness::Witness, zkey::ZKey},
        r1cs::R1CS,
    };
    use collaborative_groth16::circuit::Circuit;
    use mpc_core::protocols::aby3::{id::PartyID, network::Aby3Network};
    use std::fs::File;
    use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

    //todo remove me and put me in common test crate
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

    #[test]
    fn bn254() {
        let zkey_file = File::open("../test_vectors/bn254/multiplier2.zkey").unwrap();
        let witness_file = File::open("../test_vectors/bn254/witness.wtns").unwrap();
        let r1cs_file = File::open("../test_vectors/bn254/multiplier2.r1cs").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let (pk, _) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
        let r1cs = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
        let circuit = Circuit::new(r1cs, witness);
        let (public_inputs, witness) = circuit.get_wire_mapping();
        for ele in public_inputs {
            println!("{ele}");
        }
        for ele in witness {
            println!("{ele}");
        }
        let test_network = Aby3TestNetwork::default();
    }
}
