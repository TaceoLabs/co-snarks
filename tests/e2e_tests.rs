#[cfg(test)]
mod tests {

    use ark_bn254::Bn254;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use bytes::{Bytes, BytesMut};
    use circom_types::{
        groth16::{proof::JsonProof, witness::Witness, zkey::ZKey},
        r1cs::R1CS,
    };
    use collaborative_groth16::{circuit::Circuit, groth16::CollaborativeGroth16};
    use mpc_core::protocols::aby3::{
        self, fieldshare::Aby3PrimeFieldShareVec, id::PartyID, network::Aby3Network, Aby3Protocol,
    };
    use rand::thread_rng;
    use std::{fs::File, thread};
    use tokio::sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        oneshot,
    };

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

    impl Aby3Network for PartyTestNetwork {
        fn get_id(&self) -> PartyID {
            self.id
        }

        fn send_many<F: CanonicalSerialize>(
            &mut self,
            target: PartyID,
            data: &[F],
        ) -> std::io::Result<()> {
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

        fn recv_many<F: CanonicalDeserialize>(&mut self, from: PartyID) -> std::io::Result<Vec<F>> {
            if self.id.next_id() == from {
                let data = Vec::from(self.recv_next.blocking_recv().unwrap());
                Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
            } else if self.id.prev_id() == from {
                let data = Vec::from(self.recv_prev.blocking_recv().unwrap());
                Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
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

        fn send<F: CanonicalSerialize>(&mut self, target: PartyID, data: F) -> std::io::Result<()> {
            self.send_many(target, &[data])
        }

        fn send_next<F: CanonicalSerialize>(&mut self, data: F) -> std::io::Result<()> {
            self.send(self.get_id().next_id(), data)
        }

        fn send_next_many<F: CanonicalSerialize>(&mut self, data: &[F]) -> std::io::Result<()> {
            self.send_many(self.get_id().next_id(), data)
        }

        fn recv<F: CanonicalDeserialize>(&mut self, from: PartyID) -> std::io::Result<F> {
            let mut res = self.recv_many(from)?;
            if res.len() != 1 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected 1 element, got more",
                ))
            } else {
                Ok(res.pop().unwrap())
            }
        }

        fn recv_prev<F: CanonicalDeserialize>(&mut self) -> std::io::Result<F> {
            self.recv(self.get_id().prev_id())
        }

        fn recv_prev_many<F: CanonicalDeserialize>(&mut self) -> std::io::Result<Vec<F>> {
            self.recv_many(self.get_id().prev_id())
        }
    }

    #[tokio::test]
    async fn e2e_poseidon_bn254() {
        let zkey_file = File::open("../test_vectors/bn254/poseidon/circuit_0000.zkey").unwrap();
        let witness_file = File::open("../test_vectors/bn254/poseidon/witness.wtns").unwrap();
        let r1cs_file = File::open("../test_vectors/bn254/poseidon/poseidon.r1cs").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let (pk1, _) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
        let pk2 = pk1.clone();
        let pk3 = pk1.clone();
        let pvk = prepare_verifying_key(&pk1.vk);
        let r1cs1 = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
        let r1cs2 = r1cs1.clone();
        let r1cs3 = r1cs1.clone();
        let circuit = Circuit::new(r1cs1.clone(), witness);
        let (public_inputs1, witness) = circuit.get_wire_mapping();
        let public_inputs2 = public_inputs1.clone();
        let public_inputs3 = public_inputs1.clone();
        let inputs = circuit.public_inputs();
        let mut rng = thread_rng();
        let mut witness_share1 = Vec::with_capacity(witness.len());
        let mut witness_share2 = Vec::with_capacity(witness.len());
        let mut witness_share3 = Vec::with_capacity(witness.len());
        for w in witness {
            let [s1, s2, s3] = aby3::utils::share_field_element(w, &mut rng);
            witness_share1.push(s1);
            witness_share2.push(s2);
            witness_share3.push(s3);
        }
        let witness_share1 = Aby3PrimeFieldShareVec::from(witness_share1);
        let witness_share2 = Aby3PrimeFieldShareVec::from(witness_share2);
        let witness_share3 = Aby3PrimeFieldShareVec::from(witness_share3);
        let test_network = Aby3TestNetwork::default();
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (((((net, tx), x), r1cs), pk), ins) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip([witness_share1, witness_share2, witness_share3].into_iter())
            .zip([r1cs1, r1cs2, r1cs3].into_iter())
            .zip([pk1, pk2, pk3].into_iter())
            .zip([public_inputs1, public_inputs2, public_inputs3].into_iter())
        {
            thread::spawn(move || {
                let aby3 = Aby3Protocol::<ark_bn254::Fr, PartyTestNetwork>::new(net).unwrap();
                let mut prover = CollaborativeGroth16::<
                    Aby3Protocol<ark_bn254::Fr, PartyTestNetwork>,
                    Bn254,
                >::new(aby3);
                tx.send(prover.prove(&pk, &r1cs, &ins, x).unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
        let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(result1)).unwrap();
        let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
        let verified =
            Groth16::<Bn254>::verify_proof(&pvk, &der_proof.into(), &inputs).expect("can verify");
        assert!(verified);
    }
}
