#[cfg(test)]
mod rep3_tests {

    use ark_bn254::Bn254;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use bytes::Bytes;
    use circom_types::groth16::{proof::JsonProof, witness::Witness, zkey::ZKey};
    use circom_types::r1cs::R1CS;
    use collaborative_groth16::{
        circuit::Circuit,
        groth16::{CollaborativeGroth16, SharedWitness},
    };
    use mpc_core::protocols::rep3::{id::PartyID, network::Rep3Network, Rep3Protocol};
    use rand::thread_rng;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::{fs::File, thread};

    //todo remove me and put me in common test crate
    pub struct Rep3TestNetwork {
        p1_p2_sender: Sender<Bytes>,
        p1_p3_sender: Sender<Bytes>,
        p2_p3_sender: Sender<Bytes>,
        p2_p1_sender: Sender<Bytes>,
        p3_p1_sender: Sender<Bytes>,
        p3_p2_sender: Sender<Bytes>,
        p1_p2_receiver: Receiver<Bytes>,
        p1_p3_receiver: Receiver<Bytes>,
        p2_p3_receiver: Receiver<Bytes>,
        p2_p1_receiver: Receiver<Bytes>,
        p3_p1_receiver: Receiver<Bytes>,
        p3_p2_receiver: Receiver<Bytes>,
    }

    impl Default for Rep3TestNetwork {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Rep3TestNetwork {
        pub fn new() -> Self {
            // AT Most 1 message is buffered before they are read so this should be fine
            let p1_p2 = mpsc::channel();
            let p1_p3 = mpsc::channel();
            let p2_p3 = mpsc::channel();
            let p2_p1 = mpsc::channel();
            let p3_p1 = mpsc::channel();
            let p3_p2 = mpsc::channel();

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

    #[derive(Debug)]
    pub struct PartyTestNetwork {
        id: PartyID,
        send_prev: Sender<Bytes>,
        send_next: Sender<Bytes>,
        recv_prev: Receiver<Bytes>,
        recv_next: Receiver<Bytes>,
        _stats: [usize; 4], // [sent_prev, sent_next, recv_prev, recv_next]
    }

    impl Rep3Network for PartyTestNetwork {
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
                let data = Vec::from(self.recv_next.recv().unwrap());
                Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
            } else if self.id.prev_id() == from {
                let data = Vec::from(self.recv_prev.recv().unwrap());
                Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
            } else {
                panic!("You want to read from yourself?")
            }
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

    #[test]
    fn e2e_proof_poseidon_bn254() {
        let zkey_file = File::open("../test_vectors/bn254/poseidon/circuit_0000.zkey").unwrap();
        let r1cs_file = File::open("../test_vectors/bn254/poseidon/poseidon.r1cs").unwrap();
        let witness_file = File::open("../test_vectors/bn254/poseidon/witness.wtns").unwrap();
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
        let inputs = circuit.public_inputs();
        let mut rng = thread_rng();
        let [witness_share1, witness_share2, witness_share3] =
            SharedWitness::share_rep3(&witness, &public_inputs1, &mut rng);
        let test_network = Rep3TestNetwork::default();
        let mut threads = vec![];
        for (((net, x), r1cs), pk) in test_network
            .get_party_networks()
            .into_iter()
            .zip([witness_share1, witness_share2, witness_share3].into_iter())
            .zip([r1cs1, r1cs2, r1cs3].into_iter())
            .zip([pk1, pk2, pk3].into_iter())
        {
            threads.push(thread::spawn(move || {
                let rep3 = Rep3Protocol::<ark_bn254::Fr, PartyTestNetwork>::new(net).unwrap();
                let mut prover = CollaborativeGroth16::<
                    Rep3Protocol<ark_bn254::Fr, PartyTestNetwork>,
                    Bn254,
                >::new(rep3);
                prover.prove(&pk, &r1cs, x).unwrap()
            }));
        }
        let result3 = threads.pop().unwrap().join().unwrap();
        let result2 = threads.pop().unwrap().join().unwrap();
        let result1 = threads.pop().unwrap().join().unwrap();
        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
        let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(result1)).unwrap();
        let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
        let verified =
            Groth16::<Bn254>::verify_proof(&pvk, &der_proof.into(), &inputs).expect("can verify");
        assert!(verified);
    }

    #[test]
    fn e2e_proof_poseidon_bn254_with_zkey_matrices() {
        let zkey_file = File::open("../test_vectors/bn254/poseidon/circuit_0000.zkey").unwrap();
        let witness_file = File::open("../test_vectors/bn254/poseidon/witness.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let (pk1, matrices) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
        let pk2 = pk1.clone();
        let pk3 = pk1.clone();
        let num_inputs = matrices.num_instance_variables;
        let pvk = prepare_verifying_key(&pk1.vk);
        let mut rng = thread_rng();
        let [witness_share1, witness_share2, witness_share3] = SharedWitness::share_rep3(
            &witness.values[num_inputs..],
            &witness.values[..num_inputs],
            &mut rng,
        );
        let test_network = Rep3TestNetwork::default();
        let mut threads = vec![];
        for (((net, x), mat), pk) in test_network
            .get_party_networks()
            .into_iter()
            .zip([witness_share1, witness_share2, witness_share3].into_iter())
            .zip([matrices.clone(), matrices.clone(), matrices].into_iter())
            .zip([pk1, pk2, pk3].into_iter())
        {
            threads.push(thread::spawn(move || {
                let rep3 = Rep3Protocol::<ark_bn254::Fr, PartyTestNetwork>::new(net).unwrap();
                let mut prover = CollaborativeGroth16::<
                    Rep3Protocol<ark_bn254::Fr, PartyTestNetwork>,
                    Bn254,
                >::new(rep3);
                prover.prove_with_matrices(&pk, &mat, x).unwrap()
            }));
        }
        let result3 = threads.pop().unwrap().join().unwrap();
        let result2 = threads.pop().unwrap().join().unwrap();
        let result1 = threads.pop().unwrap().join().unwrap();
        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
        let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(result1)).unwrap();
        let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
        let inputs = witness.values[1..num_inputs].to_vec();
        let verified =
            Groth16::<Bn254>::verify_proof(&pvk, &der_proof.into(), &inputs).expect("can verify");
        assert!(verified);
    }
}
