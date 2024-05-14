#[cfg(test)]
mod gsz_tests {
    use ark_bn254::Bn254;
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use bytes::Bytes;
    use circom_types::{
        groth16::{proof::JsonProof, witness::Witness, zkey::ZKey},
        r1cs::R1CS,
    };
    use collaborative_groth16::{
        circuit::Circuit,
        groth16::{CollaborativeGroth16, SharedWitness},
    };
    use itertools::izip;
    use mpc_core::protocols::gsz::{network::GSZNetwork, GSZProtocol};
    use rand::thread_rng;
    use std::{collections::HashMap, fs::File, thread};
    use tokio::sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        oneshot,
    };

    //todo remove me and put me in common test crate
    pub struct GSZTestNetwork {
        num_parties: usize,
        sender: HashMap<(usize, usize), UnboundedSender<Bytes>>,
        receiver: HashMap<(usize, usize), UnboundedReceiver<Bytes>>,
    }

    impl GSZTestNetwork {
        pub fn new(num_parties: usize) -> Self {
            // AT Most 1 message is buffered before they are read so this should be fine
            let mut sender = HashMap::with_capacity(num_parties * (num_parties - 1));
            let mut receiver = HashMap::with_capacity(num_parties * (num_parties - 1));

            for sender_id in 0..num_parties {
                for mut receiver_id in 0..num_parties - 1 {
                    if receiver_id >= sender_id {
                        receiver_id += 1;
                    }
                    let (s, r) = mpsc::unbounded_channel();
                    sender.insert((sender_id, receiver_id), s);
                    receiver.insert((sender_id, receiver_id), r);
                }
            }

            Self {
                num_parties,
                sender,
                receiver,
            }
        }

        pub fn get_party_networks(mut self) -> Vec<PartyTestNetwork> {
            let mut res = Vec::with_capacity(self.num_parties);

            for partyid in 0..self.num_parties {
                let mut send = Vec::with_capacity(self.num_parties - 1);
                let mut recv = Vec::with_capacity(self.num_parties - 1);

                for mut other_party in 0..self.num_parties - 1 {
                    if other_party >= partyid {
                        other_party += 1;
                    }

                    let s = self.sender.remove(&(partyid, other_party)).unwrap();
                    let r = self.receiver.remove(&(other_party, partyid)).unwrap();

                    send.push(s);
                    recv.push(r);
                }
                let network = PartyTestNetwork {
                    id: partyid,
                    num_parties: self.num_parties,
                    send,
                    recv,
                };
                res.push(network);
            }

            assert!(self.sender.is_empty());
            assert!(self.receiver.is_empty());

            res
        }
    }

    pub struct PartyTestNetwork {
        id: usize,
        num_parties: usize,
        send: Vec<UnboundedSender<Bytes>>,
        recv: Vec<UnboundedReceiver<Bytes>>,
    }

    impl GSZNetwork for PartyTestNetwork {
        fn get_id(&self) -> usize {
            self.id
        }

        fn get_num_parties(&self) -> usize {
            self.num_parties
        }

        fn send_many<F: CanonicalSerialize>(
            &mut self,
            mut target: usize,
            data: &[F],
        ) -> std::io::Result<()> {
            if target >= self.num_parties || target == self.id {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("No channel found for party id={}", target),
                ));
            }
            if target > self.id {
                // to get index for the Vec
                target -= 1;
            }

            let mut to_send = Vec::with_capacity(data.len() * 32);
            data.serialize_uncompressed(&mut to_send).unwrap();

            self.send[target]
                .send(Bytes::from(to_send))
                .expect("can send");

            Ok(())
        }

        fn recv_many<F: CanonicalDeserialize>(
            &mut self,
            mut from: usize,
        ) -> std::io::Result<Vec<F>> {
            if from >= self.num_parties || from == self.id {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("No channel found for party id={}", from),
                ));
            }
            if from > self.id {
                // to get index for the Vec
                from -= 1;
            }
            let data = Vec::from(self.recv[from].blocking_recv().unwrap());
            Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
        }

        fn broadcast<F: CanonicalSerialize + CanonicalDeserialize + Clone>(
            &mut self,
            data: F,
        ) -> std::io::Result<Vec<F>> {
            // Serialize
            let size = data.serialized_size(ark_serialize::Compress::No);
            let mut ser_data = Vec::with_capacity(size);
            data.to_owned()
                .serialize_uncompressed(&mut ser_data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let send_data = Bytes::from(ser_data);

            // Send
            for send in self.send.iter_mut() {
                send.send(send_data.to_owned()).expect("can send");
            }

            // Receive
            let mut res = Vec::with_capacity(self.num_parties);
            for (other_id, recv) in self.recv.iter_mut().enumerate() {
                if other_id == self.id {
                    // Put that in the middle
                    res.push(data.to_owned());
                }

                let data = Vec::from(recv.blocking_recv().unwrap());
                res.push(F::deserialize_uncompressed(data.as_slice()).unwrap());
            }

            Ok(res)
        }
    }

    async fn e2e_poseidon_bn254_inner(num_parties: usize, threshold: usize) {
        let zkey_file = File::open("../test_vectors/bn254/poseidon/circuit_0000.zkey").unwrap();
        let r1cs_file = File::open("../test_vectors/bn254/poseidon/poseidon.r1cs").unwrap();
        let witness_file = File::open("../test_vectors/bn254/poseidon/witness.wtns").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let (pk1, _) = ZKey::<Bn254>::from_reader(zkey_file).unwrap().split();
        let pk = vec![pk1.clone(); num_parties];
        let pvk = prepare_verifying_key(&pk1.vk);
        let r1cs1 = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
        let r1cs = vec![r1cs1.clone(); num_parties];
        let circuit = Circuit::new(r1cs1.clone(), witness);
        let (public_inputs1, witness) = circuit.get_wire_mapping();
        let public_inputs = vec![public_inputs1.clone(); num_parties];
        let inputs = circuit.public_inputs();
        let mut rng = thread_rng();
        let witness_share = SharedWitness::share_gsz(witness, threshold, num_parties, &mut rng);

        let test_network = GSZTestNetwork::new(num_parties);
        let mut tx = Vec::with_capacity(num_parties);
        let mut rx = Vec::with_capacity(num_parties);
        for _ in 0..num_parties {
            let (t, r) = oneshot::channel();
            tx.push(t);
            rx.push(r);
        }

        for (net, tx, x, r1cs, pk, ins) in izip!(
            test_network.get_party_networks(),
            tx,
            witness_share,
            r1cs,
            pk,
            public_inputs
        ) {
            thread::spawn(move || {
                let gsz =
                    GSZProtocol::<ark_bn254::Fr, PartyTestNetwork>::new(threshold, net).unwrap();
                let mut prover = CollaborativeGroth16::<
                    GSZProtocol<ark_bn254::Fr, PartyTestNetwork>,
                    Bn254,
                >::new(gsz);
                tx.send(prover.prove(&pk, &r1cs, &ins, x).unwrap())
            });
        }
        let mut results = Vec::with_capacity(num_parties);
        for r in rx {
            results.push(r.await.unwrap());
        }
        let result1 = results.pop().unwrap();
        for r in results {
            assert_eq!(result1, r);
        }
        let ser_proof = serde_json::to_string(&JsonProof::<Bn254>::from(result1)).unwrap();
        let der_proof = serde_json::from_str::<JsonProof<Bn254>>(&ser_proof).unwrap();
        let verified =
            Groth16::<Bn254>::verify_proof(&pvk, &der_proof.into(), &inputs).expect("can verify");
        assert!(verified);
    }

    #[tokio::test]
    async fn e2e_poseidon_bn254() {
        e2e_poseidon_bn254_inner(3, 1).await;
        e2e_poseidon_bn254_inner(10, 4).await;
    }
}
