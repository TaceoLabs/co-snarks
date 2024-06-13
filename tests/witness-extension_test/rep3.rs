#[cfg(test)]
mod rep3_tests {

    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use bytes::Bytes;
    use circom_types::groth16::witness::Witness;
    use collaborative_groth16::groth16::SharedWitness;
    use mpc_core::protocols::rep3::{id::PartyID, network::Rep3Network, Rep3Protocol};
    use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

    #[allow(dead_code)]
    fn install_tracing() {
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::{fmt, EnvFilter};

        let fmt_layer = fmt::layer().with_target(true).with_line_number(true);
        let filter_layer = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new("info"))
            .unwrap();

        tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt_layer)
            .init();
    }
    #[derive(Debug)]
    //todo remove me and put me in common test crate
    pub struct Rep3TestNetwork {
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

    pub struct TestInputs {
        inputs: Vec<Vec<ark_bn254::Fr>>,
        witnesses: Vec<Witness<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>>,
    }

    impl Default for Rep3TestNetwork {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Rep3TestNetwork {
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
    #[derive(Debug)]
    pub struct PartyTestNetwork {
        id: PartyID,
        send_prev: UnboundedSender<Bytes>,
        send_next: UnboundedSender<Bytes>,
        recv_prev: UnboundedReceiver<Bytes>,
        recv_next: UnboundedReceiver<Bytes>,
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
                let data = Vec::from(self.recv_next.blocking_recv().unwrap());
                Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
            } else if self.id.prev_id() == from {
                let data = Vec::from(self.recv_prev.blocking_recv().unwrap());
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

    mod witness_extension {
        use super::*;
        use ark_bn254::Bn254;
        use circom_mpc_compiler::CompilerBuilder;
        use circom_types::groth16::witness::Witness;
        use itertools::izip;
        use mpc_core::protocols::rep3::{self};
        use rand::thread_rng;
        use std::fs;
        use std::str::FromStr;
        use std::{fs::File, thread};
        use tokio::sync::oneshot;
        fn combine_field_elements_for_vm(
            a: SharedWitness<Rep3Protocol<ark_bn254::Fr, PartyTestNetwork>, Bn254>,
            b: SharedWitness<Rep3Protocol<ark_bn254::Fr, PartyTestNetwork>, Bn254>,
            c: SharedWitness<Rep3Protocol<ark_bn254::Fr, PartyTestNetwork>, Bn254>,
        ) -> Vec<ark_bn254::Fr> {
            let mut res = Vec::with_capacity(a.public_inputs.len() + a.witness.len());
            for (a, b, c) in izip!(a.public_inputs, b.public_inputs, c.public_inputs) {
                assert_eq!(a, b);
                assert_eq!(b, c);
                res.push(a);
            }
            res.extend(rep3::utils::combine_field_elements(
                a.witness, b.witness, c.witness,
            ));
            res
        }
        pub fn from_test_name(fn_name: &str) -> TestInputs {
            let mut witnesses: Vec<
                Witness<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>,
            > = Vec::new();
            let mut inputs: Vec<Vec<ark_bn254::Fr>> = Vec::new();
            let mut i = 0;
            loop {
                if fs::metadata(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/{}/witness{}.wtns",
                    fn_name, i
                ))
                .is_err()
                {
                    break;
                }
                let witness = File::open(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/{}/witness{}.wtns",
                    fn_name, i
                ))
                .unwrap();
                let should_witness = Witness::<ark_bn254::Fr>::from_reader(witness).unwrap();
                witnesses.push(should_witness);
                let input_file = File::open(format!(
                    "../test_vectors/circuits/test-circuits/witness_outputs/{}/input{}.json",
                    fn_name, i
                ))
                .unwrap();
                let json_str: serde_json::Value = serde_json::from_reader(input_file).unwrap();
                let input = json_str
                    .get("in")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| ark_bn254::Fr::from_str(s.as_str().unwrap()).unwrap())
                    .collect::<Vec<_>>();
                inputs.push(input);
                i += 1
            }
            TestInputs { inputs, witnesses }
        }
        macro_rules! run_test {
            ($file: expr, $input: expr) => {{
                //install_tracing();
                let mut rng = thread_rng();
                let inputs = rep3::utils::share_field_elements_for_vm($input, &mut rng);
                let test_network = Rep3TestNetwork::default();
                let (tx1, rx1) = oneshot::channel();
                let (tx2, rx2) = oneshot::channel();
                let (tx3, rx3) = oneshot::channel();

                for (net, tx, input) in
                    izip!(test_network.get_party_networks(), [tx1, tx2, tx3], inputs)
                {
                    thread::spawn(move || {
                        let witness_extension = CompilerBuilder::<Bn254>::new($file.to_owned())
                            .link_library("../test_vectors/circuits/libs/")
                            .build()
                            .parse()
                            .unwrap()
                            .to_rep3_vm_with_network(net)
                            .unwrap();
                        tx.send(witness_extension.run_with_flat(input, 0).unwrap())
                            .unwrap()
                    });
                }
                let result1 = rx1.await.unwrap();
                let result2 = rx2.await.unwrap();
                let result3 = rx3.await.unwrap();
                combine_field_elements_for_vm(result1, result2, result3)
            }};
        }

        macro_rules! witness_extension_test_rep3 {
            ($name: ident) => {
                #[tokio::test]
                async fn $name() {
                    let inp: TestInputs = from_test_name(stringify!($name));
                    // let path = inp.circuit_path.as_str().to_owned();
                    for i in 0..inp.inputs.len() {
                        let is_witness = run_test!(
                            format!(
                                "../test_vectors/circuits/test-circuits/{}.circom",
                                stringify!($name)
                            ),
                            &inp.inputs[i]
                        );
                        assert_eq!(is_witness, inp.witnesses[i].values);
                    }
                }
            };

            ($name: ident, $file: expr, $input: expr, $should:expr) => {
                witness_extension_test!($name, $file, $input, $should, "witness");
            };

            ($name: ident, $file: expr, $input: expr) => {
                witness_extension_test!($name, $file, $input, $file);
            };
        }

        witness_extension_test_rep3!(aliascheck_test);
        witness_extension_test_rep3!(babyadd_tester);
        witness_extension_test_rep3!(babycheck_test);
        witness_extension_test_rep3!(babypbk_test);
        witness_extension_test_rep3!(binsub_test);
        witness_extension_test_rep3!(binsum_test);
        witness_extension_test_rep3!(constants_test);
        witness_extension_test_rep3!(control_flow);
        //witness_extension_test_rep3!(eddsa_test);
        witness_extension_test_rep3!(eddsa_verify);
        witness_extension_test_rep3!(eddsamimc_test);
        witness_extension_test_rep3!(eddsaposeidon_test);
        witness_extension_test_rep3!(edwards2montgomery);
        witness_extension_test_rep3!(escalarmul_test);
        witness_extension_test_rep3!(escalarmul_test_min);
        witness_extension_test_rep3!(escalarmulany_test);
        witness_extension_test_rep3!(escalarmulfix_test);
        witness_extension_test_rep3!(escalarmulw4table);
        witness_extension_test_rep3!(escalarmulw4table_test);
        witness_extension_test_rep3!(escalarmulw4table_test3);
        witness_extension_test_rep3!(functions);
        witness_extension_test_rep3!(greatereqthan);
        witness_extension_test_rep3!(greaterthan);
        witness_extension_test_rep3!(isequal);
        witness_extension_test_rep3!(iszero);
        witness_extension_test_rep3!(lesseqthan);
        witness_extension_test_rep3!(lessthan);
        witness_extension_test_rep3!(mimc_hasher);
        witness_extension_test_rep3!(mimc_sponge_hash_test);
        witness_extension_test_rep3!(mimc_sponge_test);
        witness_extension_test_rep3!(mimc_test);
        witness_extension_test_rep3!(montgomery2edwards);
        witness_extension_test_rep3!(montgomeryadd);
        witness_extension_test_rep3!(montgomerydouble);
        witness_extension_test_rep3!(multiplier16);
        witness_extension_test_rep3!(multiplier2);
        witness_extension_test_rep3!(mux1_1);
        witness_extension_test_rep3!(mux2_1);
        witness_extension_test_rep3!(mux3_1);
        witness_extension_test_rep3!(mux4_1);
        witness_extension_test_rep3!(pedersen2_test);
        witness_extension_test_rep3!(pedersen_hasher);
        witness_extension_test_rep3!(pedersen_test);
        //witness_extension_test_rep3!(pointbits_loopback);
        witness_extension_test_rep3!(poseidon3_test);
        witness_extension_test_rep3!(poseidon6_test);
        witness_extension_test_rep3!(poseidon_hasher1);
        witness_extension_test_rep3!(poseidon_hasher16);
        witness_extension_test_rep3!(poseidon_hasher2);
        witness_extension_test_rep3!(poseidonex_test);
        witness_extension_test_rep3!(sha256_2_test);
        witness_extension_test_rep3!(sha256_test448);
        witness_extension_test_rep3!(sha256_test512);
        witness_extension_test_rep3!(shared_control_flow);
        witness_extension_test_rep3!(shared_control_flow_arrays);
        witness_extension_test_rep3!(sign_test);
        witness_extension_test_rep3!(sqrt_test);
        witness_extension_test_rep3!(smtprocessor10_test);
        witness_extension_test_rep3!(smtverifier10_test);
        witness_extension_test_rep3!(sum_test);

        // witness_extension_test!(multiplier2, "multiplier2", ["3", "11"]);
        // witness_extension_test!(
        //     multiplier16,
        //     "multiplier16",
        //     [
        //         "5", "10", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
        //         "15",
        //     ]
        // );
        // witness_extension_test!(control_flow, "control_flow", ["1"]);
        // witness_extension_test!(mimc, "mimc_hasher", ["1", "2", "3", "4"], "mimc");
        // witness_extension_test!(
        //     poseidon1,
        //     "poseidon_hasher1",
        //     ["5"],
        //     "poseidon",
        //     "poseidon1"
        // );
        // witness_extension_test!(
        //     poseidon2,
        //     "poseidon_hasher2",
        //     ["0", "1"],
        //     "poseidon",
        //     "poseidon2"
        // );
        // witness_extension_test!(
        //     poseidon16,
        //     "poseidon_hasher16",
        //     (0..16).map(|i| i.to_string()).collect::<Vec<_>>(),
        //     "poseidon",
        //     "poseidon16"
        // );
        //TODO The following tests do not work atm because we need some logic
        //in the MPC driver
        /*
        witness_extension_test!(functions, "functions", ["5"]);
        witness_extension_test!(
            bin_sum,
            "binsum_caller",
            ["1", "0", "1", "1", "0", "0", "1", "1", "0", "1", "0", "1",]
        );
        witness_extension_test!(pedersen, "pedersen_hasher", ["5"], "pedersen");
        witness_extension_test!(
            eddsa_verify,
            "eddsa_verify",
            [
                "1",
                "13277427435165878497778222415993513565335242147425444199013288855685581939618",
                "13622229784656158136036771217484571176836296686641868549125388198837476602820",
                "2010143491207902444122668013146870263468969134090678646686512037244361350365",
                "11220723668893468001994760120794694848178115379170651044669708829805665054484",
                "2367470421002446880004241260470975644531657398480773647535134774673409612366",
                "1234",
            ],
            "eddsa"
        );*/
    }
}
