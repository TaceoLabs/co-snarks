use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::Bytes;
use mpc_core::protocols::gsz::network::GSZNetwork;
use std::collections::HashMap;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

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

    fn recv_many<F: CanonicalDeserialize>(&mut self, mut from: usize) -> std::io::Result<Vec<F>> {
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
        let mut ser_data = vec![0u8; size];
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

mod field_share {
    use crate::protocols::gsz::GSZTestNetwork;
    use ark_std::UniformRand;
    use itertools::{izip, Itertools};
    use mpc_core::{
        protocols::gsz::{self, GSZProtocol},
        traits::PrimeFieldMpcProtocol,
    };
    use rand::thread_rng;
    use std::{str::FromStr, thread};
    use tokio::sync::oneshot;

    async fn gsz_add_inner(num_parties: usize, threshold: usize) {
        let test_network = GSZTestNetwork::new(num_parties);
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = gsz::utils::share_field_element(x, threshold, num_parties, &mut rng);
        let y_shares = gsz::utils::share_field_element(y, threshold, num_parties, &mut rng);
        let should_result = x + y;

        let mut tx = Vec::with_capacity(num_parties);
        let mut rx = Vec::with_capacity(num_parties);
        for _ in 0..num_parties {
            let (t, r) = oneshot::channel();
            tx.push(t);
            rx.push(r);
        }

        for (net, tx, x, y) in izip!(test_network.get_party_networks(), tx, x_shares, y_shares) {
            thread::spawn(move || {
                let mut gsz = GSZProtocol::new(threshold, net).unwrap();
                tx.send(gsz.add(&x, &y))
            });
        }

        let mut results = Vec::with_capacity(num_parties);
        for r in rx {
            results.push(r.await.unwrap());
        }

        let is_result = gsz::utils::combine_field_element(
            &results,
            &(1..=num_parties).collect_vec(),
            threshold,
        )
        .unwrap();

        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn gsz_add() {
        gsz_add_inner(3, 1).await;
        gsz_add_inner(10, 4).await;
    }

    async fn gsz_sub_inner(num_parties: usize, threshold: usize) {
        let test_network = GSZTestNetwork::new(num_parties);
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = gsz::utils::share_field_element(x, threshold, num_parties, &mut rng);
        let y_shares = gsz::utils::share_field_element(y, threshold, num_parties, &mut rng);
        let should_result = x - y;

        let mut tx = Vec::with_capacity(num_parties);
        let mut rx = Vec::with_capacity(num_parties);
        for _ in 0..num_parties {
            let (t, r) = oneshot::channel();
            tx.push(t);
            rx.push(r);
        }

        for (net, tx, x, y) in izip!(test_network.get_party_networks(), tx, x_shares, y_shares) {
            thread::spawn(move || {
                let mut gsz = GSZProtocol::new(threshold, net).unwrap();
                tx.send(gsz.sub(&x, &y))
            });
        }

        let mut results = Vec::with_capacity(num_parties);
        for r in rx {
            results.push(r.await.unwrap());
        }

        let is_result = gsz::utils::combine_field_element(
            &results,
            &(1..=num_parties).collect_vec(),
            threshold,
        )
        .unwrap();

        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn gsz_sub() {
        gsz_sub_inner(3, 1).await;
        gsz_sub_inner(10, 4).await;
    }

    async fn gsz_mul2_then_add_inner(num_parties: usize, threshold: usize) {
        let test_network = GSZTestNetwork::new(num_parties);
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = gsz::utils::share_field_element(x, threshold, num_parties, &mut rng);
        let y_shares = gsz::utils::share_field_element(y, threshold, num_parties, &mut rng);
        let should_result = ((x * y) * y) + x;

        let mut tx = Vec::with_capacity(num_parties);
        let mut rx = Vec::with_capacity(num_parties);
        for _ in 0..num_parties {
            let (t, r) = oneshot::channel();
            tx.push(t);
            rx.push(r);
        }

        for (net, tx, x, y) in izip!(test_network.get_party_networks(), tx, x_shares, y_shares) {
            thread::spawn(move || {
                let mut gsz = GSZProtocol::new(threshold, net).unwrap();
                let mul = gsz.mul(&x, &y).unwrap();
                let mul = gsz.mul(&mul, &y).unwrap();
                tx.send(gsz.add(&mul, &x))
            });
        }

        let mut results = Vec::with_capacity(num_parties);
        for r in rx {
            results.push(r.await.unwrap());
        }

        let is_result = gsz::utils::combine_field_element(
            &results,
            &(1..=num_parties).collect_vec(),
            threshold,
        )
        .unwrap();

        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn gsz_mul2_then_add() {
        gsz_mul2_then_add_inner(3, 1).await;
        gsz_mul2_then_add_inner(10, 4).await;
    }

    async fn gsz_mul_vec_bn_inner(num_parties: usize, threshold: usize) {
        let test_network = GSZTestNetwork::new(num_parties);
        let mut rng = thread_rng();
        let x = [
            ark_bn254::Fr::from_str(
                "13839525561076761625780930844889299788193703994911163378019280196128582690055",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "19302971480864839163158232064620707211435225928426123775531639309944891593977",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "8048717310762513532550620831072439583505607813129662608591015555880153427210",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "2585271390974436123003027749932103593962191064365118925254473311197989280023",
            )
            .unwrap(),
        ];
        let y = [
            ark_bn254::Fr::from_str(
                "2688648969035332064113669477511029957484512453056743431884706385750388613065",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "13632770404954969699480437686769008635735921498648460325387842712839596176806",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "19199593902803943133889170931116903997086625101975591190159463567024116566625",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "8255472466884305547009533395117607586789669747151273739964395707537515634749",
            )
            .unwrap(),
        ];
        let should_result = vec![
            ark_bn254::Fr::from_str(
                "14012338922664984944451142760937475581748095944353358534203030914664561190462",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "4297594441150501195973997511775989720904927516253689527653694984160382713321",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "7875903949174289914141782934879682497141865775307179984684659764891697566272",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "6646526994769136778802685410292764833027657364709823469005920616147071273574",
            )
            .unwrap(),
        ];

        let x_shares =
            gsz::utils::share_field_elements(x.to_vec(), threshold, num_parties, &mut rng);
        let y_shares =
            gsz::utils::share_field_elements(y.to_vec(), threshold, num_parties, &mut rng);

        let mut tx = Vec::with_capacity(num_parties);
        let mut rx = Vec::with_capacity(num_parties);
        for _ in 0..num_parties {
            let (t, r) = oneshot::channel();
            tx.push(t);
            rx.push(r);
        }

        for (net, tx, x, y) in izip!(test_network.get_party_networks(), tx, x_shares, y_shares) {
            thread::spawn(move || {
                let mut gsz = GSZProtocol::new(threshold, net).unwrap();
                let mul = gsz.mul_vec(&x.to_ref(), &y.to_ref()).unwrap();
                tx.send(mul)
            });
        }

        let mut results = Vec::with_capacity(num_parties);
        for r in rx {
            results.push(r.await.unwrap());
        }

        let is_result = gsz::utils::combine_field_elements(
            &results,
            &(1..=num_parties).collect_vec(),
            threshold,
        )
        .unwrap();

        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn gsz_mul_vec_bn() {
        gsz_mul_vec_bn_inner(3, 1).await;
        gsz_mul_vec_bn_inner(10, 4).await;
    }

    async fn gsz_mul_vec_inner(num_parties: usize, threshold: usize) {
        let test_network = GSZTestNetwork::new(num_parties);
        let mut rng = thread_rng();
        let x = (0..1)
            .map(|_| ark_bn254::Fr::from_str("2").unwrap())
            .collect::<Vec<_>>();
        let y = (0..x.len())
            .map(|_| ark_bn254::Fr::from_str("3").unwrap())
            .collect::<Vec<_>>();

        let mut should_result = Vec::with_capacity(x.len());
        for (x, y) in x.iter().zip(y.iter()) {
            should_result.push((x * y) * y);
        }

        let x_shares =
            gsz::utils::share_field_elements(x.to_vec(), threshold, num_parties, &mut rng);
        let y_shares =
            gsz::utils::share_field_elements(y.to_vec(), threshold, num_parties, &mut rng);

        let mut tx = Vec::with_capacity(num_parties);
        let mut rx = Vec::with_capacity(num_parties);
        for _ in 0..num_parties {
            let (t, r) = oneshot::channel();
            tx.push(t);
            rx.push(r);
        }

        for (net, tx, x, y) in izip!(test_network.get_party_networks(), tx, x_shares, y_shares) {
            thread::spawn(move || {
                let mut gsz = GSZProtocol::new(threshold, net).unwrap();
                let mul = gsz.mul_vec(&x.to_ref(), &y.to_ref()).unwrap();
                let mul = gsz.mul_vec(&mul.to_ref(), &y.to_ref()).unwrap();
                tx.send(mul)
            });
        }

        let mut results = Vec::with_capacity(num_parties);
        for r in rx {
            results.push(r.await.unwrap());
        }

        let is_result = gsz::utils::combine_field_elements(
            &results,
            &(1..=num_parties).collect_vec(),
            threshold,
        )
        .unwrap();

        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn gsz_mul_vec() {
        gsz_mul_vec_inner(3, 1).await;
        gsz_mul_vec_inner(10, 4).await;
    }

    async fn gsz_neg_inner(num_parties: usize, threshold: usize) {
        let test_network = GSZTestNetwork::new(num_parties);
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = gsz::utils::share_field_element(x, threshold, num_parties, &mut rng);
        let should_result = -x;

        let mut tx = Vec::with_capacity(num_parties);
        let mut rx = Vec::with_capacity(num_parties);
        for _ in 0..num_parties {
            let (t, r) = oneshot::channel();
            tx.push(t);
            rx.push(r);
        }

        for (net, tx, x) in izip!(test_network.get_party_networks(), tx, x_shares) {
            thread::spawn(move || {
                let mut gsz = GSZProtocol::new(threshold, net).unwrap();
                tx.send(gsz.neg(&x))
            });
        }

        let mut results = Vec::with_capacity(num_parties);
        for r in rx {
            results.push(r.await.unwrap());
        }

        let is_result = gsz::utils::combine_field_element(
            &results,
            &(1..=num_parties).collect_vec(),
            threshold,
        )
        .unwrap();

        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn gsz_neg() {
        gsz_neg_inner(3, 1).await;
        gsz_neg_inner(10, 4).await;
    }
}
