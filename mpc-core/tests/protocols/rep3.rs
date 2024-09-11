use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::Bytes;
use mpc_core::protocols::rep3::id::PartyID;
use mpc_core::protocols::rep3::network::Rep3Network;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
pub enum Msg {
    Data(Bytes),
    Recv(UnboundedReceiver<Msg>),
}

impl Msg {
    fn to_recv(self) -> Option<UnboundedReceiver<Msg>> {
        if let Msg::Recv(x) = self {
            Some(x)
        } else {
            None
        }
    }

    fn to_data(self) -> Option<Bytes> {
        if let Msg::Data(x) = self {
            Some(x)
        } else {
            None
        }
    }
}

pub struct Rep3TestNetwork {
    p1_p2_sender: UnboundedSender<Msg>,
    p1_p3_sender: UnboundedSender<Msg>,
    p2_p3_sender: UnboundedSender<Msg>,
    p2_p1_sender: UnboundedSender<Msg>,
    p3_p1_sender: UnboundedSender<Msg>,
    p3_p2_sender: UnboundedSender<Msg>,
    p1_p2_receiver: UnboundedReceiver<Msg>,
    p1_p3_receiver: UnboundedReceiver<Msg>,
    p2_p3_receiver: UnboundedReceiver<Msg>,
    p2_p1_receiver: UnboundedReceiver<Msg>,
    p3_p1_receiver: UnboundedReceiver<Msg>,
    p3_p2_receiver: UnboundedReceiver<Msg>,
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
    pub(crate) id: PartyID,
    pub(crate) send_prev: UnboundedSender<Msg>,
    pub(crate) send_next: UnboundedSender<Msg>,
    pub(crate) recv_prev: UnboundedReceiver<Msg>,
    pub(crate) recv_next: UnboundedReceiver<Msg>,
    pub(crate) _stats: [usize; 4], // [sent_prev, sent_next, recv_prev, recv_next]
}

impl Rep3Network for PartyTestNetwork {
    fn get_id(&self) -> PartyID {
        self.id
    }

    async fn reshare_many<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: &[F],
    ) -> std::io::Result<Vec<F>> {
        self.send_next_many(data).await?;
        self.recv_prev_many().await
    }

    async fn broadcast<F: CanonicalSerialize + CanonicalDeserialize>(
        &mut self,
        data: F,
    ) -> std::io::Result<(F, F)> {
        let data = [data];
        self.send_many(self.id.next_id(), &data).await?;
        self.send_many(self.id.prev_id(), &data).await?;
        let mut prev = self.recv_many(self.id.prev_id()).await?;
        let mut next = self.recv_many(self.id.next_id()).await?;
        if next.len() != 1 || prev.len() != 1 {
            panic!("got more than one from next or prev");
        }
        Ok((next.pop().unwrap(), prev.pop().unwrap()))
    }

    async fn send_many<F: CanonicalSerialize>(
        &mut self,
        target: PartyID,
        data: &[F],
    ) -> std::io::Result<()> {
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut to_send = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut to_send).unwrap();
        if self.id.next_id() == target {
            self.send_next
                .send(Msg::Data(Bytes::from(to_send)))
                .expect("can send to next")
        } else if self.id.prev_id() == target {
            self.send_prev
                .send(Msg::Data(Bytes::from(to_send)))
                .expect("can send to next");
        } else {
            panic!("You want to send to yourself?")
        }
        Ok(())
    }

    async fn recv_many<F: CanonicalDeserialize>(
        &mut self,
        from: PartyID,
    ) -> std::io::Result<Vec<F>> {
        if self.id.next_id() == from {
            let data = Vec::from(self.recv_next.recv().await.unwrap().to_data().unwrap());
            Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
        } else if self.id.prev_id() == from {
            let data = Vec::from(self.recv_prev.recv().await.unwrap().to_data().unwrap());
            Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
        } else {
            panic!("You want to read from yourself?")
        }
    }

    async fn fork(self) -> std::io::Result<(Self, Self)>
    where
        Self: Sized,
    {
        let ch_prev = mpsc::unbounded_channel();
        let ch_next = mpsc::unbounded_channel();

        self.send_next.send(Msg::Recv(ch_next.1)).unwrap();
        self.send_prev.send(Msg::Recv(ch_prev.1)).unwrap();

        let recv_prev = self.recv_prev.recv().await.unwrap().to_recv().unwrap();
        let recv_next = self.recv_next.recv().await.unwrap().to_recv().unwrap();

        let id = self.id;

        let other = Self {
            id,
            send_prev: ch_prev.0,
            send_next: ch_next.0,
            recv_prev,
            recv_next,
            _stats: [0; 4],
        };

        Ok((self, other))
    }

    async fn shutdown(self) -> std::io::Result<()> {
        Ok(())
    }
}

mod field_share {
    use crate::protocols::rep3::Rep3TestNetwork;
    use ark_ff::Field;
    use ark_std::{UniformRand, Zero};
    use itertools::izip;
    use mpc_core::protocols::rep3::conversion;
    use mpc_core::protocols::rep3::{self, arithmetic, network::IoContext};
    use rand::thread_rng;
    use std::thread;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn rep3_add() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = x + y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (tx, x, y) in izip!([tx1, tx2, tx3], x_shares.into_iter(), y_shares.into_iter()) {
            thread::spawn(move || tx.send(arithmetic::add(x, y)));
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_sub() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (tx, x, y) in izip!([tx1, tx2, tx3], x_shares.into_iter(), y_shares.into_iter()) {
            thread::spawn(move || tx.send(arithmetic::sub(x, y)));
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_mul() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = x * y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (net, tx, x, y) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            tokio::spawn(async move {
                let mut ctx = IoContext::init(net).await.unwrap();
                let mul = arithmetic::mul(x, y, &mut ctx).await.unwrap();
                tx.send(mul)
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_fork_mul() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x0 = ark_bn254::Fr::rand(&mut rng);
        let x1 = ark_bn254::Fr::rand(&mut rng);
        let y0 = ark_bn254::Fr::rand(&mut rng);
        let y1 = ark_bn254::Fr::rand(&mut rng);
        let x_shares0 = rep3::share_field_element(x0, &mut rng);
        let x_shares1 = rep3::share_field_element(x1, &mut rng);
        let y_shares0 = rep3::share_field_element(y0, &mut rng);
        let y_shares1 = rep3::share_field_element(y1, &mut rng);
        let should_result0 = x0 * y0;
        let should_result1 = x1 * y1;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (net, tx, (x0, y0), (x1, y1)) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares0.into_iter().zip(y_shares0),
            x_shares1.into_iter().zip(y_shares1)
        ) {
            tokio::spawn(async move {
                let ctx = IoContext::init(net).await.unwrap();
                let (ctx0, ctx1) = ctx.fork().await.unwrap();
                let (res0, res1) = tokio::join!(
                    arithmetic::mul(x0, y0, &mut ctx0),
                    arithmetic::mul(x1, y1, &mut ctx1)
                );
                tx.send((res0.unwrap(), res1.unwrap()))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result0 = rep3::combine_field_element(result1.0, result2.0, result3.0);
        let is_result1 = rep3::combine_field_element(result1.1, result2.1, result3.1);
        assert_eq!(is_result0, should_result0);
        assert_eq!(is_result1, should_result1);
    }

    #[tokio::test]
    async fn rep3_mul2_then_add() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = ((x * y) * y) + x;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (net, tx, x, y) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            tokio::spawn(async move {
                let mut rep3 = IoContext::init(net).await.unwrap();
                let mul = arithmetic::mul(x, y, &mut rep3).await.unwrap();
                let mul = arithmetic::mul(mul, y, &mut rep3).await.unwrap();
                tx.send(arithmetic::add(mul, x))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    use std::str::FromStr;
    #[tokio::test]
    async fn rep3_mul_vec_bn() {
        let test_network = Rep3TestNetwork::default();
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
        let mut x_shares1 = vec![];
        let mut x_shares2 = vec![];
        let mut x_shares3 = vec![];
        let mut y_shares1 = vec![];
        let mut y_shares2 = vec![];
        let mut y_shares3 = vec![];
        for (x, y) in x.iter().zip(y.iter()) {
            let [x1, x2, x3] = rep3::share_field_element(*x, &mut rng);
            let [y1, y2, y3] = rep3::share_field_element(*y, &mut rng);
            x_shares1.push(x1);
            x_shares2.push(x2);
            x_shares3.push(x3);
            y_shares1.push(y1);
            y_shares2.push(y2);
            y_shares3.push(y3);
        }

        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (net, tx, x, y) in izip!(
            test_network.get_party_networks(),
            [tx1, tx2, tx3],
            [x_shares1, x_shares2, x_shares3,],
            [y_shares1, y_shares2, y_shares3,],
        ) {
            tokio::spawn(async move {
                let mut rep3 = IoContext::init(net).await.unwrap();
                let mul = arithmetic::mul_vec(&x, &y, &mut rep3).await.unwrap();
                tx.send(mul)
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_elements(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_mul_vec() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..1)
            .map(|_| ark_bn254::Fr::from_str("2").unwrap())
            .collect::<Vec<_>>();
        let y = (0..1)
            .map(|_| ark_bn254::Fr::from_str("3").unwrap())
            .collect::<Vec<_>>();
        let mut x_shares1 = vec![];
        let mut x_shares2 = vec![];
        let mut x_shares3 = vec![];
        let mut y_shares1 = vec![];
        let mut y_shares2 = vec![];
        let mut y_shares3 = vec![];
        let mut should_result = vec![];
        for (x, y) in x.iter().zip(y.iter()) {
            let [x1, x2, x3] = rep3::share_field_element(*x, &mut rng);
            let [y1, y2, y3] = rep3::share_field_element(*y, &mut rng);
            x_shares1.push(x1);
            x_shares2.push(x2);
            x_shares3.push(x3);
            y_shares1.push(y1);
            y_shares2.push(y2);
            y_shares3.push(y3);
            should_result.push((x * y) * y);
        }
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();

        for (net, tx, x, y) in izip!(
            test_network.get_party_networks(),
            [tx1, tx2, tx3],
            [x_shares1, x_shares2, x_shares3,],
            [y_shares1, y_shares2, y_shares3,],
        ) {
            tokio::spawn(async move {
                let mut rep3 = IoContext::init(net).await.unwrap();
                let mul = arithmetic::mul_vec(&x, &y, &mut rep3).await.unwrap();
                let mul = arithmetic::mul_vec(&mul, &y, &mut rep3).await.unwrap();
                tx.send(mul)
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_elements(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_neg() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let should_result = -x;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (tx, x) in izip!([tx1, tx2, tx3], x_shares.into_iter()) {
            thread::spawn(move || tx.send(arithmetic::neg(x)));
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_inv() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let mut x = ark_bn254::Fr::rand(&mut rng);
        while x.is_zero() {
            x = ark_bn254::Fr::rand(&mut rng);
        }
        let x_shares = rep3::share_field_element(x, &mut rng);
        let should_result = x.inverse().unwrap();
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            tokio::spawn(async move {
                let mut rep3 = IoContext::init(net).await.unwrap();
                tx.send(arithmetic::inv(x, &mut rep3).await.unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_sqrt() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x_ = ark_bn254::Fr::rand(&mut rng);
        let x = x_.square(); // Guarantees a square root exists
        let x_shares = rep3::share_field_element(x, &mut rng);
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (net, tx, x) in izip!(test_network.get_party_networks(), [tx1, tx2, tx3], x_shares,) {
            tokio::spawn(async move {
                let mut rep3 = IoContext::init(net).await.unwrap();
                tx.send(arithmetic::sqrt(x, &mut rep3).await.unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert!(is_result == x_ || is_result == -x_);
    }

    use arithmetic::ge_public;
    use arithmetic::gt_public;
    use arithmetic::le_public;
    use arithmetic::lt_public;
    macro_rules! bool_op_test {
        ($name: ident, $op: tt) => {
            paste::item! {
                #[tokio::test]
                async fn $name() {
                    let constant_number = ark_bn254::Fr::from_str("50").unwrap();
                    for i in -1..=1 {
                        let compare = constant_number + ark_bn254::Fr::from(i);
                        let test_network = Rep3TestNetwork::default();
                        let mut rng = thread_rng();
                        let x_shares = rep3::share_field_element(constant_number, &mut rng);
                        let y_shares = rep3::share_field_element(compare, &mut rng);
                        let should_result = ark_bn254::Fr::from(constant_number $op compare);
                        let (tx1, rx1) = oneshot::channel();
                        let (tx2, rx2) = oneshot::channel();
                        let (tx3, rx3) = oneshot::channel();
                        for (net, tx, x, y, public) in izip!(
                            test_network.get_party_networks(),
                            [tx1, tx2, tx3],
                            x_shares,
                            y_shares,
                            vec![compare; 3]
                        ) {
                            tokio::spawn(async move  {
                                let mut rep3 = IoContext::init(net).await.unwrap();
                                let shared_compare = arithmetic::$name(x, y, &mut rep3).await.unwrap();
                                let rhs_const =[< $name _public >](x, public, &mut rep3).await.unwrap();
                                tx.send([shared_compare, rhs_const])
                            });
                        }
                        let results1 = rx1.await.unwrap();
                        let results2 = rx2.await.unwrap();
                        let results3 = rx3.await.unwrap();
                        for (a, b, c) in izip!(results1, results2, results3) {
                            let is_result = rep3::combine_field_element(a, b, c);
                            println!("{constant_number} {} {compare} = {is_result}", stringify!($op));
                            assert_eq!(is_result, should_result.into());
                        }
                    }
                }
            }
        };
    }
    bool_op_test!(lt, <);
    bool_op_test!(le, <=);
    bool_op_test!(gt, >);
    bool_op_test!(ge, >=);

    #[tokio::test]
    async fn rep3_a2b_zero() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::zero();
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            tokio::spawn(async move {
                let mut rep3 = IoContext::init(net).await.unwrap();
                tx.send(conversion::a2b(x, &mut rep3).await.unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);
        let should_result = x.into();
        assert_eq!(is_result, should_result);
        let is_result_f: ark_bn254::Fr = is_result.into();
        assert_eq!(is_result_f, x);
    }
    #[tokio::test]
    async fn rep3_a2b() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            tokio::spawn(async move {
                let mut rep3 = IoContext::init(net).await.unwrap();
                tx.send(conversion::a2b(x, &mut rep3).await.unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);

        let should_result = x.into();
        assert_eq!(is_result, should_result);
        let is_result_f: ark_bn254::Fr = is_result.into();
        assert_eq!(is_result_f, x);
    }

    #[tokio::test]
    async fn rep3_b2a() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            tokio::spawn(async move {
                let mut rep3 = IoContext::init(net).await.unwrap();
                tx.send(conversion::b2a(&x, &mut rep3).await.unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }
}

mod curve_share {
    use ark_std::UniformRand;
    use itertools::izip;

    use mpc_core::protocols::rep3::{self, pointshare};
    use rand::thread_rng;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn rep3_add() {
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let y = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rep3::share_curve_point(x, &mut rng);
        let y_shares = rep3::share_curve_point(y, &mut rng);
        let should_result = x + y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();

        for (tx, x, y) in izip!([tx1, tx2, tx3], x_shares.into_iter(), y_shares.into_iter()) {
            tokio::spawn(async move { tx.send(pointshare::add(&x, &y)) });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_sub() {
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let y = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rep3::share_curve_point(x, &mut rng);
        let y_shares = rep3::share_curve_point(y, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (tx, x, y) in izip!([tx1, tx2, tx3], x_shares.into_iter(), y_shares.into_iter()) {
            tokio::spawn(async move { tx.send(pointshare::sub(&x, &y)) });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_scalar_mul_public_point() {
        let mut rng = thread_rng();
        let public_point = ark_bn254::G1Projective::rand(&mut rng);
        let scalar = ark_bn254::Fr::rand(&mut rng);
        let scalar_shares = rep3::share_field_element(scalar, &mut rng);
        let should_result = public_point * scalar;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();

        for (tx, scalar) in izip!([tx1, tx2, tx3], scalar_shares,) {
            tokio::spawn(async move {
                tx.send(pointshare::scalar_mul_public_point(&public_point, scalar))
            });
        }

        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rep3_scalar_mul_public_scalar() {
        let mut rng = thread_rng();
        let point = ark_bn254::G1Projective::rand(&mut rng);
        let public_scalar = ark_bn254::Fr::rand(&mut rng);
        let point_shares = rep3::share_curve_point(point, &mut rng);
        let should_result = point * public_scalar;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();

        for (tx, point) in izip!([tx1, tx2, tx3], point_shares) {
            tokio::spawn(async move {
                tx.send(pointshare::scalar_mul_public_scalar(&point, public_scalar))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rep3::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }
}
