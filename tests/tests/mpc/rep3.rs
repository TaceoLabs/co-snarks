mod field_share {
    use ark_ff::BigInteger;
    use ark_ff::Field;
    use ark_ff::One;
    use ark_ff::PrimeField;
    use ark_std::{UniformRand, Zero};
    use blake2::{Blake2s256, Digest};
    use co_builder::prelude::AES128_SBOX;
    use co_noir_common::utils::Utils;
    use itertools::izip;
    use itertools::Itertools;
    use libaes::Cipher;
    use mpc_core::gadgets::poseidon2::Poseidon2;
    use mpc_core::protocols::rep3::conversion;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3::gadgets;
    use mpc_core::protocols::rep3::id::PartyID;
    use mpc_core::protocols::rep3::network::Rep3NetworkExt;
    use mpc_core::protocols::rep3::yao;
    use mpc_core::protocols::rep3::yao::circuits::GarbledCircuits;
    use mpc_core::protocols::rep3::yao::circuits::SHA256Table;
    use mpc_core::protocols::rep3::yao::evaluator::Rep3Evaluator;
    use mpc_core::protocols::rep3::yao::garbler::Rep3Garbler;
    use mpc_core::protocols::rep3::yao::streaming_evaluator::StreamingRep3Evaluator;
    use mpc_core::protocols::rep3::yao::streaming_garbler::StreamingRep3Garbler;
    use mpc_core::protocols::rep3::yao::GCUtils;
    use mpc_core::protocols::rep3::Rep3State;
    use mpc_core::protocols::rep3::{self, arithmetic};
    use mpc_core::protocols::rep3_ring;
    use mpc_core::MpcState as _;
    use mpc_net::local::LocalNetwork;
    use mpc_net::Network;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use rand::Rng;
    use std::array;
    use std::ops::BitXor;
    use std::str::FromStr;
    use std::sync::mpsc;

    // This is helpful for debugging
    #[expect(dead_code)]
    fn open_many<F: PrimeField, N: Network>(
        net: &N,
        a: Vec<crate::rep3::field_share::rep3::Rep3PrimeFieldShare<F>>,
    ) -> eyre::Result<Vec<F>> {
        let bs = a.iter().map(|x| x.b).collect_vec();
        net.send_next(bs)?;
        let mut cs = net.recv_prev::<Vec<F>>()?;

        izip!(a, cs.iter_mut()).for_each(|(x, c)| *c += x.a + x.b);

        Ok(cs)
    }

    // TODO we dont need channels, we can just join

    #[test]
    fn rep3_add() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = x + y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (tx, x, y) in izip!([tx1, tx2, tx3], x_shares.into_iter(), y_shares.into_iter()) {
            std::thread::spawn(move || tx.send(arithmetic::add(x, y)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (tx, x, y) in izip!([tx1, tx2, tx3], x_shares.into_iter(), y_shares.into_iter()) {
            std::thread::spawn(move || tx.send(arithmetic::sub(x, y)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub_shared_by_public() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (tx, x, id) in izip!(
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            [PartyID::ID0, PartyID::ID1, PartyID::ID2]
        ) {
            std::thread::spawn(move || tx.send(arithmetic::sub_shared_by_public(x, y, id)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub_public_by_shared() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (tx, y, id) in izip!(
            [tx1, tx2, tx3],
            y_shares.into_iter(),
            [PartyID::ID0, PartyID::ID1, PartyID::ID2]
        ) {
            std::thread::spawn(move || tx.send(arithmetic::sub_public_by_shared(x, y, id)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = x * y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mul = arithmetic::mul(x, y, &net, &mut state).unwrap();
                tx.send(mul)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_div() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = x / y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mul = arithmetic::div(x, y, &net, &mut state).unwrap();
                tx.send(mul)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_fork_mul() {
        let nets0 = LocalNetwork::new_3_parties();
        let nets1 = LocalNetwork::new_3_parties();
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
        let mut threads = vec![];
        for (net0, net1, (x0, y0), (x1, y1)) in izip!(
            nets0.into_iter(),
            nets1.into_iter(),
            x_shares0.into_iter().zip(y_shares0),
            x_shares1.into_iter().zip(y_shares1)
        ) {
            threads.push(std::thread::spawn(move || {
                let mut state0 = Rep3State::new(&net0, A2BType::default()).unwrap();
                let mut state1 = state0.fork(0).unwrap();
                let (mul0, mul1) = mpc_net::join(
                    || arithmetic::mul(x0, y0, &net0, &mut state0),
                    || arithmetic::mul(x1, y1, &net1, &mut state1),
                );
                (mul0.unwrap(), mul1.unwrap())
            }));
        }
        let result3 = threads.pop().unwrap().join().unwrap();
        let result2 = threads.pop().unwrap().join().unwrap();
        let result1 = threads.pop().unwrap().join().unwrap();
        let is_result0 = rep3::combine_field_element(result1.0, result2.0, result3.0);
        let is_result1 = rep3::combine_field_element(result1.1, result2.1, result3.1);
        assert_eq!(is_result0, should_result0);
        assert_eq!(is_result1, should_result1);
    }

    #[test]
    fn rep3_mul2_then_add() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let should_result = ((x * y) * y) + x;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mul = arithmetic::mul(x, y, &net, &mut state).unwrap();
                let mul = arithmetic::mul(mul, y, &net, &mut state).unwrap();
                tx.send(arithmetic::add(mul, x))
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul_vec_bn() {
        let nets = LocalNetwork::new_3_parties();
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

        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let y_shares = rep3::share_field_elements(&y, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mul = arithmetic::mul_vec(&x, &y, &net, &mut state).unwrap();
                tx.send(mul)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul_vec() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..1)
            .map(|_| ark_bn254::Fr::from_str("2").unwrap())
            .collect::<Vec<_>>();
        let y = (0..1)
            .map(|_| ark_bn254::Fr::from_str("3").unwrap())
            .collect::<Vec<_>>();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let y_shares = rep3::share_field_elements(&y, &mut rng);

        let mut should_result = vec![];
        for (x, y) in x.iter().zip(y.iter()) {
            should_result.push((x * y) * y);
        }
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mul = arithmetic::mul_vec(&x, &y, &net, &mut state).unwrap();
                let mul = arithmetic::mul_vec(&mul, &y, &net, &mut state).unwrap();
                tx.send(mul)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_neg() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let should_result = -x;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (tx, x) in izip!([tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || tx.send(arithmetic::neg(x)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_inv() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mut x = ark_bn254::Fr::rand(&mut rng);
        while x.is_zero() {
            x = ark_bn254::Fr::rand(&mut rng);
        }
        let x_shares = rep3::share_field_element(x, &mut rng);
        let should_result = x.inverse().unwrap();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(arithmetic::inv(x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sqrt() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x_ = ark_bn254::Fr::rand(&mut rng);
        let x = x_.square(); // Guarantees a square root exists
        let x_shares = rep3::share_field_element(x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares,) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(arithmetic::sqrt(x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert!(is_result == x_ || is_result == -x_);
    }

    #[test]
    fn rep3_bit_inject() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::from(rng.gen::<bool>() as u64);
        let mut x_shares = rep3::share_biguint(x, &mut rng);
        // Simulate sharing of just one bit
        for x in x_shares.iter_mut() {
            x.a &= BigUint::one();
            x.b &= BigUint::one();
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::bit_inject(&x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_bit_inject_many() {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mut should_result = Vec::with_capacity(VEC_SIZE);
        let mut x0_shares = Vec::with_capacity(VEC_SIZE);
        let mut x1_shares = Vec::with_capacity(VEC_SIZE);
        let mut x2_shares = Vec::with_capacity(VEC_SIZE);
        for _ in 0..VEC_SIZE {
            let x = ark_bn254::Fr::from(rng.gen::<bool>() as u64);
            should_result.push(x);
            let mut x_shares = rep3::share_biguint(x, &mut rng);
            // Simulate sharing of just one bit
            for x in x_shares.iter_mut() {
                x.a &= BigUint::one();
                x.b &= BigUint::one();
            }
            x0_shares.push(x_shares[0].to_owned());
            x1_shares.push(x_shares[1].to_owned());
            x2_shares.push(x_shares[2].to_owned());
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip([x0_shares, x1_shares, x2_shares].into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::bit_inject_many(&x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    use arithmetic::ge_public;
    use arithmetic::gt_public;
    use arithmetic::le_public;
    use arithmetic::lt_public;
    macro_rules! bool_op_test {
        ($name: ident, $op: tt) => {
            paste::item! {
                #[test]
                 fn $name() {
                    let constant_number = ark_bn254::Fr::from_str("50").unwrap();
                    for i in -1..=1 {
                        let compare = constant_number + ark_bn254::Fr::from(i);
                        let nets =LocalNetwork::new_3_parties();
                        let mut rng = thread_rng();
                        let x_shares = rep3::share_field_element(constant_number, &mut rng);
                        let y_shares = rep3::share_field_element(compare, &mut rng);
                        let should_result = ark_bn254::Fr::from(constant_number $op compare);
                        let (tx1, rx1) = mpsc::channel();
                        let (tx2, rx2) = mpsc::channel();
                        let (tx3, rx3) = mpsc::channel();
                        for (net, tx, x, y, public) in izip!(
                            nets,
                            [tx1, tx2, tx3],
                            x_shares,
                            y_shares,
                            vec![compare; 3]
                        ) {
            std::thread::spawn(move || {
                                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                                let shared_compare = arithmetic::$name(x, y, &net, &mut state).unwrap();
                                let rhs_const =[< $name _public >](x, public, &net, &mut state).unwrap();
                                tx.send([shared_compare, rhs_const])
                            });
                        }
                        let results1 = rx1.recv().unwrap();
                        let results2 = rx2.recv().unwrap();
                        let results3 = rx3.recv().unwrap();
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

    #[test]
    fn rep3_pow_public_field() {
        use mpc_core::protocols::rep3::arithmetic;
        let exponents: [u64; 6] = [0, 1, 2, 3, 5, 10];
        let mut rng = thread_rng();

        for &exp in &exponents {
            let nets = LocalNetwork::new_3_parties();
            let base = ark_bn254::Fr::rand(&mut rng);
            let base_shares = rep3::share_field_element(base, &mut rng);
            let public_exp = ark_bn254::Fr::from(exp);

            let (tx1, rx1) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();
            let (tx3, rx3) = mpsc::channel();
            for (net, tx, share) in izip!(nets, [tx1, tx2, tx3], base_shares) {
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let res = arithmetic::pow_public(share, public_exp, &net, &mut state).unwrap();
                    tx.send(res).unwrap();
                });
            }
            let res1 = rx1.recv().unwrap();
            let res2 = rx2.recv().unwrap();
            let res3 = rx3.recv().unwrap();
            let got = rep3::combine_field_element(res1, res2, res3);

            let mut expected = ark_bn254::Fr::one();
            for _ in 0..exp {
                expected *= base;
            }
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn rep3_a2b_zero() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::zero();
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2b(x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);
        let should_result = x.into();
        assert_eq!(is_result, should_result);
        let is_result_f: ark_bn254::Fr = is_result.into();
        assert_eq!(is_result_f, x);
    }

    #[test]
    fn rep3_a2y2b_zero() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::zero();
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2y2b(x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);
        let should_result = x.into();
        assert_eq!(is_result, should_result);
        let is_result_f: ark_bn254::Fr = is_result.into();
        assert_eq!(is_result_f, x);
    }

    #[test]
    fn rep3_a2y2b_streaming_zero() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::zero();
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2y2b_streaming(x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);
        let should_result = x.into();
        assert_eq!(is_result, should_result);
        let is_result_f: ark_bn254::Fr = is_result.into();
        assert_eq!(is_result_f, x);
    }

    #[test]
    fn rep3_a2b() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2b(x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);

        let should_result = x.into();
        assert_eq!(is_result, should_result);
        let is_result_f: ark_bn254::Fr = is_result.into();
        assert_eq!(is_result_f, x);
    }

    #[test]
    fn rep3_a2y2b() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2y2b(x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);

        let should_result = x.into();
        assert_eq!(is_result, should_result);
        let is_result_f: ark_bn254::Fr = is_result.into();
        assert_eq!(is_result_f, x);
    }

    #[test]
    fn rep3_a2y2b_streaming() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2y2b_streaming(x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);

        let should_result = x.into();
        assert_eq!(is_result, should_result);
        let is_result_f: ark_bn254::Fr = is_result.into();
        assert_eq!(is_result_f, x);
    }

    #[test]
    fn rep3_b2a() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::b2a(&x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_b2y2a() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::b2y2a(&x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_b2y2a_streaming() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::b2y2a_streaming(&x, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_gc() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let should_result = x + y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        let [net1, net2, net3] = nets;

        // Both Garblers
        for (net, tx) in izip!([net2, net3], [tx2, tx3]) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mut garbler = Rep3Garbler::new(&net, &mut state);
                let x_ = garbler.encode_field(x);
                let y_ = garbler.encode_field(y);

                // This is without OT, just a simulation
                garbler.add_bundle_to_circuit(&x_.evaluator_wires);
                garbler.add_bundle_to_circuit(&y_.evaluator_wires);

                let circuit_output = GarbledCircuits::adder_mod_p::<_, ark_bn254::Fr>(
                    &mut garbler,
                    &x_.garbler_wires,
                    &y_.garbler_wires,
                )
                .unwrap();

                let output = garbler.output_all_parties(circuit_output.wires()).unwrap();
                let add = GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap();
                tx.send(add).unwrap();
            });
        }

        // The evaluator (ID0)
        std::thread::spawn(move || {
            let _state = Rep3State::new(&net1, A2BType::default()).unwrap(); // DONT REMOVE
            let mut evaluator = Rep3Evaluator::new(&net1);
            let n_bits = ark_bn254::Fr::MODULUS_BIT_SIZE as usize;

            // This is without OT, just a simulation
            evaluator.receive_circuit().unwrap();
            let x_ = evaluator.receive_bundle_from_circuit(n_bits).unwrap();
            let y_ = evaluator.receive_bundle_from_circuit(n_bits).unwrap();

            let circuit_output =
                GarbledCircuits::adder_mod_p::<_, ark_bn254::Fr>(&mut evaluator, &x_, &y_).unwrap();

            let output = evaluator
                .output_all_parties(circuit_output.wires())
                .unwrap();
            let add = GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap();
            tx1.send(add).unwrap();
        });

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        assert_eq!(result1, should_result);
        assert_eq!(result2, should_result);
        assert_eq!(result3, should_result);
    }

    #[test]
    fn rep3_gc_streaming() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let should_result = x + y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        let [net1, net2, net3] = nets;

        // Both Garblers
        for (net, tx) in izip!([net2, net3], [tx2, tx3]) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mut garbler = StreamingRep3Garbler::new(&net, &mut state);
                let x_ = garbler.encode_field(x);
                let y_ = garbler.encode_field(y);

                // This is without OT, just a simulation
                garbler.send_bundle(&x_.evaluator_wires).unwrap();
                garbler.send_bundle(&y_.evaluator_wires).unwrap();

                let circuit_output = GarbledCircuits::adder_mod_p::<_, ark_bn254::Fr>(
                    &mut garbler,
                    &x_.garbler_wires,
                    &y_.garbler_wires,
                )
                .unwrap();

                let output = garbler.output_all_parties(circuit_output.wires()).unwrap();
                let add = GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap();
                tx.send(add)
            });
        }

        // The evaluator (ID0)
        std::thread::spawn(move || {
            let _state = Rep3State::new(&net1, A2BType::default()).unwrap(); // DONT REMOVE
            let mut evaluator = StreamingRep3Evaluator::new(&net1);
            let n_bits = ark_bn254::Fr::MODULUS_BIT_SIZE as usize;

            // This is without OT, just a simulation
            let x_ = evaluator.receive_bundle(n_bits).unwrap();
            let y_ = evaluator.receive_bundle(n_bits).unwrap();

            let circuit_output =
                GarbledCircuits::adder_mod_p::<_, ark_bn254::Fr>(&mut evaluator, &x_, &y_).unwrap();

            let output = evaluator
                .output_all_parties(circuit_output.wires())
                .unwrap();
            let add = GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap();
            tx1.send(add)
        });

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        assert_eq!(result1, should_result);
        assert_eq!(result2, should_result);
        assert_eq!(result3, should_result);
    }

    #[test]
    fn rep3_a2y() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let id = state.id;
                let delta = state.rngs.generate_random_garbler_delta(id);

                let converted = conversion::a2y(x, delta, &net, &mut state).unwrap();

                let output = match id {
                    PartyID::ID0 => {
                        let mut evaluator = Rep3Evaluator::new(&net);
                        evaluator.receive_circuit().unwrap();
                        evaluator.output_all_parties(converted.wires()).unwrap()
                    }
                    PartyID::ID1 | PartyID::ID2 => {
                        let mut garbler =
                            Rep3Garbler::new_with_delta(&net, &mut state, delta.unwrap());
                        garbler.output_all_parties(converted.wires()).unwrap()
                    }
                };

                tx.send(GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap())
                    .unwrap();
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        assert_eq!(result1, x);
        assert_eq!(result2, x);
        assert_eq!(result3, x);
    }

    #[test]
    fn rep3_a2y_streaming() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let id = state.id;
                let delta = state.rngs.generate_random_garbler_delta(id);

                let converted = conversion::a2y_streaming(x, delta, &net, &mut state).unwrap();

                let output = match id {
                    PartyID::ID0 => {
                        let mut evaluator = StreamingRep3Evaluator::new(&net);
                        evaluator.output_all_parties(converted.wires()).unwrap()
                    }
                    PartyID::ID1 | PartyID::ID2 => {
                        let mut garbler =
                            StreamingRep3Garbler::new_with_delta(&net, &mut state, delta.unwrap());
                        garbler.output_all_parties(converted.wires()).unwrap()
                    }
                };

                tx.send(GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap())
                    .unwrap();
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        assert_eq!(result1, x);
        assert_eq!(result2, x);
        assert_eq!(result3, x);
    }

    #[test]
    fn rep3_y2a() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let delta = GCUtils::random_delta(&mut rng);
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = GCUtils::encode_field(x, &mut rng, delta);
        let x_shares = [
            x_shares.evaluator_wires,
            x_shares.garbler_wires.to_owned(),
            x_shares.garbler_wires,
        ];

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let converted =
                    conversion::y2a::<ark_bn254::Fr, _>(x, Some(delta), &net, &mut state).unwrap();
                tx.send(converted).unwrap();
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_y2a_streaming() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let delta = GCUtils::random_delta(&mut rng);
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = GCUtils::encode_field(x, &mut rng, delta);
        let x_shares = [
            x_shares.evaluator_wires,
            x_shares.garbler_wires.to_owned(),
            x_shares.garbler_wires,
        ];

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let converted =
                    conversion::y2a_streaming::<ark_bn254::Fr, _>(x, Some(delta), &net, &mut state)
                        .unwrap();
                tx.send(converted).unwrap();
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_b2y() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let id = state.id;
                let delta = state.rngs.generate_random_garbler_delta(id);

                let converted = conversion::b2y(&x, delta, &net, &mut state).unwrap();

                let output = match id {
                    PartyID::ID0 => {
                        let mut evaluator = Rep3Evaluator::new(&net);
                        evaluator.receive_circuit().unwrap();
                        evaluator.output_all_parties(converted.wires()).unwrap()
                    }
                    PartyID::ID1 | PartyID::ID2 => {
                        let mut garbler =
                            Rep3Garbler::new_with_delta(&net, &mut state, delta.unwrap());
                        garbler.output_all_parties(converted.wires()).unwrap()
                    }
                };

                tx.send(GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap())
                    .unwrap();
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        assert_eq!(result1, x);
        assert_eq!(result2, x);
        assert_eq!(result3, x);
    }

    #[test]
    fn rep3_b2y_streaming() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let id = state.id;
                let delta = state.rngs.generate_random_garbler_delta(id);

                let converted = conversion::b2y(&x, delta, &net, &mut state).unwrap();

                let output = match id {
                    PartyID::ID0 => {
                        let mut evaluator = StreamingRep3Evaluator::new(&net);
                        evaluator.output_all_parties(converted.wires()).unwrap()
                    }
                    PartyID::ID1 | PartyID::ID2 => {
                        let mut garbler =
                            StreamingRep3Garbler::new_with_delta(&net, &mut state, delta.unwrap());
                        garbler.output_all_parties(converted.wires()).unwrap()
                    }
                };

                tx.send(GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap())
                    .unwrap();
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        assert_eq!(result1, x);
        assert_eq!(result2, x);
        assert_eq!(result3, x);
    }

    #[test]
    fn rep3_y2b() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let delta = GCUtils::random_delta(&mut rng);
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = GCUtils::encode_field(x, &mut rng, delta);
        let x_shares = [
            x_shares.evaluator_wires,
            x_shares.garbler_wires.to_owned(),
            x_shares.garbler_wires,
        ];

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let converted = conversion::y2b::<ark_bn254::Fr, _>(x, &net, &mut state).unwrap();
                tx.send(converted).unwrap();
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);

        let should_result = x.into();
        assert_eq!(is_result, should_result);
        let is_result_f: ark_bn254::Fr = is_result.into();
        assert_eq!(is_result_f, x);
    }

    #[test]
    fn rep3_decompose_shared_field_many_via_yao() {
        const VEC_SIZE: usize = 10;
        const TOTAL_BIT_SIZE: usize = 64;
        const CHUNK_SIZE: usize = 14;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let mut should_result =
            Vec::with_capacity(VEC_SIZE * (TOTAL_BIT_SIZE.div_ceil(CHUNK_SIZE)));
        let big_mask = (BigUint::from(1u64) << TOTAL_BIT_SIZE) - BigUint::one();
        let small_mask = (BigUint::from(1u64) << CHUNK_SIZE) - BigUint::one();
        for x in x.into_iter() {
            let mut x: BigUint = x.into();
            x &= &big_mask;
            for _ in 0..TOTAL_BIT_SIZE.div_ceil(CHUNK_SIZE) {
                let chunk = &x & &small_mask;
                x >>= CHUNK_SIZE;
                should_result.push(ark_bn254::Fr::from(chunk));
            }
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed = yao::decompose_arithmetic_many(
                    &x,
                    &net,
                    &mut state,
                    TOTAL_BIT_SIZE,
                    CHUNK_SIZE,
                )
                .unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_decompose_shared_field_to_other_field_many_via_yao() {
        const VEC_SIZE: usize = 10;
        const TOTAL_BIT_SIZE: usize = 64;
        const CHUNK_SIZE: usize = 14;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let mut should_result =
            Vec::with_capacity(VEC_SIZE * (TOTAL_BIT_SIZE.div_ceil(CHUNK_SIZE)));
        let big_mask = (BigUint::from(1u64) << TOTAL_BIT_SIZE) - BigUint::one();
        let small_mask = (BigUint::from(1u64) << CHUNK_SIZE) - BigUint::one();
        for x in x.into_iter() {
            let mut x: BigUint = x.into();
            x &= &big_mask;
            for _ in 0..TOTAL_BIT_SIZE.div_ceil(CHUNK_SIZE) {
                let chunk = &x & &small_mask;
                x >>= CHUNK_SIZE;
                should_result.push(ark_bn254::Fq::from(chunk));
            }
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed = yao::decompose_arithmetic_to_other_field_many::<
                    ark_bn254::Fr,
                    ark_bn254::Fq,
                    _,
                >(&x, &net, &mut state, TOTAL_BIT_SIZE, CHUNK_SIZE)
                .unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    fn rep3_slice_shared_field_many_via_yao_inner(msb: usize, lsb: usize, bitsize: usize) {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let mut should_result = Vec::with_capacity(VEC_SIZE * 3);
        let big_mask = (BigUint::from(1u64) << bitsize) - BigUint::one();
        let hi_mask = (BigUint::one() << (bitsize - msb)) - BigUint::one();
        let lo_mask = (BigUint::one() << lsb) - BigUint::one();
        let slice_mask = (BigUint::one() << ((msb - lsb) as u32 + 1)) - BigUint::one();
        let msb_plus_one = msb as u32 + 1;

        for x in x.into_iter() {
            let mut x: BigUint = x.into();
            x &= &big_mask;
            let hi = (&x >> msb_plus_one) & &hi_mask;
            let lo = &x & &lo_mask;
            let slice = (&x >> lsb) & &slice_mask;
            assert_eq!(x, &lo + (&slice << lsb) + (&hi << msb_plus_one));
            should_result.push(ark_bn254::Fr::from(lo));
            should_result.push(ark_bn254::Fr::from(slice));
            should_result.push(ark_bn254::Fr::from(hi));
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed =
                    yao::slice_arithmetic_many(&x, &net, &mut state, msb, lsb, bitsize).unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_slice_shared_field_many_via_yao() {
        rep3_slice_shared_field_many_via_yao_inner(253, 0, 254);
        rep3_slice_shared_field_many_via_yao_inner(100, 10, 254);
        rep3_slice_shared_field_many_via_yao_inner(100, 10, 110);
    }

    #[test]
    fn rep3_slice_and_and_rotated() {
        const VEC_SIZE: usize = 10;
        const TOTAL_BIT_SIZE: usize = 32;
        const ROTATION: usize = 2;
        const BASE_BIT: usize = 6;
        const BASE: usize = 1 << BASE_BIT;
        const NUM_DECOMPS: usize = TOTAL_BIT_SIZE.div_ceil(BASE_BIT);

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mask: BigUint = (BigUint::one() << TOTAL_BIT_SIZE) - BigUint::one();
        let x = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let y = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let y_shares = rep3::share_field_elements(&y, &mut rng);

        let mut should_result = Vec::new();
        for (x, y) in x.into_iter().zip(y.into_iter()) {
            let mut x: BigUint = x.into();
            let mut y: BigUint = y.into();
            let mut xs = Vec::with_capacity(NUM_DECOMPS);
            let mut ys = Vec::with_capacity(NUM_DECOMPS);
            let mut rs = Vec::with_capacity(NUM_DECOMPS);

            for _ in 0..NUM_DECOMPS {
                let res1 = &x % BASE;
                xs.push(ark_bn254::Fr::from(res1.clone()));
                x /= BASE;
                let res2 = &y % BASE;
                ys.push(ark_bn254::Fr::from(res2.clone()));
                y /= BASE;
                let res = u64::try_from(res1 & res2).unwrap();
                let rotated = res.rotate_right(ROTATION as u32);
                rs.push(ark_bn254::Fr::from(rotated));
            }
            should_result.extend(xs);
            should_result.extend(ys);
            should_result.extend(rs);
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed = yao::slice_and_many(
                    &x,
                    &y,
                    &net,
                    &mut state,
                    BASE_BIT,
                    ROTATION,
                    TOTAL_BIT_SIZE,
                )
                .unwrap();
                tx.send(decomposed)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_compute_wnaf_digits() {
        const VEC_SIZE: usize = 10;

        const NUM_SCALAR_BITS: usize = 128; // The length of scalars handled by the ECCVVM
        const NUM_WNAF_DIGIT_BITS: usize = 4; // Scalars are decompose into base 16 in wNAF form
        const NUM_WNAF_DIGITS_PER_SCALAR: usize = NUM_SCALAR_BITS / NUM_WNAF_DIGIT_BITS; // 32
        const WNAF_MASK: u64 = (1 << NUM_WNAF_DIGIT_BITS) - 1;
        const WNAF_DIGITS_PER_ROW: usize = 4;
        let num_rows_per_scalar = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mask: BigUint = (BigUint::one() << NUM_SCALAR_BITS) - BigUint::one();
        let x = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let mut should_result = Vec::with_capacity(
            VEC_SIZE * NUM_WNAF_DIGITS_PER_SCALAR + VEC_SIZE * (NUM_WNAF_DIGITS_PER_SCALAR - 1),
        );
        let mut should_result_pos = Vec::with_capacity(
            VEC_SIZE * NUM_WNAF_DIGITS_PER_SCALAR + VEC_SIZE * (NUM_WNAF_DIGITS_PER_SCALAR - 1),
        );
        let mut should_result_even = Vec::with_capacity(VEC_SIZE);
        let mut should_result_unchanged = Vec::with_capacity(VEC_SIZE * NUM_WNAF_DIGITS_PER_SCALAR);
        let mut should_result_row_chunks =
            Vec::with_capacity(VEC_SIZE * NUM_WNAF_DIGITS_PER_SCALAR);
        let mut should_result_row_chunks_neg =
            Vec::with_capacity(VEC_SIZE * NUM_WNAF_DIGITS_PER_SCALAR);
        let mut should_result_row_s = Vec::with_capacity(VEC_SIZE * NUM_WNAF_DIGITS_PER_SCALAR);

        let compute_wnaf_digits = |mut scalar: BigUint| -> (
            [i32; NUM_WNAF_DIGITS_PER_SCALAR],
            [bool; NUM_WNAF_DIGITS_PER_SCALAR],
            [i32; NUM_WNAF_DIGITS_PER_SCALAR],
        ) {
            let mut output = [0; NUM_WNAF_DIGITS_PER_SCALAR];
            let mut pos_output = [true; NUM_WNAF_DIGITS_PER_SCALAR];
            let mut neg_output = [0i32; NUM_WNAF_DIGITS_PER_SCALAR];
            let mut previous_slice = 0;
            const BORROW_CONSTANT: i32 = 1 << NUM_WNAF_DIGIT_BITS;

            for i in 0..NUM_WNAF_DIGITS_PER_SCALAR {
                let raw_slice = &scalar & BigUint::from(WNAF_MASK);
                let is_even = (&raw_slice & BigUint::one()) == BigUint::zero();
                let mut wnaf_slice = raw_slice
                    .to_u32_digits()
                    .first()
                    .cloned()
                    .unwrap_or_default() as i32;

                if i == 0 && is_even {
                    wnaf_slice += 1;
                } else if is_even {
                    previous_slice -= BORROW_CONSTANT;

                    wnaf_slice += 1;
                }

                if i > 0 {
                    if previous_slice < 0 {
                        pos_output[NUM_WNAF_DIGITS_PER_SCALAR - i] = false;
                    }
                    neg_output[NUM_WNAF_DIGITS_PER_SCALAR - i] = previous_slice;
                    output[NUM_WNAF_DIGITS_PER_SCALAR - i] = (previous_slice + 15) / 2;
                }
                previous_slice = wnaf_slice;

                scalar >>= NUM_WNAF_DIGIT_BITS;
            }

            assert!(scalar.is_zero());
            output[0] = (previous_slice + 15) / 2;
            pos_output[0] = previous_slice > 0;
            neg_output[0] = previous_slice;

            (output, pos_output, neg_output)
        };
        for x in x.into_iter() {
            let x: BigUint = x.into();
            let (wnaf_digits, neg_output, outputs_unchanged) = compute_wnaf_digits(x.clone());
            let is_even = (x & BigUint::one()) == BigUint::zero();
            should_result_even.push(ark_bn254::Fr::from(is_even as u64));
            should_result.extend(wnaf_digits.iter().map(|&d| ark_bn254::Fr::from(d as u64)));
            should_result_pos.extend(neg_output);
            should_result_unchanged.extend(outputs_unchanged);
        }

        // This happens later in the code in compute_rows, but we put it into the gc to save time
        for chunk in should_result_unchanged.chunks(NUM_WNAF_DIGITS_PER_SCALAR) {
            for i in 0..num_rows_per_scalar {
                let slice0 = &chunk[i * WNAF_DIGITS_PER_ROW];
                let slice1 = &chunk[i * WNAF_DIGITS_PER_ROW + 1];
                let slice2 = &chunk[i * WNAF_DIGITS_PER_ROW + 2];
                let slice3 = &chunk[i * WNAF_DIGITS_PER_ROW + 3];
                let row_chunk = slice3 + (slice2 << 4) + (slice1 << 8) + (slice0 << 12);

                let slice0base2 = (slice0 + 15) / 2;
                let slice1base2 = (slice1 + 15) / 2;
                let slice2base2 = (slice2 + 15) / 2;
                let slice3base2 = (slice3 + 15) / 2;

                // Convert into 2-bit chunks
                let row_s1 = slice0base2 >> 2;
                let row_s2 = slice0base2 & 3;
                let row_s3 = slice1base2 >> 2;
                let row_s4 = slice1base2 & 3;
                let row_s5 = slice2base2 >> 2;
                let row_s6 = slice2base2 & 3;
                let row_s7 = slice3base2 >> 2;
                let row_s8 = slice3base2 & 3;
                should_result_row_s.push(ark_bn254::Fr::from(row_s1 as u64));
                should_result_row_s.push(ark_bn254::Fr::from(row_s2 as u64));
                should_result_row_s.push(ark_bn254::Fr::from(row_s3 as u64));
                should_result_row_s.push(ark_bn254::Fr::from(row_s4 as u64));
                should_result_row_s.push(ark_bn254::Fr::from(row_s5 as u64));
                should_result_row_s.push(ark_bn254::Fr::from(row_s6 as u64));
                should_result_row_s.push(ark_bn254::Fr::from(row_s7 as u64));
                should_result_row_s.push(ark_bn254::Fr::from(row_s8 as u64));
                if row_chunk < 0 {
                    should_result_row_chunks_neg.push(ark_bn254::Fr::one())
                } else {
                    should_result_row_chunks_neg.push(ark_bn254::Fr::zero())
                }
                should_result_row_chunks.push(ark_bn254::Fr::from(row_chunk.unsigned_abs()));
            }
        }

        let should_result_neg: Vec<ark_bn254::Fr> = should_result_pos
            .iter()
            .map(|x| {
                if *x {
                    ark_bn254::Fr::one()
                } else {
                    ark_bn254::Fr::zero()
                }
            })
            .collect();

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed = yao::compute_wnaf_digits_and_compute_rows_many(
                    &x,
                    &net,
                    &mut state,
                    NUM_SCALAR_BITS,
                )
                .unwrap();
                tx.send(decomposed)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);

        let mut is_result_even = Vec::with_capacity(32 * VEC_SIZE);
        let mut is_result_values = Vec::<ark_bn254::Fr>::with_capacity(32 * VEC_SIZE);
        let mut is_result_pos = Vec::<ark_bn254::Fr>::with_capacity(VEC_SIZE);
        let mut row_s = Vec::with_capacity(8 * 8 * VEC_SIZE);
        let mut row_chunks_abs = Vec::with_capacity(8 * VEC_SIZE);
        let mut row_chunks_neg = Vec::with_capacity(8 * VEC_SIZE);

        let chunk_size: usize = 32 + 32 + 1 + 8 * 8 + 8 + 8;
        for chunk in is_result.chunks(chunk_size) {
            is_result_even.push(chunk[0]);

            for second_chunk in chunk[1..].chunks(18) {
                let tmp_values = second_chunk.iter().step_by(2).take(4);
                is_result_values.extend(tmp_values);
                let tmp_values = second_chunk.iter().skip(1).step_by(2).take(4);
                is_result_pos.extend(tmp_values);
                row_s.extend_from_slice(&second_chunk[8..16]);
                row_chunks_abs.push(second_chunk[16]);
                row_chunks_neg.push(second_chunk[17]);
            }
        }

        assert_eq!(is_result_even, should_result_even);
        assert_eq!(is_result_values, should_result);
        assert_eq!(is_result_pos, should_result_neg);
        assert_eq!(row_s, should_result_row_s);
        assert_eq!(row_chunks_abs, should_result_row_chunks);
        assert_eq!(row_chunks_neg, should_result_row_chunks_neg);
    }

    #[test]
    fn rep3_slice_and_xor_rotated() {
        const VEC_SIZE: usize = 10;
        const TOTAL_BIT_SIZE: usize = 32;
        const ROTATION: usize = 2;
        const BASE_BIT: usize = 6;
        const BASE: usize = 1 << BASE_BIT;
        const NUM_DECOMPS: usize = TOTAL_BIT_SIZE.div_ceil(BASE_BIT);

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mask: BigUint = (BigUint::one() << TOTAL_BIT_SIZE) - BigUint::one();
        let x = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let y = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let y_shares = rep3::share_field_elements(&y, &mut rng);

        let mut should_result = Vec::new();
        for (x, y) in x.into_iter().zip(y.into_iter()) {
            let mut x: BigUint = x.into();
            let mut y: BigUint = y.into();
            let mut xs = Vec::with_capacity(NUM_DECOMPS);
            let mut ys = Vec::with_capacity(NUM_DECOMPS);
            let mut rs = Vec::with_capacity(NUM_DECOMPS);

            for _ in 0..NUM_DECOMPS {
                let res1 = &x % BASE;
                xs.push(ark_bn254::Fr::from(res1.clone()));
                x /= BASE;
                let res2 = &y % BASE;
                ys.push(ark_bn254::Fr::from(res2.clone()));
                y /= BASE;
                let res = u64::try_from(res1 ^ res2).unwrap();
                let rotated = res.rotate_right(ROTATION as u32);
                rs.push(ark_bn254::Fr::from(rotated));
            }
            should_result.extend(xs);
            should_result.extend(ys);
            should_result.extend(rs);
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed = yao::slice_xor_many(
                    &x,
                    &y,
                    &net,
                    &mut state,
                    BASE_BIT,
                    ROTATION,
                    TOTAL_BIT_SIZE,
                )
                .unwrap();
                tx.send(decomposed)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_batcher_odd_even_merge_sort_via_yao() {
        const VEC_SIZE: usize = 10;
        const CHUNK_SIZE: usize = 14;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let mut should_result = Vec::with_capacity(VEC_SIZE);
        let mask = (BigUint::from(1u64) << CHUNK_SIZE) - BigUint::one();
        for x in x.into_iter() {
            let mut x: BigUint = x.into();
            x &= &mask;
            should_result.push(ark_bn254::Fr::from(x));
        }
        should_result.sort();

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed = gadgets::sort::batcher_odd_even_merge_sort_yao(
                    &x, &net, &mut state, CHUNK_SIZE,
                )
                .unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_radix_sort() {
        const VEC_SIZE: usize = 20;
        const CHUNK_SIZE: usize = 14;

        let nets0 = LocalNetwork::new_3_parties();
        let nets1 = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x[..VEC_SIZE / 2], &mut rng);

        // Only sort by the first CHUNK_SIZE bits
        let mut shortened = Vec::with_capacity(VEC_SIZE);
        let mask = (BigUint::from(1u64) << CHUNK_SIZE) - BigUint::one();
        for (i, x) in x.iter().cloned().enumerate() {
            let mut x: BigUint = x.into();
            x &= &mask;
            shortened.push((i, ark_bn254::Fr::from(x)));
        }
        shortened.sort_by(|a, b| a.1.cmp(&b.1));
        let mut should_result = Vec::with_capacity(VEC_SIZE);
        for (i, _) in shortened.into_iter() {
            should_result.push(x[i]);
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net0, net1, tx, x_) in izip!(
            nets0.into_iter(),
            nets1.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            let x_pub = x[VEC_SIZE / 2..].to_vec();
            std::thread::spawn(move || {
                let mut state0 = Rep3State::new(&net0, A2BType::default()).unwrap();
                let mut state1 = state0.fork(0).unwrap();

                let decomposed = rep3_ring::gadgets::sort::radix_sort_fields(
                    x_,
                    x_pub,
                    CHUNK_SIZE,
                    &net0,
                    &net1,
                    &mut state0,
                    &mut state1,
                )
                .unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sha256() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mut state: Vec<u32> = (0..8).map(|_| rng.gen()).collect();
        let message: Vec<u32> = (0..16).map(|_| rng.gen()).collect();

        let x = state.iter().map(|&x| ark_bn254::Fr::from(x)).collect_vec();
        let y = message
            .iter()
            .map(|&x| ark_bn254::Fr::from(x))
            .collect_vec();

        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let y_shares = rep3::share_field_elements(&y, &mut rng);

        let mut blocks = [0_u8; 64];
        for (i, block) in message.iter().enumerate() {
            let bytes = block.to_be_bytes();
            blocks[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }

        let blocks = blocks.into();
        sha2::compress256(state.as_mut_slice().try_into().unwrap(), &[blocks]);
        let should_result: Vec<_> = state
            .iter()
            .map(|x| ark_bn254::Fr::from(*x as u128))
            .collect();

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter(),
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let res = rep3::yao::sha256_from_bristol(
                    x.as_slice().try_into().expect("Expected slice of size 8"),
                    y.as_slice().try_into().expect("Expected slice of size 16"),
                    &net,
                    &mut state,
                )
                .unwrap();
                tx.send(res)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    fn slice_and_get_sparse_table_with_rotation_values<const BASE: u64>(
        slice_sizes: Vec<u64>,
        rotation_values: Vec<u32>,
    ) {
        const VEC_SIZE: usize = 10;
        const TOTAL_BIT_SIZE: usize = 128;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mask: BigUint = (BigUint::one() << TOTAL_BIT_SIZE) - BigUint::one();
        let keys_a = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let keys_b = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let x_shares = rep3::share_field_elements(&keys_a, &mut rng);
        let y_shares = rep3::share_field_elements(&keys_b, &mut rng);

        let mut should_result = Vec::new();
        for (x, y) in keys_a.into_iter().zip(keys_b) {
            let mut x: BigUint = x.into();
            let mut y: BigUint = y.into();
            let mut xs = Vec::with_capacity(slice_sizes.len());
            let mut ys = Vec::with_capacity(slice_sizes.len());
            let mut rs0 = Vec::with_capacity(slice_sizes.len());
            let mut rs1 = Vec::with_capacity(slice_sizes.len());

            for (rot, slice) in rotation_values.iter().zip(slice_sizes.iter()) {
                let res1 = &x % slice;
                xs.push(ark_bn254::Fr::from(res1.clone()));
                x /= *slice;
                let res2 = &y % slice;
                ys.push(ark_bn254::Fr::from(res2.clone()));
                y /= *slice;
                let res = u64::try_from(res1).unwrap();
                let mapped_into = Utils::map_into_sparse_form::<BASE>(res);
                rs0.push(ark_bn254::Fr::from(mapped_into));
                let rotated: u32 = u32::try_from(res).unwrap();
                let rotated = rotated.rotate_right(*rot);
                let mapped_into = Utils::map_into_sparse_form::<BASE>(rotated as u64);
                rs1.push(ark_bn254::Fr::from(mapped_into));
            }
            should_result.extend(xs);
            should_result.extend(ys);
            should_result.extend(rs0);
            should_result.extend(rs1);
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter(),
        ) {
            let slices = slice_sizes.clone();
            let rotation = rotation_values.clone();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let res = rep3::yao::get_sparse_table_with_rotation_values_many(
                    &x,
                    &y,
                    &net,
                    &mut state,
                    &slices,
                    &rotation,
                    TOTAL_BIT_SIZE,
                )
                .unwrap();
                tx.send(res)
            });
        }
        let base_powers = Utils::get_base_powers::<BASE, 32>();
        let base_powers = base_powers
            .iter()
            .map(|x| ark_bn254::Fr::from(x.clone()))
            .collect_vec();
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let result_chunk = result3.len() / VEC_SIZE;

        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        let mut result = Vec::new();
        let slices_len = slice_sizes.len();
        for res in is_result.chunks_exact(result_chunk) {
            result.extend_from_slice(&res[..2 * slices_len]);
            let mut res0 = Vec::with_capacity((res.len() - 2 * slices_len) / 64);
            let mut res1 = Vec::with_capacity((res.len() - 2 * slices_len) / 64);
            for chunk in res[2 * slices_len..].chunks_exact(64) {
                let mut vec_t0 = chunk[..32].to_vec();
                let mut vec_t1 = chunk[32..].to_vec();

                for (a, b) in vec_t0.iter_mut().zip(base_powers.iter()) {
                    *a *= b;
                }
                for (a, b) in vec_t1.iter_mut().zip(base_powers.iter()) {
                    *a *= b;
                }
                let sum_a = vec_t0.iter().sum::<ark_bn254::Fr>();
                let sum_b = vec_t1.iter().sum::<ark_bn254::Fr>();
                res0.push(sum_a);
                res1.push(sum_b);
            }
            result.extend(res0);
            result.extend(res1);
        }
        assert_eq!(result, should_result);
    }

    #[test]
    fn test_slice_and_get_sparse_table_with_rotation_values() {
        slice_and_get_sparse_table_with_rotation_values::<16>(
            vec![(1 << 3), (1 << 7), (1 << 8), (1 << 18)],
            vec![0, 4, 7, 1],
        );
        slice_and_get_sparse_table_with_rotation_values::<28>(
            vec![(1 << 11), (1 << 11), (1 << 10)],
            vec![6, 0, 3],
        );
        slice_and_get_sparse_table_with_rotation_values::<16>(
            vec![(1 << 11), (1 << 11), (1 << 10)],
            vec![2, 2, 0],
        );
    }

    fn slice_and_get_sparse_normalization_values<const BASE: u64>(
        slice_sizes: Vec<u64>,
        base_table: &[u64],
        table_type: &SHA256Table,
    ) {
        const VEC_SIZE: usize = 1;
        const TOTAL_BIT_SIZE: usize = 128;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mask: BigUint = (BigUint::one() << TOTAL_BIT_SIZE) - BigUint::one();
        let keys_a = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let keys_b = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let x_shares = rep3::share_field_elements(&keys_a, &mut rng);
        let y_shares = rep3::share_field_elements(&keys_b, &mut rng);

        let mut should_result = Vec::new();
        for (x, y) in keys_a.into_iter().zip(keys_b.into_iter()) {
            let mut x: BigUint = x.into();
            let mut y: BigUint = y.into();
            let mut xs = Vec::with_capacity(slice_sizes.len());
            let mut ys = Vec::with_capacity(slice_sizes.len());
            let mut rs0 = Vec::with_capacity(slice_sizes.len());

            for slice in slice_sizes.iter() {
                let res1 = &x % slice;
                xs.push(ark_bn254::Fr::from(res1.clone()));
                x /= *slice;
                let res2 = &y % slice;
                ys.push(ark_bn254::Fr::from(res2.clone()));
                y /= *slice;

                let res = u64::try_from(res1).unwrap();
                let mut accumulator = 0u64;
                let mut input = res;
                let mut count = 0u64;
                while input > 0 {
                    let slice = input % BASE;
                    let bit = base_table[slice as usize];
                    accumulator += bit << count;
                    input -= slice;
                    input /= BASE;
                    count += 1;
                }
                rs0.push(ark_bn254::Fr::from(accumulator));
            }
            should_result.extend(xs);
            should_result.extend(ys);
            should_result.extend(rs0);
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter(),
        ) {
            let base_bits = slice_sizes.clone();
            let table_type = *table_type;
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let res = rep3::yao::get_sparse_normalization_values_many(
                    &x,
                    &y,
                    &net,
                    &mut state,
                    &base_bits,
                    BASE,
                    TOTAL_BIT_SIZE,
                    &table_type,
                )
                .unwrap();
                tx.send(res)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(
            is_result
                .iter()
                .map(|&x| ark_bn254::Fr::from(x))
                .collect_vec(),
            should_result
                .iter()
                .map(|&x| ark_bn254::Fr::from(x))
                .collect_vec()
        );
    }

    #[test]
    fn test_slice_and_get_sparse_normalization_values() {
        const MAJORITY_NORMALIZATION_TABLE: [u64; 16] =
            [0, 0, 1, 1, 1, 1, 2, 2, 0, 0, 1, 1, 1, 1, 2, 2];

        const CHOOSE_NORMALIZATION_TABLE: [u64; 28] = [
            0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 2, 1, 2, 2, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 2, 1, 2, 2,
        ];

        const WITNESS_EXTENSION_NORMALIZATION_TABLE: [u64; 16] =
            [0, 1, 0, 1, 1, 2, 1, 2, 0, 1, 0, 1, 1, 2, 1, 2];

        slice_and_get_sparse_normalization_values::<28>(
            vec![28u64.pow(2); 16],
            &CHOOSE_NORMALIZATION_TABLE,
            &SHA256Table::Choose,
        );

        slice_and_get_sparse_normalization_values::<16>(
            vec![16u64.pow(3); 11],
            &MAJORITY_NORMALIZATION_TABLE,
            &SHA256Table::Majority,
        );
        slice_and_get_sparse_normalization_values::<16>(
            vec![16u64.pow(3); 11],
            &WITNESS_EXTENSION_NORMALIZATION_TABLE,
            &SHA256Table::WitnessExtension,
        );
    }

    fn slice_and_get_aes_sparse_normalization_values<const BASE: u64>(slice_sizes: Vec<u64>) {
        const VEC_SIZE: usize = 3;
        const TOTAL_BIT_SIZE: usize = 64;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mask: BigUint = (BigUint::one() << TOTAL_BIT_SIZE) - BigUint::one();
        let keys_a = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let keys_b = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let x_shares = rep3::share_field_elements(&keys_a, &mut rng);
        let y_shares = rep3::share_field_elements(&keys_b, &mut rng);

        let mut should_result = Vec::new();
        for (x, y) in keys_a.into_iter().zip(keys_b.into_iter()) {
            let mut x: BigUint = x.into();
            let mut y: BigUint = y.into();
            let mut xs = Vec::with_capacity(slice_sizes.len());
            let mut ys = Vec::with_capacity(slice_sizes.len());
            let mut rs0 = Vec::with_capacity(slice_sizes.len());

            for slice in slice_sizes.iter() {
                let res1 = &x % slice;
                xs.push(ark_bn254::Fr::from(res1.clone()));
                rs0.push(ark_bn254::Fr::from(
                    Utils::map_into_sparse_form::<{ BASE }>(
                        Utils::map_from_sparse_form::<{ BASE }>(res1),
                    ),
                ));
                x /= *slice;
                let res2 = &y % slice;
                ys.push(ark_bn254::Fr::from(res2.clone()));
                y /= *slice;
            }
            should_result.extend(xs);
            should_result.extend(ys);
            should_result.extend(rs0);
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y) in izip!(
            nets,
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter(),
        ) {
            let base_bits = slice_sizes.clone();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let res = rep3::yao::slice_and_map_from_sparse_form_many(
                    &x,
                    &y,
                    &net,
                    &mut state,
                    &base_bits,
                    BASE,
                    TOTAL_BIT_SIZE,
                )
                .unwrap();
                tx.send(res)
            });
        }
        let base_powers = Utils::get_base_powers::<BASE, 32>();
        let base_powers = base_powers
            .iter()
            .map(|x| ark_bn254::Fr::from(x.clone()))
            .collect_vec();
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let result_chunk = result3.len() / VEC_SIZE;
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        let mut result = Vec::new();
        let slices_len = slice_sizes.len();

        for res in is_result.chunks_exact(result_chunk) {
            result.extend_from_slice(&res[..2 * slices_len]);
            let mut res0 = Vec::with_capacity((res.len() - 2 * slices_len) / 8);
            for chunk in res[2 * slices_len..].chunks_exact(8) {
                let mut vec_t0 = chunk.to_vec();

                for (a, b) in vec_t0.iter_mut().zip(base_powers.iter()) {
                    *a *= b;
                }

                let sum_a = vec_t0.iter().sum::<ark_bn254::Fr>();
                res0.push(sum_a);
            }
            result.extend(res0);
        }

        assert_eq!(result, should_result);
    }

    #[test]
    fn test_slice_and_get_aes_sparse_normalization_values() {
        slice_and_get_aes_sparse_normalization_values::<9>(vec![9u64.pow(4); 2]);
    }

    fn slice_and_get_aes_sbox_values<const BASE: u64>(slice_sizes: Vec<u64>) {
        const VEC_SIZE: usize = 5;
        const TOTAL_BIT_SIZE: usize = 64;
        let s_box = AES128_SBOX;

        let nets0 = LocalNetwork::new_3_parties();
        let nets1 = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mask: BigUint = (BigUint::one() << TOTAL_BIT_SIZE) - BigUint::one();
        let keys_a = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let keys_b = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();
        let x_shares = rep3::share_field_elements(&keys_a, &mut rng);
        let y_shares = rep3::share_field_elements(&keys_b, &mut rng);

        let mut should_result = Vec::new();
        for (x, y) in keys_a.into_iter().zip(keys_b.into_iter()) {
            let mut x: BigUint = x.into();
            let mut y: BigUint = y.into();
            let mut xs = Vec::with_capacity(slice_sizes.len());
            let mut ys = Vec::with_capacity(slice_sizes.len());
            let mut rs0 = Vec::with_capacity(slice_sizes.len());
            let mut rs1 = Vec::with_capacity(slice_sizes.len());

            for slice in slice_sizes.iter() {
                let res1 = &x % slice;
                xs.push(ark_bn254::Fr::from(res1.clone()));
                let byte = Utils::map_from_sparse_form::<{ BASE }>(res1);
                let sbox_value = AES128_SBOX[byte as usize];
                let swizzled = (sbox_value << 1u8) ^ (((sbox_value >> 7u8) & 1u8) * 0x1b);
                rs0.push(ark_bn254::Fr::from(
                    Utils::map_into_sparse_form::<{ BASE }>(sbox_value as u64),
                ));
                rs1.push(ark_bn254::Fr::from(
                    Utils::map_into_sparse_form::<{ BASE }>((sbox_value ^ swizzled) as u64),
                ));
                x /= *slice;
                let res2 = &y % slice;
                ys.push(ark_bn254::Fr::from(res2.clone()));
                y /= *slice;
            }
            should_result.extend(xs);
            should_result.extend(ys);
            should_result.extend(rs0);
            should_result.extend(rs1);
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net0, net1, tx, x, y) in izip!(
            nets0,
            nets1,
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter(),
        ) {
            let base_bits = slice_sizes.clone();
            let slices = slice_sizes.len();
            std::thread::spawn(move || {
                let mut state0 = Rep3State::new(&net0, A2BType::default()).unwrap();
                let mut state1 = state0.fork(0).unwrap();
                let res = rep3::yao::slice_and_map_from_sparse_form_many_sbox(
                    &x,
                    &y,
                    &net0,
                    &mut state0,
                    &base_bits,
                    BASE,
                    TOTAL_BIT_SIZE,
                )
                .unwrap();
                let result_chunk = res.len() / VEC_SIZE;
                let mut xs = Vec::new();
                let mut ys = Vec::new();
                let mut rs = Vec::new();
                let mut rs0 = Vec::new();
                let mut rs1 = Vec::new();
                for val in res.chunks(result_chunk) {
                    xs.extend_from_slice(&val[..slices]);
                    ys.extend_from_slice(&val[slices..2 * slices]);
                    rs.extend_from_slice(&val[2 * slices..]);
                }

                let sbox_lut = rep3_ring::lut_field::PublicPrivateLut::Public(
                    s_box
                        .iter()
                        .map(|&value| ark_bn254::Fr::from(value))
                        .collect::<Vec<_>>(),
                );
                let base_powers = Utils::get_base_powers::<BASE, 32>();
                let base_powers: [ark_bn254::Fr; 32] =
                    array::from_fn(|i| ark_bn254::Fr::from(base_powers[i].clone()));

                let rs = conversion::a2b_many(&rs, &net0, &mut state0).unwrap();
                for key in rs {
                    let sbox_value =
                        rep3_ring::lut_field::Rep3FieldLookupTable::get_from_public_lut_no_b2a_conversion::<
                            u8,
                            _,
                        >(
                            key, &sbox_lut, &net0, &net1, &mut state0, &mut state1
                        )
                        .unwrap();

                    let shift_1 = sbox_value.clone() << 1;
                    let shift_2 = sbox_value.clone() >> 7;
                    let and = shift_2 & BigUint::one();

                    // This is a multiplication by 0x1b in the binary domain
                    let mut and2a = &and << 4;
                    and2a = and2a.bitxor(&and << 3);
                    and2a = and2a.bitxor(&and << 1);
                    and2a = and2a.bitxor(and);

                    let swizzled = shift_1.bitxor(and2a);
                    let value = swizzled.bitxor(sbox_value.clone());
                    let mut a_bits_split =
                        (0..8).map(|i| (&value >> i) & BigUint::one()).collect_vec();
                    a_bits_split.extend(
                        (0..8)
                            .map(|i| (&sbox_value >> i) & BigUint::one())
                            .collect_vec(),
                    );
                    let bin_share =
                        rep3::conversion::bit_inject_many(&a_bits_split, &net0, &mut state0)
                            .unwrap();
                    let (bin_share, second_bin_share) = bin_share.split_at(bin_share.len() / 2);
                    let mut sum_a = arithmetic::mul_public(bin_share[0], base_powers[0]);
                    let mut sum_b = arithmetic::mul_public(second_bin_share[0], base_powers[0]);
                    for (vec_t0_, vec_t1_, base_power) in izip!(
                        bin_share.iter().cloned(),
                        second_bin_share.iter().cloned(),
                        base_powers.iter()
                    )
                    .skip(1)
                    .take(31)
                    {
                        let tmp = arithmetic::mul_public(vec_t0_, *base_power);
                        sum_a = arithmetic::add(sum_a, tmp);
                        let tmp = arithmetic::mul_public(vec_t1_, *base_power);
                        sum_b = arithmetic::add(sum_b, tmp);
                    }
                    rs0.push(sum_b);
                    rs1.push(sum_a);
                }
                let mut result: Vec<_> = Vec::new();
                for (x, y, r0, r1) in izip!(
                    xs.chunks(slices),
                    ys.chunks(slices),
                    rs0.chunks(slices),
                    rs1.chunks(slices),
                ) {
                    result.extend(x);
                    result.extend(y);
                    result.extend(r0);
                    result.extend(r1);
                }
                tx.send(result)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn test_slice_and_get_aes_sbox_values() {
        const NUM_RUNS: usize = 5;
        for _ in 0..NUM_RUNS {
            slice_and_get_aes_sbox_values::<9>(vec![9u64.pow(8); 1]);
        }
    }

    fn accumulate_from_sparse_bytes<const BASE: u64>(input_bitsize: usize, output_bitsize: usize) {
        const VEC_SIZE: usize = 16;
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mask: BigUint = (BigUint::one() << input_bitsize) - BigUint::one();
        let input = (0..VEC_SIZE)
            .map(|_| {
                let res = BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask;
                ark_bn254::Fr::from(res)
            })
            .collect_vec();

        let x_shares = rep3::share_field_elements(&input, &mut rng);

        let mut accumulator = BigUint::zero();
        let byte_mask: BigUint = (BigUint::one() << output_bitsize) - BigUint::one();
        for byte in input.iter() {
            let mut sparse_byte = BigUint::from(*byte);
            sparse_byte &= BigUint::from(u64::MAX);
            let byte = Utils::map_from_sparse_form::<BASE>(sparse_byte);
            accumulator <<= 8;
            accumulator += BigUint::from(byte) & byte_mask.clone();
        }
        let should_result = ark_bn254::Fr::from(accumulator);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let res = rep3::yao::accumulate_from_sparse_bytes(
                    &x,
                    &net,
                    &mut state,
                    input_bitsize,
                    output_bitsize,
                    BASE,
                )
                .unwrap();
                tx.send(res)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);

        assert_eq!(is_result[0], should_result);
    }

    #[test]
    fn test_accumulate_from_sparse_bytes() {
        const BASE: u64 = 9;
        let input_bitsize = 64;
        let output_bitsize = 8;
        accumulate_from_sparse_bytes::<{ BASE }>(input_bitsize, output_bitsize);
    }

    #[test]
    fn rep3_aes() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let plaintext_size: usize = rng.gen::<u8>() as usize % 1024;
        let key: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        let iv: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        let pt: Vec<u8> = (0..plaintext_size).map(|_| rng.gen()).collect();

        let x = pt.iter().map(|&x| ark_bn254::Fr::from(x)).collect_vec();
        let y = key.iter().map(|&x| ark_bn254::Fr::from(x)).collect_vec();
        let z = iv.iter().map(|&x| ark_bn254::Fr::from(x)).collect_vec();

        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let y_shares = rep3::share_field_elements(&y, &mut rng);
        let z_shares = rep3::share_field_elements(&z, &mut rng);

        let mut pt_to_be_bytes = Vec::with_capacity(x.len());
        let mut iv_to_be_bytes = Vec::with_capacity(y.len());
        let mut key_to_be_bytes = Vec::with_capacity(z.len());
        for inp in x {
            let byte = inp.into_bigint().as_ref()[0].to_le_bytes()[0];
            pt_to_be_bytes.push(byte);
        }
        for inp in y {
            let byte = inp.into_bigint().as_ref()[0].to_le_bytes()[0];
            key_to_be_bytes.push(byte);
        }
        for inp in z {
            let byte = inp.into_bigint().as_ref()[0].to_le_bytes()[0];
            iv_to_be_bytes.push(byte);
        }
        let cipher = Cipher::new_128(
            key_to_be_bytes
                .as_slice()
                .try_into()
                .expect("slice with incorrect length"),
        );
        let encrypted = cipher.cbc_encrypt(&iv_to_be_bytes, &pt_to_be_bytes);
        let should_result: Vec<_> = encrypted
            .iter()
            .map(|x| ark_bn254::Fr::from(*x as u128))
            .collect();

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x, y, z) in izip!(
            nets,
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter(),
            z_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let res = rep3::yao::aes_from_bristol(&x, &y, &z, &net, &mut state).unwrap();
                tx.send(res)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(
            is_result
                .iter()
                .map(|&x| ark_bn254::Fr::from(x))
                .collect_vec(),
            should_result
                .iter()
                .map(|&x| ark_bn254::Fr::from(x))
                .collect_vec()
        );
    }

    fn rep3_mod_red(a: u64, b: u64) {
        let nets = LocalNetwork::new_3_parties();
        let should_result = ark_bn254::Fr::from(a % b);
        let a = ark_bn254::Fr::from(a);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        let [net1, net2, net3] = nets;

        // Both Garblers
        for (net, tx) in izip!([net2, net3], [tx2, tx3]) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mut garbler = Rep3Garbler::new(&net, &mut state);
                let x_ = garbler.encode_field(a);

                // This is without OT, just a simulation
                garbler.add_bundle_to_circuit(&x_.evaluator_wires);

                let circuit_output = GarbledCircuits::bin_modulo_reduction(
                    &mut garbler,
                    x_.garbler_wires.wires(),
                    b,
                )
                .unwrap();

                let output = garbler.output_all_parties(&circuit_output.0).unwrap();
                let add = GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap();
                tx.send(add)
            });
        }

        // The evaluator (ID0)
        std::thread::spawn(move || {
            let _state = Rep3State::new(&net1, A2BType::default()).unwrap(); // DONT REMOVE
            let mut evaluator = Rep3Evaluator::new(&net1);
            let n_bits = ark_bn254::Fr::MODULUS_BIT_SIZE as usize;

            // This is without OT, just a simulation
            evaluator.receive_circuit().unwrap();
            let x_ = evaluator.receive_bundle_from_circuit(n_bits).unwrap();

            let circuit_output =
                GarbledCircuits::bin_modulo_reduction(&mut evaluator, x_.wires(), b).unwrap();

            let output = evaluator.output_all_parties(&circuit_output.0).unwrap();
            let add = GCUtils::bits_to_field::<ark_bn254::Fr>(&output).unwrap();
            tx1.send(add)
        });

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        assert_eq!(result1, should_result);
        assert_eq!(result2, should_result);
        assert_eq!(result3, should_result);
    }

    #[test]
    fn test_rep3_mod_red() {
        const TEST_RUN: usize = 10;
        for _ in 0..TEST_RUN {
            let mut rng = thread_rng();
            let a: u64 = rng.gen();
            let b: u64 = rng.gen::<u64>() & ((1u64 << 32) - 1);
            rep3_mod_red(a, b);
        }
    }

    fn rep3_slicing_using_arbitrary_base(
        a: ark_bn254::Fr,
        modulus: u64,
        num_decomps_per_field: usize,
    ) {
        let nets = LocalNetwork::new_3_parties();
        let bases = vec![modulus; num_decomps_per_field];
        fn slice_input_using_variable_bases(input: BigUint, bases: &[u64]) -> Vec<ark_bn254::Fr> {
            let mut target = input;
            let mut slices = Vec::with_capacity(bases.len());
            for i in 0..bases.len() {
                if target >= bases[i].into() && i == bases.len() - 1 {
                    panic!("Last key slice greater than {}", bases[i]);
                }
                slices.push(ark_bn254::Fr::from(&target % bases[i]));
                target /= bases[i];
            }
            slices
        }
        let should_result = slice_input_using_variable_bases(BigUint::from(a), &bases);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        let [net1, net2, net3] = nets;

        // Both Garblers
        for (net, tx) in izip!([net2, net3], [tx2, tx3]) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mut garbler = Rep3Garbler::new(&net, &mut state);
                let x_ = garbler.encode_field(a);

                // This is without OT, just a simulation
                garbler.add_bundle_to_circuit(&x_.evaluator_wires);

                let circuit_output = GarbledCircuits::bin_slicing_using_arbitrary_base(
                    &mut garbler,
                    x_.garbler_wires.wires(),
                    modulus,
                    num_decomps_per_field,
                )
                .unwrap();
                let circuit_output: Vec<_> = circuit_output.into_iter().flatten().collect();
                let output = garbler.output_all_parties(&circuit_output).unwrap();

                let mut add = Vec::new();
                for out in output.chunks(output.len() / num_decomps_per_field) {
                    add.push(GCUtils::bits_to_field::<ark_bn254::Fr>(out).unwrap());
                }
                tx.send(add)
            });
        }

        // The evaluator (ID0)
        std::thread::spawn(move || {
            let _state = Rep3State::new(&net1, A2BType::default()).unwrap(); // DONT REMOVE
            let mut evaluator = Rep3Evaluator::new(&net1);
            let n_bits = ark_bn254::Fr::MODULUS_BIT_SIZE as usize;

            // This is without OT, just a simulation
            evaluator.receive_circuit().unwrap();
            let x_ = evaluator.receive_bundle_from_circuit(n_bits).unwrap();

            let circuit_output = GarbledCircuits::bin_slicing_using_arbitrary_base(
                &mut evaluator,
                x_.wires(),
                modulus,
                num_decomps_per_field,
            )
            .unwrap();

            let circuit_output: Vec<_> = circuit_output.into_iter().flatten().collect();
            let output = evaluator.output_all_parties(&circuit_output).unwrap();

            let mut add = Vec::new();
            for out in output.chunks(output.len() / num_decomps_per_field) {
                add.push(GCUtils::bits_to_field::<ark_bn254::Fr>(out).unwrap());
            }
            tx1.send(add)
        });

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        assert_eq!(result1, should_result);
        assert_eq!(result2, should_result);
        assert_eq!(result3, should_result);
    }

    #[test]
    fn test_rep3_slicing_using_arbitrary_base() {
        const TEST_RUN: usize = 1;
        for _ in 0..TEST_RUN {
            const TOTAL_BIT_SIZE: usize = 128;
            let mask: BigUint = (BigUint::one() << TOTAL_BIT_SIZE) - BigUint::one();
            let mut rng = thread_rng();
            let a = ark_bn254::Fr::from(BigUint::from(ark_bn254::Fr::rand(&mut rng)) & &mask);
            let base: u64 = 16u64.pow(3);
            let num_decomps_per_field = 16;
            rep3_slicing_using_arbitrary_base(a, base, num_decomps_per_field);
        }
    }

    #[test]
    fn rep3_int_div_power_2_via_yao() {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let divisor_bit: usize =
            rng.gen_range(0..=ark_bn254::Fr::MODULUS_BIT_SIZE.try_into().unwrap());

        let mut should_result = Vec::with_capacity(VEC_SIZE);
        for x in x.into_iter() {
            let mut x: BigUint = x.into();
            x >>= divisor_bit;
            should_result.push(ark_bn254::Fr::from(x));
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed =
                    yao::field_int_div_power_2_many(&x, &net, &mut state, divisor_bit).unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_int_div_via_yao() {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let y = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let y_shares = rep3::share_field_elements(&y, &mut rng);

        let mut should_result = Vec::with_capacity(VEC_SIZE);
        for (x, y) in x.into_iter().zip(y.into_iter()) {
            let x: BigUint = x.into();
            let y: BigUint = y.into();

            should_result.push(ark_bn254::Fr::from(x / y));
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed = yao::field_int_div_many(&x, &y, &net, &mut state).unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_int_div_by_public_via_yao() {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let y = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let mut should_result = Vec::with_capacity(VEC_SIZE);
        for (x, y) in x.into_iter().zip(y.iter().cloned()) {
            let x: BigUint = x.into();
            let y: BigUint = y.into();

            should_result.push(ark_bn254::Fr::from(x / y));
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter(),) {
            let y_ = y.to_owned();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let decomposed =
                    yao::field_int_div_by_public_many(&x, &y_, &net, &mut state).unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_int_div_by_shared_via_yao() {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let y = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let y_shares = rep3::share_field_elements(&y, &mut rng);

        let mut should_result = Vec::with_capacity(VEC_SIZE);
        for (x, y) in x.iter().cloned().zip(y.into_iter()) {
            let x: BigUint = x.into();
            let y: BigUint = y.into();

            should_result.push(ark_bn254::Fr::from(x / y));
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, y_c) in izip!(nets.into_iter(), [tx1, tx2, tx3], y_shares.into_iter(),) {
            let x_ = x.to_owned();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let div = yao::field_int_div_by_shared_many(&x_, &y_c, &net, &mut state).unwrap();
                tx.send(div)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    fn reshare_from_2_to_3_parties_test_internal(recipient: PartyID) {
        const VEC_SIZE: usize = 10;
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let decomposed = arithmetic::reshare_from_2_to_3_parties(
                    Some(x),
                    VEC_SIZE,
                    recipient,
                    &net,
                    &mut state,
                )
                .unwrap();
                tx.send(decomposed)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn reshare_from_2_to_3_parties_test() {
        reshare_from_2_to_3_parties_test_internal(PartyID::ID0);
        reshare_from_2_to_3_parties_test_internal(PartyID::ID1);
        reshare_from_2_to_3_parties_test_internal(PartyID::ID2);
    }

    #[test]
    fn rep3_poseidon2_gadget_kat1() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let input = [
            ark_bn254::Fr::from(0),
            ark_bn254::Fr::from(1),
            ark_bn254::Fr::from(2),
            ark_bn254::Fr::from(3),
        ];

        let input_shares = rep3::share_field_elements(&input, &mut rng);

        let expected = [
            mpc_core::gadgets::field_from_hex_string(
                "0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a",
            )
            .unwrap(),
        ];

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], input_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let poseidon = Poseidon2::<_, 4, 5>::default();
                let output = poseidon
                    .rep3_permutation(x.as_slice().try_into().unwrap(), &net, &mut state)
                    .unwrap();
                tx.send(output)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);

        assert_eq!(is_result, expected);
    }

    #[test]
    fn rep3_poseidon2_gadget_kat1_precomp() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let input = [
            ark_bn254::Fr::from(0),
            ark_bn254::Fr::from(1),
            ark_bn254::Fr::from(2),
            ark_bn254::Fr::from(3),
        ];

        let input_shares = rep3::share_field_elements(&input, &mut rng);

        let expected = [
            mpc_core::gadgets::field_from_hex_string(
                "0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a",
            )
            .unwrap(),
        ];

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], input_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let poseidon = Poseidon2::<_, 4, 5>::default();
                let mut precomp = poseidon.precompute_rep3(1, &net, &mut state).unwrap();
                let output = poseidon
                    .rep3_permutation_with_precomputation(
                        x.as_slice().try_into().unwrap(),
                        &mut precomp,
                        &net,
                    )
                    .unwrap();
                tx.send(output)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);

        assert_eq!(is_result, expected);
    }

    #[test]
    fn rep3_poseidon2_gadget_kat1_precomp_packed() {
        const NUM_POSEIDON: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let mut input = vec![ark_bn254::Fr::default(); NUM_POSEIDON * 4];
        for input in input.chunks_exact_mut(4) {
            input[0] = ark_bn254::Fr::from(0);
            input[1] = ark_bn254::Fr::from(1);
            input[2] = ark_bn254::Fr::from(2);
            input[3] = ark_bn254::Fr::from(3);
        }

        let input_shares = rep3::share_field_elements(&input, &mut rng);

        let expected = [
            mpc_core::gadgets::field_from_hex_string(
                "0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a",
            )
            .unwrap(),
        ];

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], input_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let poseidon = Poseidon2::<_, 4, 5>::default();
                let mut precomp = poseidon
                    .precompute_rep3(NUM_POSEIDON, &net, &mut state)
                    .unwrap();
                let output = poseidon
                    .rep3_permutation_with_precomputation_packed(&x, &mut precomp, &net)
                    .unwrap();
                tx.send(output)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);

        for r in is_result.chunks_exact(4) {
            assert_eq!(r, expected);
        }
    }

    #[test]
    fn rep3_poseidon2_gadget_kat1_precomp_additive() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let input = [
            ark_bn254::Fr::from(0),
            ark_bn254::Fr::from(1),
            ark_bn254::Fr::from(2),
            ark_bn254::Fr::from(3),
        ];

        let input_shares = rep3::share_field_elements(&input, &mut rng);

        let expected = [
            mpc_core::gadgets::field_from_hex_string(
                "0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb",
            )
            .unwrap(),
            mpc_core::gadgets::field_from_hex_string(
                "0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a",
            )
            .unwrap(),
        ];

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], input_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let poseidon = Poseidon2::<_, 4, 5>::default();
                let mut precomp = poseidon
                    .precompute_rep3_additive(1, &net, &mut state)
                    .unwrap();
                let output = poseidon
                    .rep3_permutation_additive_with_precomputation(
                        x.as_slice().try_into().unwrap(),
                        &mut precomp,
                        &net,
                        &mut state,
                    )
                    .unwrap();
                tx.send(output)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);

        assert_eq!(is_result, expected);
    }

    #[test]
    fn rep3_poseidon2_merkle_tree() {
        const NUM_LEAVES: usize = 4usize.pow(3);

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let input = (0..NUM_LEAVES)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();

        let input_shares = rep3::share_field_elements(&input, &mut rng);

        let poseidon2 = Poseidon2::<ark_bn254::Fr, 4, 5>::default();
        let expected1 = poseidon2.merkle_tree_sponge::<2>(input.clone());
        let expected2 = poseidon2.merkle_tree_compression::<4>(input);
        let expected = [expected1, expected2];

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], input_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let poseidon = Poseidon2::<_, 4, 5>::default();
                let output1 = poseidon
                    .merkle_tree_sponge_rep3::<2, _>(x.clone(), &net, &mut state)
                    .unwrap();
                let output2 = poseidon
                    .merkle_tree_compression_rep3::<4, _>(x, &net, &mut state)
                    .unwrap();
                let output = [output1, output2];
                tx.send(output)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);

        assert_eq!(is_result, expected);
    }

    #[test]
    fn rep3_field_mod_pow2() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let bit = rng.gen_range(1..ark_bn254::Fr::MODULUS_BIT_SIZE);
        let y = ark_bn254::Fr::from(BigUint::one() << bit);
        let x_shares = rep3::share_field_element(x.to_owned(), &mut rng);

        let should_result = ark_bn254::Fr::from(BigUint::from(x) % BigUint::from(y));

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x_) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares) {
            let y_c = y.to_owned();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let divisor: BigUint = y_c.into();
                assert_eq!(divisor.count_ones(), 1);
                let divisor_bit = divisor.bits() as usize - 1;
                let res = yao::field_mod_power_2(x_, &net, &mut state, divisor_bit).unwrap();
                tx.send(res)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_blake2s() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        const INPUT_SIZE: usize = 64;
        let input: Vec<u8> = (0..INPUT_SIZE).map(|_| rng.gen()).collect();
        let num_bits = vec![8; INPUT_SIZE];

        let x = input.iter().map(|&x| ark_bn254::Fr::from(x)).collect_vec();

        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let mut real_input = Vec::new();
        for (inp, num_bits) in x.into_iter().zip(num_bits.iter()) {
            let num_elements = (*num_bits as u32).div_ceil(8);
            let bytes = inp.into_bigint().to_bytes_le();
            real_input.extend(bytes[0..num_elements as usize].to_vec());
        }
        let output_bytes: [u8; 32] = Blake2s256::digest(real_input).into();
        let should_result: Vec<_> = output_bytes.into_iter().map(ark_bn254::Fr::from).collect();

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter(),) {
            let num_bits = num_bits.to_owned();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let res = rep3::yao::blake2s(&x, &net, &mut state, &num_bits).unwrap();
                tx.send(res)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_blake3() {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        const INPUT_SIZE: usize = 64;
        let input: Vec<u8> = (0..INPUT_SIZE).map(|_| rng.gen()).collect();
        let num_bits = vec![8; INPUT_SIZE];

        let x = input.iter().map(|&x| ark_bn254::Fr::from(x)).collect_vec();

        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let mut real_input = Vec::new();
        for (inp, num_bits) in x.into_iter().zip(num_bits.iter()) {
            let num_elements = (*num_bits as u32).div_ceil(8);
            let bytes = inp.into_bigint().to_bytes_le();
            real_input.extend(bytes[0..num_elements as usize].to_vec());
        }
        let output_bytes: [u8; 32] = blake3::hash(&real_input).into();
        let should_result: Vec<_> = output_bytes.into_iter().map(ark_bn254::Fr::from).collect();

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], x_shares.into_iter(),) {
            let num_bits = num_bits.to_owned();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let res = rep3::yao::blake3(&x, &net, &mut state, &num_bits).unwrap();
                tx.send(res)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }
}

mod curve_share {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{One, PrimeField, Zero};
    use ark_std::UniformRand;
    use itertools::{izip, Itertools};
    use mpc_core::protocols::rep3::{
        self,
        conversion::{self, A2BType},
        pointshare, Rep3BigUintShare, Rep3State,
    };
    use mpc_net::local::LocalNetwork;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use std::sync::mpsc;

    #[test]
    fn rep3_add() {
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let y = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rep3::share_curve_point(x, &mut rng);
        let y_shares = rep3::share_curve_point(y, &mut rng);
        let should_result = x + y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (tx, x, y) in izip!([tx1, tx2, tx3], x_shares.into_iter(), y_shares.into_iter()) {
            std::thread::spawn(move || tx.send(pointshare::add(&x, &y)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub() {
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let y = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rep3::share_curve_point(x, &mut rng);
        let y_shares = rep3::share_curve_point(y, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (tx, x, y) in izip!([tx1, tx2, tx3], x_shares.into_iter(), y_shares.into_iter()) {
            std::thread::spawn(move || tx.send(pointshare::sub(&x, &y)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_scalar_mul_public_point() {
        let mut rng = thread_rng();
        let public_point = ark_bn254::G1Projective::rand(&mut rng);
        let scalar = ark_bn254::Fr::rand(&mut rng);
        let scalar_shares = rep3::share_field_element(scalar, &mut rng);
        let should_result = public_point * scalar;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (tx, scalar) in izip!([tx1, tx2, tx3], scalar_shares,) {
            std::thread::spawn(move || {
                tx.send(pointshare::scalar_mul_public_point(&public_point, scalar))
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_scalar_mul_public_scalar() {
        let mut rng = thread_rng();
        let point = ark_bn254::G1Projective::rand(&mut rng);
        let public_scalar = ark_bn254::Fr::rand(&mut rng);
        let point_shares = rep3::share_curve_point(point, &mut rng);
        let should_result = point * public_scalar;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (tx, point) in izip!([tx1, tx2, tx3], point_shares) {
            std::thread::spawn(move || {
                tx.send(pointshare::scalar_mul_public_scalar(&point, public_scalar))
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_a2b_many_single() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        let nets = LocalNetwork::new_3_parties();

        for (tx, x, net) in izip!([tx1, tx2, tx3], x_shares.into_iter(), nets) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let single = conversion::a2b(x, &net, &mut state).unwrap();
                let many = conversion::a2b_many(&[x], &net, &mut state).unwrap();
                tx.send((single, many))
            });
        }
        let (single1, many1) = rx1.recv().unwrap();
        let (single2, many2) = rx2.recv().unwrap();
        let (single3, many3) = rx3.recv().unwrap();
        let result_single = rep3::combine_binary_element(single1, single2, single3);
        let result_many =
            rep3::combine_binary_element(many1[0].clone(), many2[0].clone(), many3[0].clone());
        assert_eq!(result_many, x.into());
        assert_eq!(result_many, result_single);
    }

    #[test]
    fn rep3_a2b_many() {
        let mut rng = thread_rng();
        let batch_size = 10;
        let should_batch = (0..batch_size)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let batch_shares = rep3::share_field_elements(&should_batch, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        let nets = LocalNetwork::new_3_parties();

        for (tx, x, net) in izip!([tx1, tx2, tx3], batch_shares.into_iter(), nets) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let single = x
                    .iter()
                    .map(|x| conversion::a2b(*x, &net, &mut state).unwrap())
                    .collect_vec();
                let single_many = conversion::a2b_many(&x, &net, &mut state).unwrap();
                tx.send((single, single_many))
            });
        }
        let (single1, many1) = rx1.recv().unwrap();
        let (single2, many2) = rx2.recv().unwrap();
        let (single3, many3) = rx3.recv().unwrap();
        let single_batch = izip!(single1, single2, single3)
            .map(|(single1, single2, single3)| {
                rep3::combine_binary_element(single1, single2, single3)
            })
            .collect_vec();
        let many_batch = izip!(many1, many2, many3)
            .map(|(many1, many2, many3)| rep3::combine_binary_element(many1, many2, many3))
            .collect_vec();
        assert_eq!(single_batch, many_batch);
        assert_eq!(
            many_batch,
            should_batch.into_iter().map(BigUint::from).collect_vec()
        );
    }

    fn to_fieldshares<C: CurveGroup>(point: C)
    where
        C::BaseField: PrimeField,
    {
        let mut rng = thread_rng();
        let point_shares = rep3::share_curve_point(point, &mut rng);

        let nets = LocalNetwork::new_3_parties();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        let (should_result_x, should_result_y) = point.into_affine().xy().unwrap_or_default();

        for (net, tx, point) in izip!(nets.into_iter(), [tx1, tx2, tx3], point_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::point_share_to_fieldshares(point, &net, &mut state).unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result_x = rep3::combine_field_element(result1.0, result2.0, result3.0);
        let is_result_y = rep3::combine_field_element(result1.1, result2.1, result3.1);
        let is_result_is_zero = rep3::combine_field_element(result1.2, result2.2, result3.2);

        assert!(is_result_is_zero <= C::BaseField::one());
        if is_result_is_zero.is_zero() {
            assert_eq!(is_result_x, should_result_x, "x");
            assert_eq!(is_result_y, should_result_y, "y");
        } else {
            assert!(point.is_zero(), "is_zero");
        }
    }

    fn to_fieldshares_many<C: CurveGroup>(points: &[C])
    where
        C::BaseField: PrimeField,
    {
        let mut rng = thread_rng();
        let point_shares = rep3::share_curve_points(points, &mut rng);

        let nets = LocalNetwork::new_3_parties();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        let (should_result_xs, should_result_ys) = points
            .iter()
            .map(|p| p.into_affine().xy().unwrap_or_default())
            .unzip::<_, _, Vec<_>, Vec<_>>();

        for (net, tx, point) in izip!(nets.into_iter(), [tx1, tx2, tx3], point_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(
                    conversion::point_share_to_fieldshares_many(&point, &net, &mut state).unwrap(),
                )
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result_x = rep3::combine_field_elements(&result1.0, &result2.0, &result3.0);
        let is_result_y = rep3::combine_field_elements(&result1.1, &result2.1, &result3.1);
        let is_result_is_zero = rep3::combine_field_elements(&result1.2, &result2.2, &result3.2);

        for (is_res_x, is_res_y, is_res_inf, should_x, should_y, point) in izip!(
            is_result_x,
            is_result_y,
            is_result_is_zero,
            should_result_xs,
            should_result_ys,
            points
        ) {
            assert!(is_res_inf <= C::BaseField::one());
            if is_res_inf.is_zero() {
                assert_eq!(is_res_x, should_x, "x");
                assert_eq!(is_res_y, should_y, "y");
            } else {
                assert!(point.is_zero(), "is_zero");
            }
        }
    }

    #[test]
    fn bn254_to_fieldshares() {
        for _ in 0..10 {
            to_fieldshares(ark_bn254::G1Projective::zero());
            to_fieldshares(ark_bn254::G1Projective::rand(&mut thread_rng()));
        }
    }

    #[test]
    fn grumpkin_to_fieldshares() {
        for _ in 0..10 {
            to_fieldshares(ark_grumpkin::Projective::zero());
            to_fieldshares(ark_grumpkin::Projective::rand(&mut thread_rng()));
        }
    }

    #[test]
    fn bn254_to_fieldshares_many() {
        const VEC_SIZE: usize = 10;
        const RUNS: usize = 10;
        for _ in 0..RUNS {
            let mut rng = thread_rng();
            let points = (0..VEC_SIZE)
                .map(|_| ark_bn254::G1Projective::rand(&mut rng))
                .collect_vec();
            to_fieldshares_many(&points);
        }
        for _ in 0..RUNS {
            let points = (0..VEC_SIZE)
                .map(|_| ark_bn254::G1Projective::zero())
                .collect_vec();
            to_fieldshares_many(&points);
        }
    }

    #[test]
    fn grumpkin_to_fieldshares_many() {
        const VEC_SIZE: usize = 10;
        const RUNS: usize = 10;
        for _ in 0..RUNS {
            let mut rng = thread_rng();
            let points = (0..VEC_SIZE)
                .map(|_| ark_grumpkin::Projective::rand(&mut rng))
                .collect_vec();
            to_fieldshares_many(&points);
        }
        for _ in 0..RUNS {
            let points = (0..VEC_SIZE)
                .map(|_| ark_grumpkin::Projective::zero())
                .collect_vec();
            to_fieldshares_many(&points);
        }
    }

    fn from_fieldshares<C: CurveGroup>(point: C)
    where
        C::BaseField: PrimeField,
    {
        let mut rng = thread_rng();
        let (x, y) = point.into_affine().xy().unwrap_or_default();
        let x_shares = rep3::share_field_element(x, &mut rng);
        let y_shares = rep3::share_field_element(y, &mut rng);
        let is_infinity = if point.is_zero() {
            rep3::share_field_element(C::BaseField::one(), &mut rng)
        } else {
            rep3::share_field_element(C::BaseField::zero(), &mut rng)
        };

        let nets = LocalNetwork::new_3_parties();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y, is_inf) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter(),
            is_infinity.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(
                    conversion::fieldshares_to_pointshare(x, y, is_inf, &net, &mut state).unwrap(),
                )
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result: C = rep3::combine_curve_point(result1, result2, result3);

        assert_eq!(is_result, point);
    }

    fn from_fieldshares_many<C: CurveGroup>(points: &[C])
    where
        C::BaseField: PrimeField,
    {
        let mut rng = thread_rng();
        let coords: Vec<_> = points
            .iter()
            .map(|c| c.into_affine().xy().unwrap_or_default())
            .collect_vec();
        let (x, y): (Vec<_>, Vec<_>) = coords.into_iter().unzip();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let y_shares = rep3::share_field_elements(&y, &mut rng);
        let is_infinity = points
            .iter()
            .map(|p| {
                if p.is_zero() {
                    C::BaseField::one()
                } else {
                    C::BaseField::zero()
                }
            })
            .collect_vec();
        let is_infinity = rep3::share_field_elements(&is_infinity, &mut rng);

        let nets = LocalNetwork::new_3_parties();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y, is_inf) in izip!(
            nets.into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter(),
            is_infinity.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(
                    conversion::fieldshares_to_pointshare_many(&x, &y, &is_inf, &net, &mut state)
                        .unwrap(),
                )
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result: Vec<C> = rep3::combine_curve_points(&result1, &result2, &result3);

        assert_eq!(is_result, points);
    }

    #[test]
    fn bn254_from_fieldshares() {
        for _ in 0..10 {
            from_fieldshares(ark_bn254::G1Projective::zero());
            from_fieldshares(ark_bn254::G1Projective::rand(&mut thread_rng()));
        }
    }

    #[test]
    fn grumpkin_from_fieldshares() {
        for _ in 0..10 {
            from_fieldshares(ark_grumpkin::Projective::zero());
            from_fieldshares(ark_grumpkin::Projective::rand(&mut thread_rng()));
        }
    }

    #[test]
    fn bn254_from_fieldshares_many() {
        for _ in 0..10 {
            let mut rng = thread_rng();
            let points = (0..10)
                .map(|_| ark_bn254::G1Projective::rand(&mut rng))
                .collect_vec();
            from_fieldshares_many(&points);
        }
    }
    #[test]
    fn grumpkin_from_fieldshares_many() {
        for _ in 0..10 {
            let mut rng = thread_rng();
            let points = (0..10)
                .map(|_| ark_grumpkin::Projective::rand(&mut rng))
                .collect_vec();
            from_fieldshares_many(&points);
        }
    }

    fn point_is_zero<C: CurveGroup>(point: C)
    where
        C::BaseField: PrimeField,
    {
        let mut rng = thread_rng();
        let shares = rep3::share_curve_point(point, &mut rng);

        let nets = LocalNetwork::new_3_parties();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let res = pointshare::is_zero(x, &net, &mut state).unwrap();
                let res = Rep3BigUintShare::<C::ScalarField>::new(
                    BigUint::from(res.0),
                    BigUint::from(res.1),
                );
                tx.send(res)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_binary_element(result1, result2, result3);
        assert!(is_result <= BigUint::one());
        if point.is_zero() {
            assert_eq!(is_result, BigUint::one());
        } else {
            assert_eq!(is_result, BigUint::zero());
        }
    }

    fn point_is_zero_many<C: CurveGroup>(points: &[C])
    where
        C::BaseField: PrimeField,
    {
        let mut rng = thread_rng();
        let mut shares: [Vec<_>; 3] = [
            Vec::with_capacity(points.len()),
            Vec::with_capacity(points.len()),
            Vec::with_capacity(points.len()),
        ];
        for p in points {
            let s = rep3::share_curve_point(*p, &mut rng);
            shares[0].push(s[0]);
            shares[1].push(s[1]);
            shares[2].push(s[2]);
        }

        let nets = LocalNetwork::new_3_parties();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets.into_iter(), [tx1, tx2, tx3], shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let res = pointshare::is_zero_many(&x, &net, &mut state).unwrap();
                let mut res_ = Vec::with_capacity(res.len());
                for r in res {
                    res_.push(Rep3BigUintShare::<C::ScalarField>::new(
                        BigUint::from(r.0),
                        BigUint::from(r.1),
                    ));
                }
                tx.send(res_)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let mut is_results = Vec::with_capacity(result1.len());
        for i in 0..result1.len() {
            is_results.push(rep3::combine_binary_element(
                result1[i].clone(),
                result2[i].clone(),
                result3[i].clone(),
            ));
        }
        for (point, is_result) in points.iter().zip(is_results.iter()) {
            assert!(is_result <= &BigUint::one());
            if point.is_zero() {
                assert_eq!(*is_result, BigUint::one());
            } else {
                assert_eq!(*is_result, BigUint::zero());
            }
        }
    }

    #[test]
    fn bn254_point_is_zero() {
        for _ in 0..10 {
            point_is_zero(ark_bn254::G1Projective::zero());
            point_is_zero(ark_bn254::G1Projective::rand(&mut thread_rng()));
        }
    }
    #[test]
    fn bn254_point_is_zero_many() {
        for _ in 0..10 {
            let mut rng = thread_rng();
            let points = (0..10)
                .map(|_| ark_bn254::G1Projective::rand(&mut rng))
                .chain(std::iter::once(ark_bn254::G1Projective::zero()))
                .collect_vec();
            point_is_zero_many(&points);

            let zero_points = vec![ark_bn254::G1Projective::zero(); 10];
            point_is_zero_many(&zero_points);
        }
    }

    #[test]
    fn grumpkin_point_is_zero() {
        for _ in 0..10 {
            point_is_zero(ark_grumpkin::Projective::zero());
            point_is_zero(ark_grumpkin::Projective::rand(&mut thread_rng()));
        }
    }
    #[test]
    fn grumpkin_point_is_zero_many() {
        for _ in 0..10 {
            let mut rng = thread_rng();
            let points = (0..10)
                .map(|_| ark_grumpkin::Projective::rand(&mut rng))
                .chain(std::iter::once(ark_grumpkin::Projective::zero()))
                .collect_vec();
            point_is_zero_many(&points);

            let zero_points = vec![ark_grumpkin::Projective::zero(); 10];
            point_is_zero_many(&zero_points);
        }
    }
}
