mod field_share {
    use ark_ff::Field;
    use ark_ff::One;
    use ark_ff::PrimeField;
    use ark_std::{UniformRand, Zero};
    use itertools::izip;
    use itertools::Itertools;
    use mpc_core::gadgets::poseidon2::Poseidon2;
    use mpc_core::protocols::rep3::conversion;
    use mpc_core::protocols::rep3::gadgets;
    use mpc_core::protocols::rep3::id::PartyID;
    use mpc_core::protocols::rep3::yao;
    use mpc_core::protocols::rep3::yao::circuits::GarbledCircuits;
    use mpc_core::protocols::rep3::yao::evaluator::Rep3Evaluator;
    use mpc_core::protocols::rep3::yao::garbler::Rep3Garbler;
    use mpc_core::protocols::rep3::yao::streaming_evaluator::StreamingRep3Evaluator;
    use mpc_core::protocols::rep3::yao::streaming_garbler::StreamingRep3Garbler;
    use mpc_core::protocols::rep3::yao::GCUtils;
    use mpc_core::protocols::rep3::{self, arithmetic, network::IoContext};
    use mpc_core::protocols::rep3_ring;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use rand::Rng;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::thread;
    use tests::rep3_network::Rep3TestNetwork;

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
            thread::spawn(move || tx.send(arithmetic::add(x, y)));
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
            thread::spawn(move || tx.send(arithmetic::sub(x, y)));
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
            thread::spawn(move || tx.send(arithmetic::sub_shared_by_public(x, y, id)));
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
            thread::spawn(move || tx.send(arithmetic::sub_public_by_shared(x, y, id)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul() {
        let test_network = Rep3TestNetwork::default();
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
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();
                let mul = arithmetic::mul(x, y, &mut ctx).unwrap();
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
        let test_network = Rep3TestNetwork::default();
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
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();
                let mul = arithmetic::div(x, y, &mut ctx).unwrap();
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
        let mut threads = vec![];
        for (net, (x0, y0), (x1, y1)) in izip!(
            test_network.get_party_networks().into_iter(),
            x_shares0.into_iter().zip(y_shares0),
            x_shares1.into_iter().zip(y_shares1)
        ) {
            threads.push(thread::spawn(move || {
                let mut ctx0 = IoContext::init(net).unwrap();
                let mut ctx1 = ctx0.fork().unwrap();
                std::thread::scope(|s| {
                    let mul0 = s.spawn(|| arithmetic::mul(x0, y0, &mut ctx0));
                    let mul1 = arithmetic::mul(x1, y1, &mut ctx1).unwrap();
                    (mul0.join().expect("can join").unwrap(), mul1)
                })
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
        let test_network = Rep3TestNetwork::default();
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
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let mul = arithmetic::mul(x, y, &mut rep3).unwrap();
                let mul = arithmetic::mul(mul, y, &mut rep3).unwrap();
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

        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let y_shares = rep3::share_field_elements(&y, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x, y) in izip!(
            test_network.get_party_networks(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let mul = arithmetic::mul_vec(&x, &y, &mut rep3).unwrap();
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
        let test_network = Rep3TestNetwork::default();
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
            test_network.get_party_networks(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let mul = arithmetic::mul_vec(&x, &y, &mut rep3).unwrap();
                let mul = arithmetic::mul_vec(&mul, &y, &mut rep3).unwrap();
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
            thread::spawn(move || tx.send(arithmetic::neg(x)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_inv() {
        let test_network = Rep3TestNetwork::default();
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
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(arithmetic::inv(x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x_ = ark_bn254::Fr::rand(&mut rng);
        let x = x_.square(); // Guarantees a square root exists
        let x_shares = rep3::share_field_element(x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(test_network.get_party_networks(), [tx1, tx2, tx3], x_shares,) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(arithmetic::sqrt(x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
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
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::bit_inject(&x, &mut rep3).unwrap())
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

        let test_network = Rep3TestNetwork::default();
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
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip([x0_shares, x1_shares, x2_shares].into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::bit_inject_many(&x, &mut rep3).unwrap())
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
                        let test_network = Rep3TestNetwork::default();
                        let mut rng = thread_rng();
                        let x_shares = rep3::share_field_element(constant_number, &mut rng);
                        let y_shares = rep3::share_field_element(compare, &mut rng);
                        let should_result = ark_bn254::Fr::from(constant_number $op compare);
                        let (tx1, rx1) = mpsc::channel();
                        let (tx2, rx2) = mpsc::channel();
                        let (tx3, rx3) = mpsc::channel();
                        for (net, tx, x, y, public) in izip!(
                            test_network.get_party_networks(),
                            [tx1, tx2, tx3],
                            x_shares,
                            y_shares,
                            vec![compare; 3]
                        ) {
            thread::spawn(move || {
                                let mut rep3 = IoContext::init(net).unwrap();
                                let shared_compare = arithmetic::$name(x, y, &mut rep3).unwrap();
                                let rhs_const =[< $name _public >](x, public, &mut rep3).unwrap();
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
    fn rep3_a2b_zero() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::zero();
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::a2b(x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::zero();
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::a2y2b(x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::zero();
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::a2y2b_streaming(x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::a2b(x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::a2y2b(x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::a2y2b_streaming(x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::b2a(&x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::b2y2a(&x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                tx.send(conversion::b2y2a_streaming(&x, &mut rep3).unwrap())
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let should_result = x + y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        let [net1, net2, net3] = test_network.get_party_networks();

        // Both Garblers
        for (net, tx) in izip!([net2, net3], [tx2, tx3]) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();

                let mut garbler = Rep3Garbler::new(&mut ctx);
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
                tx.send(add)
            });
        }

        // The evaluator (ID0)
        thread::spawn(move || {
            let mut ctx = IoContext::init(net1).unwrap();

            let mut evaluator = Rep3Evaluator::new(&mut ctx);
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
    fn rep3_gc_streaming() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let should_result = x + y;
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        let [net1, net2, net3] = test_network.get_party_networks();

        // Both Garblers
        for (net, tx) in izip!([net2, net3], [tx2, tx3]) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();

                let mut garbler = StreamingRep3Garbler::new(&mut ctx);
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
        thread::spawn(move || {
            let mut ctx = IoContext::init(net1).unwrap();

            let mut evaluator = StreamingRep3Evaluator::new(&mut ctx);
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let id = rep3.network.id;
                let delta = rep3.rngs.generate_random_garbler_delta(id);

                let converted = conversion::a2y(x, delta, &mut rep3).unwrap();

                let output = match id {
                    PartyID::ID0 => {
                        let mut evaluator = Rep3Evaluator::new(&mut rep3);
                        evaluator.receive_circuit().unwrap();
                        evaluator.output_all_parties(converted.wires()).unwrap()
                    }
                    PartyID::ID1 | PartyID::ID2 => {
                        let mut garbler = Rep3Garbler::new_with_delta(&mut rep3, delta.unwrap());
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let id = rep3.network.id;
                let delta = rep3.rngs.generate_random_garbler_delta(id);

                let converted = conversion::a2y_streaming(x, delta, &mut rep3).unwrap();

                let output = match id {
                    PartyID::ID0 => {
                        let mut evaluator = StreamingRep3Evaluator::new(&mut rep3);
                        evaluator.output_all_parties(converted.wires()).unwrap()
                    }
                    PartyID::ID1 | PartyID::ID2 => {
                        let mut garbler =
                            StreamingRep3Garbler::new_with_delta(&mut rep3, delta.unwrap());
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
        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let converted =
                    conversion::y2a::<ark_bn254::Fr, _>(x, Some(delta), &mut rep3).unwrap();
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
        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let converted =
                    conversion::y2a_streaming::<ark_bn254::Fr, _>(x, Some(delta), &mut rep3)
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let id = rep3.network.id;
                let delta = rep3.rngs.generate_random_garbler_delta(id);

                let converted = conversion::b2y(&x, delta, &mut rep3).unwrap();

                let output = match id {
                    PartyID::ID0 => {
                        let mut evaluator = Rep3Evaluator::new(&mut rep3);
                        evaluator.receive_circuit().unwrap();
                        evaluator.output_all_parties(converted.wires()).unwrap()
                    }
                    PartyID::ID1 | PartyID::ID2 => {
                        let mut garbler = Rep3Garbler::new_with_delta(&mut rep3, delta.unwrap());
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_biguint(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let id = rep3.network.id;
                let delta = rep3.rngs.generate_random_garbler_delta(id);

                let converted = conversion::b2y(&x, delta, &mut rep3).unwrap();

                let output = match id {
                    PartyID::ID0 => {
                        let mut evaluator = StreamingRep3Evaluator::new(&mut rep3);
                        evaluator.output_all_parties(converted.wires()).unwrap()
                    }
                    PartyID::ID1 | PartyID::ID2 => {
                        let mut garbler =
                            StreamingRep3Garbler::new_with_delta(&mut rep3, delta.unwrap());
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
        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let converted = conversion::y2b::<ark_bn254::Fr, _>(x, &mut rep3).unwrap();
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

        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let decomposed =
                    yao::decompose_arithmetic_many(&x, &mut rep3, TOTAL_BIT_SIZE, CHUNK_SIZE)
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

        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let decomposed =
                    yao::slice_arithmetic_many(&x, &mut rep3, msb, lsb, bitsize).unwrap();
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

        let test_network = Rep3TestNetwork::default();
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
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let decomposed =
                    yao::slice_and_many(&x, &y, &mut rep3, BASE_BIT, ROTATION, TOTAL_BIT_SIZE)
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
    fn rep3_slice_and_xor_rotated() {
        const VEC_SIZE: usize = 10;
        const TOTAL_BIT_SIZE: usize = 32;
        const ROTATION: usize = 2;
        const BASE_BIT: usize = 6;
        const BASE: usize = 1 << BASE_BIT;
        const NUM_DECOMPS: usize = TOTAL_BIT_SIZE.div_ceil(BASE_BIT);

        let test_network = Rep3TestNetwork::default();
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
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let decomposed =
                    yao::slice_xor_many(&x, &y, &mut rep3, BASE_BIT, ROTATION, TOTAL_BIT_SIZE)
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

        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let decomposed =
                    gadgets::sort::batcher_odd_even_merge_sort_yao(&x, &mut rep3, CHUNK_SIZE)
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
        const VEC_SIZE: usize = 10;
        const CHUNK_SIZE: usize = 14;

        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let mut forked = rep3.fork().unwrap();

                let decomposed = rep3_ring::gadgets::sort::radix_sort_fields(
                    &x,
                    &mut rep3,
                    &mut forked,
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
    fn rep3_int_div_power_2_via_yao() {
        const VEC_SIZE: usize = 10;

        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let decomposed =
                    yao::field_int_div_power_2_many(&x, &mut rep3, divisor_bit).unwrap();
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

        let test_network = Rep3TestNetwork::default();
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
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let decomposed = yao::field_int_div_many(&x, &y, &mut rep3).unwrap();
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

        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
        ) {
            let y_ = y.to_owned();
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let decomposed = yao::field_int_div_by_public_many(&x, &y_, &mut rep3).unwrap();
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

        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, y_c) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            y_shares.into_iter(),
        ) {
            let x_ = x.to_owned();
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let div = yao::field_int_div_by_shared_many(&x_, &y_c, &mut rep3).unwrap();
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
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();
                let decomposed = arithmetic::reshare_from_2_to_3_parties(
                    Some(x),
                    VEC_SIZE,
                    recipient,
                    &mut rep3,
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
        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            input_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let poseidon = Poseidon2::<_, 4, 5>::default();
                let output = poseidon
                    .rep3_permutation(x.as_slice().try_into().unwrap(), &mut rep3)
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
        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            input_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let poseidon = Poseidon2::<_, 4, 5>::default();
                let output = poseidon
                    .rep3_permutation_with_precomputation(
                        x.as_slice().try_into().unwrap(),
                        &mut rep3,
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
    fn rep3_poseidon2_gadget_kat1_precomp_additive() {
        let test_network = Rep3TestNetwork::default();
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

        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            input_shares.into_iter()
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let poseidon = Poseidon2::<_, 4, 5>::default();
                let output = poseidon
                    .rep3_permutation_additive_with_precomputation(
                        x.as_slice().try_into().unwrap(),
                        &mut rep3,
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
}

mod curve_share {
    use std::{sync::mpsc, thread};

    use ark_std::UniformRand;
    use itertools::izip;

    use mpc_core::protocols::rep3::{self, pointshare};
    use rand::thread_rng;

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
            thread::spawn(move || tx.send(pointshare::add(&x, &y)));
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
            thread::spawn(move || tx.send(pointshare::sub(&x, &y)));
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
            thread::spawn(move || {
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
            thread::spawn(move || {
                tx.send(pointshare::scalar_mul_public_scalar(&point, public_scalar))
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }
}
