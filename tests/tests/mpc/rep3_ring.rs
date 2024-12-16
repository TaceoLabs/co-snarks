mod ring_share {
    use ark_ff::PrimeField;
    use ark_std::UniformRand;
    use itertools::izip;
    use itertools::Itertools;
    use mpc_core::protocols::rep3;
    use mpc_core::protocols::rep3::id::PartyID;
    use mpc_core::protocols::rep3::network::IoContext;
    use mpc_core::protocols::rep3::yao::circuits::GarbledCircuits;
    use mpc_core::protocols::rep3::yao::evaluator::Rep3Evaluator;
    use mpc_core::protocols::rep3::yao::garbler::Rep3Garbler;
    use mpc_core::protocols::rep3::yao::streaming_evaluator::StreamingRep3Evaluator;
    use mpc_core::protocols::rep3::yao::streaming_garbler::StreamingRep3Garbler;
    use mpc_core::protocols::rep3::yao::GCUtils;
    use mpc_core::protocols::rep3_ring;
    use mpc_core::protocols::rep3_ring::arithmetic;
    use mpc_core::protocols::rep3_ring::casts;
    use mpc_core::protocols::rep3_ring::conversion;
    use mpc_core::protocols::rep3_ring::ring::bit::Bit;
    use mpc_core::protocols::rep3_ring::ring::int_ring::IntRing2k;
    use mpc_core::protocols::rep3_ring::ring::ring_impl::RingElement;
    use mpc_core::protocols::rep3_ring::yao;
    use num_bigint::BigUint;
    use num_traits::{AsPrimitive, One, Zero};
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand::thread_rng;
    use rand::Rng;
    use std::sync::mpsc;
    use std::thread;
    use tests::rep3_network::Rep3TestNetwork;

    macro_rules! apply_to_all {
        ($expr:ident,[$($t:ty),*]) => {
            $(
                $expr::<$t>();
            )*
        };
    }

    macro_rules! apply_to_all2 {
        ($expr:ident,[$t1:ty],[$($t2:ty),*]) => {
            $(
                $expr::<$t1,$t2>();
            )*
        };
        ($expr:ident,[$($t1:ty),*],$t2:tt) => {
            $(
                apply_to_all2!($expr,[$t1], $t2);
            )*
        };
    }

    // TODO we dont need channels, we can just join

    fn rep3_add_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
        println!("x {x} y {x}");
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let y_shares = rep3_ring::share_ring_element(y, &mut rng);
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_add() {
        apply_to_all!(rep3_add_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_sub_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let y_shares = rep3_ring::share_ring_element(y, &mut rng);
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub() {
        apply_to_all!(rep3_sub_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_sub_shared_by_public_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub_shared_by_public() {
        apply_to_all!(rep3_sub_shared_by_public_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_sub_public_by_shared_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
        let y_shares = rep3_ring::share_ring_element(y, &mut rng);
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub_public_by_shared() {
        apply_to_all!(rep3_sub_public_by_shared_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_mul_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let y_shares = rep3_ring::share_ring_element(y, &mut rng);
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul() {
        apply_to_all!(rep3_mul_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_fork_mul_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x0 = rng.gen::<RingElement<T>>();
        let x1 = rng.gen::<RingElement<T>>();
        let y0 = rng.gen::<RingElement<T>>();
        let y1 = rng.gen::<RingElement<T>>();
        let x_shares0 = rep3_ring::share_ring_element(x0, &mut rng);
        let x_shares1 = rep3_ring::share_ring_element(x1, &mut rng);
        let y_shares0 = rep3_ring::share_ring_element(y0, &mut rng);
        let y_shares1 = rep3_ring::share_ring_element(y1, &mut rng);
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
        let is_result0 = rep3_ring::combine_ring_element(result1.0, result2.0, result3.0);
        let is_result1 = rep3_ring::combine_ring_element(result1.1, result2.1, result3.1);
        assert_eq!(is_result0, should_result0);
        assert_eq!(is_result1, should_result1);
    }

    #[test]
    fn rep3_fork_mul() {
        apply_to_all!(rep3_fork_mul_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_mul2_then_add_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let y_shares = rep3_ring::share_ring_element(y, &mut rng);
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul2_then_add() {
        apply_to_all!(rep3_mul2_then_add_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_mul_vec_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..1)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect::<Vec<_>>();
        let y = (0..1)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect::<Vec<_>>();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let y_shares = rep3_ring::share_ring_elements(&y, &mut rng);

        let mut should_result = vec![];
        for (x, y) in x.iter().zip(y.iter()) {
            should_result.push((*x * y) * y);
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
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul_vec() {
        apply_to_all!(rep3_mul_vec_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_neg_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_neg() {
        apply_to_all!(rep3_neg_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_bit_inject_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>() & RingElement::one();
        let mut x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);
        // Simulate sharing of just one bit
        for x in x_shares.iter_mut() {
            x.a &= RingElement::one();
            x.b &= RingElement::one();
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_bit_inject() {
        apply_to_all!(rep3_bit_inject_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_bit_inject_many_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let mut should_result = Vec::with_capacity(VEC_SIZE);
        let mut x0_shares = Vec::with_capacity(VEC_SIZE);
        let mut x1_shares = Vec::with_capacity(VEC_SIZE);
        let mut x2_shares = Vec::with_capacity(VEC_SIZE);
        for _ in 0..VEC_SIZE {
            let x = rng.gen::<RingElement<T>>() & RingElement::one();
            should_result.push(x);
            let mut x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);
            // Simulate sharing of just one bit
            for x in x_shares.iter_mut() {
                x.a &= RingElement::one();
                x.b &= RingElement::one();
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
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_bit_inject_many() {
        apply_to_all!(rep3_bit_inject_many_t, [Bit, u8, u16, u32, u64, u128]);
    }

    use arithmetic::ge_public;
    use arithmetic::gt_public;
    use arithmetic::le_public;
    use arithmetic::lt_public;
    macro_rules! bool_op_test {
            ($name: ident, $name_t: ident, $op: tt) => {
                paste::item! {
                     fn $name_t<T: IntRing2k>() where Standard: Distribution<T> {
                        let constant_number: RingElement<T> = RingElement(T::try_from(50u64).unwrap());
                        let compare = constant_number - RingElement::one();
                        for i in 0u64..3 {
                            let compare = compare + RingElement(T::try_from(i).unwrap());
                            let test_network = Rep3TestNetwork::default();
                            let mut rng = thread_rng();
                            let x_shares = rep3_ring::share_ring_element(constant_number, &mut rng);
                            let y_shares = rep3_ring::share_ring_element(compare, &mut rng);
                            let should_result = constant_number $op compare;
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
                                let is_result = rep3_ring::combine_ring_element(a, b, c);
                                println!("{constant_number} {} {compare} = {is_result}", stringify!($op));
                                assert_eq!(is_result.0.convert(), should_result);
                            }
                        }
                    }

                    #[test]
                    fn $name() {
                        // $name_t::<Bit>();
                        apply_to_all!($name_t,[u8, u16, u32, u64, u128]);
                    }
                }
            };
        }
    bool_op_test!(lt, lt_t, <);
    bool_op_test!(le, le_t, <=);
    bool_op_test!(gt, gt_t, >);
    bool_op_test!(ge, ge_t, >=);

    fn rep3_a2b_zero_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = RingElement::<T>::zero();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

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
        let is_result = rep3_ring::combine_ring_element_binary(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_a2b_zero() {
        apply_to_all!(rep3_a2b_zero_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_a2y2b_zero_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = RingElement::<T>::zero();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

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
        let is_result = rep3_ring::combine_ring_element_binary(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_a2y2b_zero() {
        apply_to_all!(rep3_a2y2b_zero_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_a2y2b_streaming_zero_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = RingElement::<T>::zero();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

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
        let is_result = rep3_ring::combine_ring_element_binary(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_a2y2b_streaming_zero() {
        apply_to_all!(rep3_a2y2b_streaming_zero_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_a2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

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
        let is_result = rep3_ring::combine_ring_element_binary(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_a2b() {
        apply_to_all!(rep3_a2b_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_a2y2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

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
        let is_result = rep3_ring::combine_ring_element_binary(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_a2y2b() {
        apply_to_all!(rep3_a2y2b_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_a2y2b_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

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
        let is_result = rep3_ring::combine_ring_element_binary(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_a2y2b_streaming() {
        apply_to_all!(rep3_a2y2b_streaming_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_b2a_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_b2a() {
        apply_to_all!(rep3_b2a_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_b2y2a_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_b2y2a() {
        apply_to_all!(rep3_b2y2a_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_b2y2a_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_b2y2a_streaming() {
        apply_to_all!(rep3_b2y2a_streaming_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_gc_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
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
                let x_ = garbler.encode_ring(x);
                let y_ = garbler.encode_ring(y);

                // This is without OT, just a simulation
                garbler.add_bundle_to_circuit(&x_.evaluator_wires);
                garbler.add_bundle_to_circuit(&y_.evaluator_wires);

                let circuit_output = GarbledCircuits::adder_mod_2k(
                    &mut garbler,
                    &x_.garbler_wires,
                    &y_.garbler_wires,
                )
                .unwrap();

                let output = garbler.output_all_parties(circuit_output.wires()).unwrap();
                let add = GCUtils::bits_to_ring::<T>(&output).unwrap();
                tx.send(add)
            });
        }

        // The evaluator (ID0)
        thread::spawn(move || {
            let mut ctx = IoContext::init(net1).unwrap();

            let mut evaluator = Rep3Evaluator::new(&mut ctx);
            let n_bits = T::K;

            // This is without OT, just a simulation
            evaluator.receive_circuit().unwrap();
            let x_ = evaluator.receive_bundle_from_circuit(n_bits).unwrap();
            let y_ = evaluator.receive_bundle_from_circuit(n_bits).unwrap();

            let circuit_output = GarbledCircuits::adder_mod_2k(&mut evaluator, &x_, &y_).unwrap();

            let output = evaluator
                .output_all_parties(circuit_output.wires())
                .unwrap();
            let add = GCUtils::bits_to_ring::<T>(&output).unwrap();
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
    fn rep3_gc() {
        apply_to_all!(rep3_gc_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_gc_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
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
                let x_ = garbler.encode_ring(x);
                let y_ = garbler.encode_ring(y);

                // This is without OT, just a simulation
                garbler.send_bundle(&x_.evaluator_wires).unwrap();
                garbler.send_bundle(&y_.evaluator_wires).unwrap();

                let circuit_output = GarbledCircuits::adder_mod_2k(
                    &mut garbler,
                    &x_.garbler_wires,
                    &y_.garbler_wires,
                )
                .unwrap();

                let output = garbler.output_all_parties(circuit_output.wires()).unwrap();
                let add = GCUtils::bits_to_ring::<T>(&output).unwrap();
                tx.send(add)
            });
        }

        // The evaluator (ID0)
        thread::spawn(move || {
            let mut ctx = IoContext::init(net1).unwrap();

            let mut evaluator = StreamingRep3Evaluator::new(&mut ctx);
            let n_bits = T::K;

            // This is without OT, just a simulation
            let x_ = evaluator.receive_bundle(n_bits).unwrap();
            let y_ = evaluator.receive_bundle(n_bits).unwrap();

            let circuit_output = GarbledCircuits::adder_mod_2k(&mut evaluator, &x_, &y_).unwrap();

            let output = evaluator
                .output_all_parties(circuit_output.wires())
                .unwrap();
            let add = GCUtils::bits_to_ring::<T>(&output).unwrap();
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
        apply_to_all!(rep3_gc_streaming_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_a2y_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

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

                tx.send(GCUtils::bits_to_ring::<T>(&output).unwrap())
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
    fn rep3_a2y() {
        apply_to_all!(rep3_a2y_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_a2y_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

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

                tx.send(GCUtils::bits_to_ring::<T>(&output).unwrap())
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
        apply_to_all!(rep3_a2y_streaming_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_y2a_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let delta = GCUtils::random_delta(&mut rng);
        let x = rng.gen::<RingElement<T>>();
        let x_shares = GCUtils::encode_ring(x, &mut rng, delta);
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
                let converted = conversion::y2a::<T, _>(x, Some(delta), &mut rep3).unwrap();
                tx.send(converted).unwrap();
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_y2a() {
        apply_to_all!(rep3_y2a_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_y2a_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let delta = GCUtils::random_delta(&mut rng);
        let x = rng.gen::<RingElement<T>>();
        let x_shares = GCUtils::encode_ring(x, &mut rng, delta);
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
                    conversion::y2a_streaming::<T, _>(x, Some(delta), &mut rep3).unwrap();
                tx.send(converted).unwrap();
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_y2a_streaming() {
        apply_to_all!(rep3_y2a_streaming_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_b2y_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

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

                tx.send(GCUtils::bits_to_ring::<T>(&output).unwrap())
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
    fn rep3_b2y() {
        apply_to_all!(rep3_b2y_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_b2y_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

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

                tx.send(GCUtils::bits_to_ring::<T>(&output).unwrap())
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
        apply_to_all!(rep3_b2y_streaming_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_y2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let delta = GCUtils::random_delta(&mut rng);
        let x = rng.gen::<RingElement<T>>();
        let x_shares = GCUtils::encode_ring(x, &mut rng, delta);
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
                let converted = conversion::y2b::<T, _>(x, &mut rep3).unwrap();
                tx.send(converted).unwrap();
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element_binary(result1, result2, result3);
        assert_eq!(is_result, x);
    }

    #[test]
    fn rep3_y2b() {
        apply_to_all!(rep3_y2b_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_ring_cast_a2b_t<T, U>()
    where
        Standard: Distribution<T> + Distribution<U>,
        T: IntRing2k + AsPrimitive<U>,
        U: IntRing2k,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let should_result = RingElement(x.0.as_());
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
        ) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();
                let y = casts::cast_a2b(x, &mut ctx).unwrap();
                tx.send(y)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_ring_cast_a2b() {
        apply_to_all2!(
            rep3_ring_cast_a2b_t,
            [Bit, u8, u16, u32, u64, u128],
            [Bit, u8, u16, u32, u64, u128]
        );
    }

    fn rep3_field_to_ring_cast_a2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let should_result_biguint: BigUint = x.into();
        let should_result = RingElement(T::cast_from_biguint(&should_result_biguint));
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
        ) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();
                let y = casts::field_to_ring_a2b(x, &mut ctx).unwrap();
                tx.send(y)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_field_to_ring_a2b_cast() {
        apply_to_all!(
            rep3_field_to_ring_cast_a2b_t,
            [Bit, u8, u16, u32, u64, u128]
        );
    }

    fn rep3_ring_to_field_cast_a2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let should_result = ark_bn254::Fr::from(T::cast_to_biguint(&x.0));
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
        ) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();
                let y = casts::ring_to_field_a2b::<_, ark_bn254::Fr, _>(x, &mut ctx).unwrap();
                tx.send(y)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_ring_to_field_cast_a2b() {
        apply_to_all!(
            rep3_ring_to_field_cast_a2b_t,
            [Bit, u8, u16, u32, u64, u128]
        );
    }

    fn rep3_field_to_ring_cast_gc_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let should_result = x
            .into_iter()
            .map(|x| {
                let should_result_biguint: BigUint = x.into();
                RingElement(T::cast_from_biguint(&should_result_biguint))
            })
            .collect::<Vec<_>>();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
        ) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();
                let y = yao::field_to_ring_many::<_, T, _>(&x, &mut ctx).unwrap();
                tx.send(y)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_field_to_ring_cast_gc() {
        apply_to_all!(rep3_field_to_ring_cast_gc_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_ring_to_field_cast_gc_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect::<Vec<_>>();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let should_result = x
            .into_iter()
            .map(|x| ark_bn254::Fr::from(T::cast_to_biguint(&x.0)))
            .collect::<Vec<_>>();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
        ) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();
                let y = yao::ring_to_field_many::<_, ark_bn254::Fr, _>(&x, &mut ctx).unwrap();
                tx.send(y)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_ring_to_field_cast_gc() {
        apply_to_all!(rep3_ring_to_field_cast_gc_t, [Bit, u8, u16, u32, u64, u128]);
    }

    fn rep3_ring_upcast_gc_t<T, U>()
    where
        Standard: Distribution<T> + Distribution<U>,
        T: IntRing2k + AsPrimitive<U>,
        U: IntRing2k,
    {
        const VEC_SIZE: usize = 10;

        if U::K <= T::K {
            return;
        }
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect::<Vec<_>>();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let should_result = x
            .into_iter()
            .map(|x| RingElement(x.0.as_()))
            .collect::<Vec<_>>();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
        ) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();
                let y = yao::upcast_many(&x, &mut ctx).unwrap();
                tx.send(y)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_ring_upcast_gc() {
        apply_to_all2!(
            rep3_ring_upcast_gc_t,
            [Bit, u8, u16, u32, u64, u128],
            [Bit, u8, u16, u32, u64, u128]
        );
    }

    fn rep3_ring_cast_gc_t<T, U>()
    where
        Standard: Distribution<T> + Distribution<U>,
        T: IntRing2k + AsPrimitive<U>,
        U: IntRing2k,
    {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let should_result = RingElement(x.0.as_());
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
        ) {
            thread::spawn(move || {
                let mut ctx = IoContext::init(net).unwrap();
                let y = casts::cast_gc(x, &mut ctx).unwrap();
                tx.send(y)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_ring_cast_gc() {
        apply_to_all2!(
            rep3_ring_cast_gc_t,
            [Bit, u8, u16, u32, u64, u128],
            [Bit, u8, u16, u32, u64, u128]
        );
    }

    fn rep3_decompose_shared_field_many_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;
        let num_chunks = (ark_bn254::Fr::MODULUS_BIT_SIZE as usize).div_ceil(T::K);

        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let mut should_result = Vec::with_capacity(VEC_SIZE * num_chunks);
        let mask = (BigUint::from(1u64) << T::K) - BigUint::one();
        for x in x.into_iter() {
            let mut x: BigUint = x.into();
            for _ in 0..num_chunks {
                let chunk = &x & &mask;
                x >>= T::K;
                should_result.push(RingElement(T::cast_from_biguint(&chunk)));
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
                    yao::decompose_field_to_rings_many(&x, &mut rep3, num_chunks, T::K).unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_decompose_shared_field_many_via_yao() {
        apply_to_all!(
            rep3_decompose_shared_field_many_via_yao_t,
            [Bit, u8, u16, u32, u64, u128]
        );
    }

    fn rep3_div_power_2_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let divisor_bit: usize = rng.gen_range(0..=T::K);

        let mut should_result = Vec::with_capacity(VEC_SIZE);
        for x in x.into_iter() {
            should_result.push(x >> divisor_bit);
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

                let decomposed = yao::ring_div_power_2_many(&x, &mut rep3, divisor_bit).unwrap();
                tx.send(decomposed)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }
    fn rep3_bin_div_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let y = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let y_shares = rep3_ring::share_ring_elements(&y, &mut rng);
        let mut should_result: Vec<RingElement<T>> = Vec::with_capacity(VEC_SIZE);
        for (x, y) in x.into_iter().zip(y.into_iter()) {
            should_result.push(RingElement(T::cast_from_biguint(
                &(x.0.cast_to_biguint() / y.0.cast_to_biguint()),
            )));
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

                let div = yao::ring_div_many(&x, &y, &mut rep3).unwrap();
                tx.send(div)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }
    fn rep3_bin_div_by_public_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let y = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let y_1 = y.clone();
        let y_2 = y.clone();
        let y_3 = y.clone();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let mut should_result: Vec<RingElement<T>> = Vec::with_capacity(VEC_SIZE);
        for (x, y) in x.into_iter().zip(y.into_iter()) {
            should_result.push(RingElement(T::cast_from_biguint(
                &(x.0.cast_to_biguint() / y.0.cast_to_biguint()),
            )));
        }
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y_c) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            [y_1, y_2, y_3]
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let div = yao::ring_div_by_public_many(&x, &y_c, &mut rep3).unwrap();
                tx.send(div)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }
    fn rep3_bin_div_by_shared_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let y = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let x_1 = x.clone();
        let x_2 = x.clone();
        let x_3 = x.clone();
        let y_shares = rep3_ring::share_ring_elements(&y, &mut rng);
        let mut should_result: Vec<RingElement<T>> = Vec::with_capacity(VEC_SIZE);
        for (x, y) in x.into_iter().zip(y.into_iter()) {
            should_result.push(RingElement(T::cast_from_biguint(
                &(x.0.cast_to_biguint() / y.0.cast_to_biguint()),
            )));
        }
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, y_c, x_c) in izip!(
            test_network.get_party_networks().into_iter(),
            [tx1, tx2, tx3],
            y_shares.into_iter(),
            [x_1, x_2, x_3]
        ) {
            thread::spawn(move || {
                let mut rep3 = IoContext::init(net).unwrap();

                let div = yao::ring_div_by_shared_many(&x_c, &y_c, &mut rep3).unwrap();
                tx.send(div)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }
    #[test]
    fn rep3_bin_div_by_shared_via_yao() {
        apply_to_all!(rep3_bin_div_by_shared_via_yao_t, [u8, u16, u32, u64, u128]);
    }
    #[test]
    fn rep3_bin_div_by_public_via_yao() {
        apply_to_all!(rep3_bin_div_by_public_via_yao_t, [u8, u16, u32, u64, u128]);
    }
    #[test]
    fn rep3_bin_div_via_yao() {
        apply_to_all!(rep3_bin_div_via_yao_t, [u8, u16, u32, u64, u128]);
    }

    #[test]
    fn rep3_div_power_2_via_yao() {
        apply_to_all!(rep3_div_power_2_via_yao_t, [Bit, u8, u16, u32, u64, u128]);
    }
}
