#![allow(clippy::result_large_err)]
mod ring_share {
    use ark_ff::PrimeField;
    use ark_std::UniformRand;
    use itertools::izip;
    use itertools::Itertools;
    use mpc_core::protocols::rep3;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3::id::PartyID;
    use mpc_core::protocols::rep3::yao::circuits::GarbledCircuits;
    use mpc_core::protocols::rep3::yao::evaluator::Rep3Evaluator;
    use mpc_core::protocols::rep3::yao::garbler::Rep3Garbler;
    use mpc_core::protocols::rep3::yao::streaming_evaluator::StreamingRep3Evaluator;
    use mpc_core::protocols::rep3::yao::streaming_garbler::StreamingRep3Garbler;
    use mpc_core::protocols::rep3::yao::GCUtils;
    use mpc_core::protocols::rep3::Rep3State;
    use mpc_core::protocols::rep3_ring;
    use mpc_core::protocols::rep3_ring::arithmetic;
    use mpc_core::protocols::rep3_ring::casts;
    use mpc_core::protocols::rep3_ring::conversion;
    use mpc_core::protocols::rep3_ring::gadgets;
    use mpc_core::protocols::rep3_ring::ring::bit::Bit;
    use mpc_core::protocols::rep3_ring::ring::int_ring::IntRing2k;
    use mpc_core::protocols::rep3_ring::ring::int_ring::U512;
    use mpc_core::protocols::rep3_ring::ring::ring_impl::RingElement;
    use mpc_core::protocols::rep3_ring::yao;
    use mpc_core::protocols::rep3_ring::Rep3RingShare;
    use mpc_core::uint::{FieldUint, UintBackend, U256};
    use mpc_core::MpcState;
    use mpc_net::local::LocalNetwork;
    use num_traits::{AsPrimitive, One, Zero};
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand::thread_rng;
    use rand::Rng;
    use std::sync::mpsc;

    /// Widens a ring element into a [`U512`] for independent public-value
    /// math (division by a field modulus, bit-slicing, etc.). `U512` is the
    /// widest ring type exercised in this file, so it is always wide enough
    /// to hold any `T` used here without loss.
    fn ring_to_u512<T: IntRing2k>(x: &T) -> U512 {
        x.cast_to_uint()
    }

    /// Extracts bits `[start, end)` of `x` as a field element
    /// (the `Utils::slice_u256` computation on a fixed-width uint).
    fn slice_u512<F: FieldUint>(x: &U512, start: u64, end: u64) -> F {
        let slice = (*x >> start as usize) & U512::mask((end - start) as usize);
        u512_to_field(&slice)
    }

    /// Reduces a [`U512`] into the field `F`.
    fn u512_to_field<F: FieldUint>(u: &U512) -> F {
        debug_assert!(u.bit_len() <= F::Uint::BITS);
        F::from_uint_reduced(&F::Uint::from_limbs_truncating(u.as_limbs()))
    }

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

    fn gen_non_zero<T: IntRing2k, R: Rng>(rng: &mut R) -> RingElement<T>
    where
        Standard: Distribution<T>,
    {
        loop {
            let el = rng.gen::<RingElement<T>>();
            if !el.is_zero() {
                return el;
            }
        }
    }

    // TODO we dont need channels, we can just join

    fn rep3_add_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let y_shares = rep3_ring::share_ring_element(y, &mut rng);
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_add() {
        apply_to_all!(rep3_add_t, [Bit, u8, u16, u32, u64, u128, U512]);
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
            std::thread::spawn(move || tx.send(arithmetic::sub(x, y)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub() {
        apply_to_all!(rep3_sub_t, [Bit, u8, u16, u32, u64, u128, U512]);
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
            std::thread::spawn(move || tx.send(arithmetic::sub_shared_by_public(x, y, id)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub_shared_by_public() {
        apply_to_all!(
            rep3_sub_shared_by_public_t,
            [Bit, u8, u16, u32, u64, u128, U512]
        );
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
            std::thread::spawn(move || tx.send(arithmetic::sub_public_by_shared(x, y, id)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_sub_public_by_shared() {
        apply_to_all!(
            rep3_sub_public_by_shared_t,
            [Bit, u8, u16, u32, u64, u128, U512]
        );
    }

    fn rep3_mul_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
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
            nets,
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul() {
        apply_to_all!(rep3_mul_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_fork_mul_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets0 = LocalNetwork::new_3_parties();
        let nets1 = LocalNetwork::new_3_parties();
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
        for (net0, net1, (x0, y0), (x1, y1)) in izip!(
            nets0,
            nets1,
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
        let is_result0 = rep3_ring::combine_ring_element(result1.0, result2.0, result3.0);
        let is_result1 = rep3_ring::combine_ring_element(result1.1, result2.1, result3.1);
        assert_eq!(is_result0, should_result0);
        assert_eq!(is_result1, should_result1);
    }

    #[test]
    fn rep3_fork_mul() {
        apply_to_all!(rep3_fork_mul_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_mul2_then_add_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
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
            nets,
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
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul2_then_add() {
        apply_to_all!(rep3_mul2_then_add_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_mul_vec_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
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
            nets,
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
        let is_result = rep3_ring::combine_ring_elements(&result1, &result2, &result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_mul_vec() {
        apply_to_all!(rep3_mul_vec_t, [Bit, u8, u16, u32, u64, u128, U512]);
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
            std::thread::spawn(move || tx.send(arithmetic::neg(x)));
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[test]
    fn rep3_neg() {
        apply_to_all!(rep3_neg_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_bit_inject_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
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
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::bit_inject(&x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_bit_inject_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_bit_inject_many_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
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
        for ((net, tx), x) in nets
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip([x0_shares, x1_shares, x2_shares])
        {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::bit_inject_many(&x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_bit_inject_many_t, [Bit, u8, u16, u32, u64, u128, U512]);
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
                            let nets = LocalNetwork::new_3_parties();
                            let mut rng = thread_rng();
                            let x_shares = rep3_ring::share_ring_element(constant_number, &mut rng);
                            let y_shares = rep3_ring::share_ring_element(compare, &mut rng);
                            let should_result = constant_number $op compare;
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
                                let is_result = rep3_ring::combine_ring_element(a, b, c);
                                println!("{constant_number} {} {compare} = {is_result}", stringify!($op));
                                assert_eq!(is_result.0.convert(), should_result);
                            }
                        }
                    }

                    #[test]
                    fn $name() {
                        // $name_t::<Bit>();
                        apply_to_all!($name_t,[u8, u16, u32, u64, u128,U512]);
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
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = RingElement::<T>::zero();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2b(x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_a2b_zero_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_a2y2b_zero_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = RingElement::<T>::zero();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2y2b(x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_a2y2b_zero_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_a2y2b_streaming_zero_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = RingElement::<T>::zero();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2y2b_streaming(x, &net, &mut state).unwrap())
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
        apply_to_all!(
            rep3_a2y2b_streaming_zero_t,
            [Bit, u8, u16, u32, u64, u128, U512]
        );
    }

    fn rep3_a2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2b(x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_a2b_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_a2y2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2y2b(x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_a2y2b_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_a2y2b_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::a2y2b_streaming(x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_a2y2b_streaming_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_b2a_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::b2a(&x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_b2a_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_b2y2a_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::b2y2a(&x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_b2y2a_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_b2y2a_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                tx.send(conversion::b2y2a_streaming(&x, &net, &mut state).unwrap())
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
        apply_to_all!(rep3_b2y2a_streaming_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_gc_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
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
        std::thread::spawn(move || {
            let _state = Rep3State::new(&net1, A2BType::default()).unwrap(); // DONT REMOVE
            let mut evaluator = Rep3Evaluator::new(&net1);
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
        apply_to_all!(rep3_gc_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_gc_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let y = rng.gen::<RingElement<T>>();
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
        std::thread::spawn(move || {
            let _state = Rep3State::new(&net1, A2BType::default()).unwrap(); // DONT REMOVE
            let mut evaluator = StreamingRep3Evaluator::new(&net1);
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
        apply_to_all!(rep3_gc_streaming_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_a2y_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter()) {
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
        apply_to_all!(rep3_a2y_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_a2y_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter()) {
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
        apply_to_all!(rep3_a2y_streaming_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_y2a_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
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

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let converted = conversion::y2a::<T, _>(x, Some(delta), &net, &mut state).unwrap();
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
        apply_to_all!(rep3_y2a_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_y2a_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
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

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let converted =
                    conversion::y2a_streaming::<T, _>(x, Some(delta), &net, &mut state).unwrap();
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
        apply_to_all!(rep3_y2a_streaming_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_b2y_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
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
        apply_to_all!(rep3_b2y_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_b2y_streaming_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element_binary(x, &mut rng);

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for ((net, tx), x) in nets.into_iter().zip([tx1, tx2, tx3]).zip(x_shares) {
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
        apply_to_all!(rep3_b2y_streaming_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_y2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
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

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let converted = conversion::y2b::<T, _>(x, &net, &mut state).unwrap();
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
        apply_to_all!(rep3_y2b_t, [Bit, u8, u16, u32, u64, u128, U512]);
    }

    fn rep3_ring_cast_a2b_t<T, U>()
    where
        Standard: Distribution<T> + Distribution<U>,
        T: IntRing2k + AsPrimitive<U>,
        U: IntRing2k,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let should_result = RingElement(x.0.as_());
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let y = casts::cast_a2b(x, &net, &mut state).unwrap();
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
            [Bit, u8, u16, u32, u64, u128, U512],
            [Bit, u8, u16, u32, u64, u128, U512]
        );
    }

    fn rep3_field_to_ring_cast_a2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let should_result = RingElement(T::cast_from_uint(&x.to_uint()));
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let y = casts::field_to_ring_a2b(x, &net, &mut state).unwrap();
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
            [Bit, u8, u16, u32, u64, u128, U512]
        );
    }

    fn rep3_ring_to_field_cast_a2b_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let should_result = ark_bn254::Fr::from_uint_unchecked(&x.0.cast_to_uint::<U256>());
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let y =
                    casts::ring_to_field_a2b::<_, ark_bn254::Fr, _>(x, &net, &mut state).unwrap();
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

    fn rep3_ring_to_field_cast_a2b_big_ring_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let should_result = ark_bn254::Fr::rand(&mut rng);
        let x = RingElement(T::cast_from_uint(&should_result.to_uint()));
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let y =
                    casts::ring_to_field_a2b_big_ring::<_, ark_bn254::Fr, _>(x, &net, &mut state)
                        .unwrap();
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
    fn rep3_ring_to_field_cast_a2b_big_ring() {
        apply_to_all!(rep3_ring_to_field_cast_a2b_big_ring_t, [U512]);
    }

    // The truncated ring element is larger than the modulus, so it has to be reduced
    #[test]
    fn rep3_ring_to_field_cast_a2b_big_ring_reduces() {
        type F = ark_bn254::Fr;
        let bits = F::MODULUS_BIT_SIZE as usize;
        // 2^bits - 1 mod p
        let mut bytes = vec![0xffu8; bits.div_ceil(8)];
        *bytes.last_mut().unwrap() >>= (8 - bits % 8) % 8;
        let should_result = F::from_le_bytes_mod_order(&bytes);
        assert_ne!(should_result.to_uint(), U256::mask(bits));

        // all bits of the modulus size are set, all bits of the ring are set
        let truncated = RingElement(U512::cast_from_uint(&U256::mask(bits)));
        for x in [truncated, !RingElement::<U512>::zero()] {
            let mut rng = thread_rng();
            let x_shares = rep3_ring::share_ring_element(x, &mut rng);
            let threads = izip!(LocalNetwork::new_3_parties(), x_shares)
                .map(|(net, x)| {
                    std::thread::spawn(move || {
                        let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                        let single =
                            casts::ring_to_field_a2b_big_ring::<_, F, _>(x, &net, &mut state)
                                .unwrap();
                        let many = casts::ring_to_field_a2b_big_ring_many::<_, F, _>(
                            &[x, x],
                            &net,
                            &mut state,
                        )
                        .unwrap();
                        (single, many)
                    })
                })
                .collect_vec();
            let results = threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect_vec();
            let single = rep3::combine_field_element(results[0].0, results[1].0, results[2].0);
            assert_eq!(single, should_result);
            let many = rep3::combine_field_elements(&results[0].1, &results[1].1, &results[2].1);
            assert_eq!(many, vec![should_result; 2]);
        }
    }

    // A ring with more bits than the field has elements that are no valid field elements
    #[test]
    fn rep3_ring_to_field_casts_reject_big_rings() {
        type F = ark_bn254::Fr;
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<U512>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let threads = izip!(LocalNetwork::new_3_parties(), x_shares)
            .map(|(net, x)| {
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    assert!(casts::ring_to_field_a2b::<_, F, _>(x, &net, &mut state).is_err());
                    assert!(
                        casts::ring_to_field_a2b_many::<_, F, _>(&[x], &net, &mut state).is_err()
                    );
                    assert!(yao::ring_to_field_many::<_, F, _>(&[x], &net, &mut state).is_err());
                    // and the other way round
                    let narrow = Rep3RingShare::<u64>::default();
                    assert!(
                        casts::ring_to_field_a2b_big_ring::<_, F, _>(narrow, &net, &mut state)
                            .is_err()
                    );
                    // The casts via Yao from a field need all bits of the ring in the field
                    let field_share = rep3::Rep3PrimeFieldShare::<F>::default();
                    assert!(yao::field_to_ring_many::<F, U512, _>(
                        &[field_share],
                        &net,
                        &mut state
                    )
                    .is_err());
                    // The decomposition into another field needs fields of the same bit size
                    assert!(rep3::yao::decompose_arithmetic_to_other_field_many::<
                        F,
                        ark_bls12_381::Fr,
                        _,
                    >(&[field_share], &net, &mut state, 8, 8)
                    .is_err());
                })
            })
            .collect_vec();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    fn rep3_field_to_ring_cast_gc_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let should_result = x
            .into_iter()
            .map(|x| RingElement(T::cast_from_uint(&x.to_uint())))
            .collect::<Vec<_>>();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let y = yao::field_to_ring_many::<_, T, _>(&x, &net, &mut state).unwrap();
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

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect::<Vec<_>>();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let should_result = x
            .into_iter()
            .map(|x| ark_bn254::Fr::from_uint_unchecked(&x.0.cast_to_uint::<U256>()))
            .collect::<Vec<_>>();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let y =
                    yao::ring_to_field_many::<_, ark_bn254::Fr, _>(&x, &net, &mut state).unwrap();
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
        let nets = LocalNetwork::new_3_parties();
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
        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let y = yao::upcast_many(&x, &net, &mut state).unwrap();
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
            [Bit, u8, u16, u32, u64, u128, U512],
            [Bit, u8, u16, u32, u64, u128, U512]
        );
    }

    fn rep3_ring_cast_gc_t<T, U>()
    where
        Standard: Distribution<T> + Distribution<U>,
        T: IntRing2k + AsPrimitive<U>,
        U: IntRing2k,
    {
        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = rng.gen::<RingElement<T>>();
        let x_shares = rep3_ring::share_ring_element(x, &mut rng);
        let should_result = RingElement(x.0.as_());
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let y = casts::cast_gc(x, &net, &mut state).unwrap();
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
            [Bit, u8, u16, u32, u64, u128, U512],
            [Bit, u8, u16, u32, u64, u128, U512]
        );
    }

    fn rep3_decompose_shared_field_many_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;
        let num_chunks = (ark_bn254::Fr::MODULUS_BIT_SIZE as usize).div_ceil(T::K);

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);

        let mut should_result = Vec::with_capacity(VEC_SIZE * num_chunks);
        let mask = U512::mask(T::K);
        for x in x.into_iter() {
            let mut x = U512::from_limbs_truncating(x.to_uint().as_limbs());
            for _ in 0..num_chunks {
                let chunk = x & mask;
                x >>= T::K;
                should_result.push(RingElement(T::cast_from_uint(&chunk)));
            }
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed =
                    yao::decompose_field_to_rings_many(&x, &net, &mut state, num_chunks, T::K)
                        .unwrap();
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
            [Bit, u8, u16, u32, u64, u128, U512]
        );
    }

    fn rep3_div_power_2_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
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

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter()) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let decomposed =
                    yao::ring_div_power_2_many(&x, &net, &mut state, divisor_bit).unwrap();
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
    fn rep3_div_power_2_via_yao() {
        apply_to_all!(
            rep3_div_power_2_via_yao_t,
            [Bit, u8, u16, u32, u64, u128, U512]
        );
    }

    fn rep3_bin_div_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let y = (0..VEC_SIZE)
            .map(|_| gen_non_zero::<T, _>(&mut rng))
            .collect_vec();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let y_shares = rep3_ring::share_ring_elements(&y, &mut rng);
        let mut should_result: Vec<RingElement<T>> = Vec::with_capacity(VEC_SIZE);
        for (x, y) in x.into_iter().zip(y) {
            should_result.push(RingElement(T::cast_from_uint(
                &(ring_to_u512(&x.0) / ring_to_u512(&y.0)),
            )));
        }
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x, y) in izip!(
            nets,
            [tx1, tx2, tx3],
            x_shares.into_iter(),
            y_shares.into_iter()
        ) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let div = yao::ring_div_many(&x, &y, &net, &mut state).unwrap();
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
    fn rep3_bin_div_via_yao() {
        apply_to_all!(rep3_bin_div_via_yao_t, [u8, u16, u32, u64, u128]); //Too slow for U512
    }

    fn rep3_div_by_public_two_field_output_t<T: IntRing2k, F: FieldUint, K: FieldUint>(
        divisor: &U512,
    ) where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 5;
        const SLICE_SIZE: u64 = 68;
        const LIMBS_PER_FIELD: usize = 4;

        let nets = LocalNetwork::new_with_timeout(3, Some(std::time::Duration::from_secs(120)));
        let mut rng = thread_rng();
        // we are dividing by the field modulus, so we want this to be large
        // enough (also in bb this is close to 512 bits)
        let x = (0..VEC_SIZE)
            .map(|_| RingElement(rng.r#gen::<T>()))
            .collect_vec();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let mut should_result1: Vec<RingElement<T>> = Vec::with_capacity(VEC_SIZE);
        let mut should_result_remainders = Vec::with_capacity(VEC_SIZE);
        for x in x.into_iter() {
            should_result1.push(RingElement(T::cast_from_uint(
                &(ring_to_u512(&x.0) / *divisor),
            )));
            should_result_remainders.push(u512_to_field::<K>(&(ring_to_u512(&x.0) % *divisor)));
        }
        let mut should_result_quotients = Vec::with_capacity(VEC_SIZE);
        for x in &should_result1 {
            let x_uint = ring_to_u512(&x.0);
            should_result_quotients.push(slice_u512::<F>(&x_uint, 0, SLICE_SIZE));
            should_result_quotients.push(slice_u512::<F>(&x_uint, SLICE_SIZE, 2 * SLICE_SIZE));
            should_result_quotients.push(slice_u512::<F>(&x_uint, 2 * SLICE_SIZE, 3 * SLICE_SIZE));
            should_result_quotients.push(slice_u512::<F>(&x_uint, 3 * SLICE_SIZE, 4 * SLICE_SIZE));
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            let divisor = *divisor;
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let div = yao::ring_div_by_public_to_fr_limbs_and_fq_many::<_, _, F, K>(
                    &x,
                    SLICE_SIZE as usize,
                    &divisor,
                    LIMBS_PER_FIELD,
                    &net,
                    &mut state,
                )
                .unwrap();
                tx.send(div)
            });
        }

        let (result1, result1_other) = rx1.recv().unwrap();
        let (result2, result2_other) = rx2.recv().unwrap();
        let (result3, result3_other) = rx3.recv().unwrap();
        let is_result: Vec<F> = rep3::combine_field_elements(&result1, &result2, &result3);
        let is_result_other: Vec<K> =
            rep3::combine_field_elements(&result1_other, &result2_other, &result3_other);

        assert_eq!(is_result, should_result_quotients);
        assert_eq!(is_result_other, should_result_remainders);
    }

    #[test]
    fn rep3_div_by_public_two_field_output() {
        rep3_div_by_public_two_field_output_t::<U512, ark_bn254::Fr, ark_bn254::Fq>(
            &U512::from_limbs_truncating(ark_bn254::Fq::MODULUS.as_ref()),
        );
    }

    fn rep3_div_by_public_to_limbs_output_t<T: IntRing2k, F: FieldUint>(divisor: &U512)
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 5;
        const SLICE_SIZE: u64 = 68;
        const LIMBS_PER_FIELD: usize = 4;

        let nets = LocalNetwork::new_with_timeout(3, Some(std::time::Duration::from_secs(120)));
        let mut rng = thread_rng();
        // we are dividing by the field modulus, so we want this to be large
        // enough (also in bb this is close to 512 bits)
        let x = (0..VEC_SIZE)
            .map(|_| RingElement(rng.r#gen::<T>()))
            .collect_vec();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let mut should_result_quotients_ = Vec::with_capacity(VEC_SIZE);
        let mut should_result_remainders_ = Vec::with_capacity(VEC_SIZE);
        for x in x.into_iter() {
            should_result_quotients_.push(ring_to_u512(&x.0) / *divisor);
            should_result_remainders_.push(ring_to_u512(&x.0) % *divisor);
        }

        let mut should_result_quotients = Vec::with_capacity(VEC_SIZE * LIMBS_PER_FIELD);
        let mut should_result_remainders = Vec::with_capacity(VEC_SIZE * LIMBS_PER_FIELD);
        for x in &should_result_quotients_ {
            for i in 0..LIMBS_PER_FIELD as u64 {
                should_result_quotients.push(slice_u512::<F>(
                    x,
                    i * SLICE_SIZE,
                    (i + 1) * SLICE_SIZE,
                ));
            }
        }
        for x in &should_result_remainders_ {
            for i in 0..LIMBS_PER_FIELD as u64 {
                should_result_remainders.push(slice_u512::<F>(
                    x,
                    i * SLICE_SIZE,
                    (i + 1) * SLICE_SIZE,
                ));
            }
        }

        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            let divisor = *divisor;
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let div = yao::ring_div_by_public_to_limbs_many::<_, _, F>(
                    &x,
                    &divisor,
                    SLICE_SIZE as usize,
                    LIMBS_PER_FIELD,
                    &net,
                    &mut state,
                )
                .unwrap();
                tx.send(div)
            });
        }

        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();
        let is_result: Vec<F> = rep3::combine_field_elements(&result1, &result2, &result3);

        let mut is_quotients = Vec::with_capacity(VEC_SIZE);
        let mut is_remainders = Vec::with_capacity(VEC_SIZE);
        for chunk in is_result.chunks(2 * LIMBS_PER_FIELD) {
            is_quotients.extend(chunk[..LIMBS_PER_FIELD].to_vec());
            is_remainders.extend(chunk[LIMBS_PER_FIELD..].to_vec());
        }

        assert_eq!(is_quotients, should_result_quotients);
        assert_eq!(is_remainders, should_result_remainders);
    }

    #[test]
    fn rep3_div_by_public_to_limbs_output() {
        rep3_div_by_public_to_limbs_output_t::<U512, ark_bn254::Fr>(&U512::from_limbs_truncating(
            ark_bn254::Fq::MODULUS.as_ref(),
        ));
    }

    fn rep3_bin_div_by_public_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let y = (0..VEC_SIZE)
            .map(|_| gen_non_zero::<T, _>(&mut rng))
            .collect_vec();
        let x_shares = rep3_ring::share_ring_elements(&x, &mut rng);
        let mut should_result: Vec<RingElement<T>> = Vec::with_capacity(VEC_SIZE);
        for (x, y) in x.into_iter().zip(y.iter()) {
            should_result.push(RingElement(T::cast_from_uint(
                &(ring_to_u512(&x.0) / ring_to_u512(&y.0)),
            )));
        }
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
            let y_ = y.to_owned();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let div = yao::ring_div_by_public_many(&x, &y_, &net, &mut state).unwrap();
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
    fn rep3_bin_div_by_public_via_yao() {
        apply_to_all!(rep3_bin_div_by_public_via_yao_t, [u8, u16, u32, u64, u128]);
    }

    fn rep3_bin_div_by_shared_via_yao_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        const VEC_SIZE: usize = 10;

        let nets = LocalNetwork::new_3_parties();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| rng.gen::<RingElement<T>>())
            .collect_vec();
        let y = (0..VEC_SIZE)
            .map(|_| gen_non_zero::<T, _>(&mut rng))
            .collect_vec();
        let y_shares = rep3_ring::share_ring_elements(&y, &mut rng);
        let mut should_result: Vec<RingElement<T>> = Vec::with_capacity(VEC_SIZE);
        for (x, y) in x.iter().zip(y) {
            should_result.push(RingElement(T::cast_from_uint(
                &(ring_to_u512(&x.0) / ring_to_u512(&y.0)),
            )));
        }
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx, y_c) in izip!(nets, [tx1, tx2, tx3], y_shares.into_iter(),) {
            let x_ = x.to_owned();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                let div = yao::ring_div_by_shared_many(&x_, &y_c, &net, &mut state).unwrap();
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
        apply_to_all!(
            rep3_bin_div_by_shared_via_yao_t,
            [u8, u16, u32, u64, u128] //Too slow for U512
        );
    }

    fn rep3_rand_ohv_test_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let nets = LocalNetwork::new_3_parties();
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();

        for (net, tx) in izip!(nets, [tx1, tx2, tx3],) {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                // First run, get one of size K
                let res = gadgets::ohv::rand_ohv::<T, _>(T::K, &net, &mut state).unwrap();
                tx.send(res).unwrap();

                // Second run, get one of size K/2
                let res = gadgets::ohv::rand_ohv::<T, _>(T::K >> 1, &net, &mut state).unwrap();
                tx.send(res)
            });
        }

        // Check first run
        let (result1, bits1) = rx1.recv().unwrap();
        let (result2, bits2) = rx2.recv().unwrap();
        let (result3, bits3) = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element_binary(result1, result2, result3);
        let is_bits = rep3_ring::combine_ring_elements(&bits1, &bits2, &bits3);
        assert_eq!(is_bits.len(), 1 << T::K);
        let index: usize = is_result.0.try_into().unwrap();
        for (i, el) in is_bits.into_iter().enumerate() {
            if i == index {
                assert!(el.0.convert())
            } else {
                assert!(!el.0.convert())
            }
        }

        // Check second run
        let (result1, bits1) = rx1.recv().unwrap();
        let (result2, bits2) = rx2.recv().unwrap();
        let (result3, bits3) = rx3.recv().unwrap();
        let is_result = rep3_ring::combine_ring_element_binary(result1, result2, result3);
        let is_bits = rep3_ring::combine_ring_elements(&bits1, &bits2, &bits3);
        assert_eq!(is_bits.len(), 1 << (T::K >> 1));
        let index: usize = is_result.0.try_into().unwrap();
        for (i, el) in is_bits.into_iter().enumerate() {
            if i == index {
                assert!(el.0.convert())
            } else {
                assert!(!el.0.convert())
            }
        }
    }

    #[test]
    fn rep3_rand_ohv_test() {
        apply_to_all!(rep3_rand_ohv_test_t, [u8, u16]);
    }

    fn rep3_lut_test_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        for k in 1..T::K {
            let n = 1 << k;
            let lut = (0..n)
                .map(|_| ark_bn254::Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let x = rng.gen_range::<usize, _>(0..n);
            let x_ = RingElement(T::try_from(x as u64).unwrap());
            let x_shares = rep3_ring::share_ring_element_binary(x_, &mut rng);
            let should_result_f = lut[x].to_owned();

            let nets = LocalNetwork::new_3_parties();
            let (tx1, rx1) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();
            let (tx3, rx3) = mpsc::channel();

            for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
                let lut = lut.clone();
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let res =
                        gadgets::lut_field::read_public_lut(&lut, x, &net, &mut state).unwrap();
                    tx.send(res)
                });
            }

            let result1 = rx1.recv().unwrap();
            let result2 = rx2.recv().unwrap();
            let result3 = rx3.recv().unwrap();
            let is_result = rep3::combine_binary_element(result1, result2, result3);
            let should_result = should_result_f.to_uint();
            assert_eq!(is_result, should_result);
            let is_result_f = ark_bn254::Fr::from_uint_unchecked(&is_result);
            assert_eq!(is_result_f, should_result_f);
        }
    }

    #[test]
    fn rep3_lut_test() {
        apply_to_all!(rep3_lut_test_t, [u8, u16]);
    }

    fn rep3_curve_lut_test_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        for k in 1..T::K {
            let n = 1 << k;
            let lut = (0..n)
                .map(|_| ark_bn254::G1Projective::rand(&mut rng))
                .collect::<Vec<_>>();
            let x = rng.gen_range::<usize, _>(0..n);
            let x_ = RingElement(T::try_from(x as u64).unwrap());
            let x_shares = rep3_ring::share_ring_element_binary(x_, &mut rng);
            let should_result_f = lut[x].to_owned();

            let nets = LocalNetwork::new_3_parties();
            let (tx1, rx1) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();
            let (tx3, rx3) = mpsc::channel();

            for (net, tx, x) in izip!(nets, [tx1, tx2, tx3], x_shares.into_iter(),) {
                let lut = lut.clone();
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let res =
                        gadgets::lut_curve::read_public_lut(&lut, x, &net, &mut state).unwrap();
                    tx.send(res)
                });
            }

            let result1 = rx1.recv().unwrap();
            let result2 = rx2.recv().unwrap();
            let result3 = rx3.recv().unwrap();
            let is_result = rep3::combine_curve_point(result1, result2, result3);
            assert_eq!(is_result, should_result_f);
        }
    }

    #[test]
    fn rep3_curve_lut_test() {
        apply_to_all!(rep3_curve_lut_test_t, [u8, u16]);
    }

    fn rep3_lut_low_depth_test_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        for k in 1..T::K {
            let n = 1 << k;
            let lut = (0..n)
                .map(|_| ark_bn254::Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let x = rng.gen_range::<usize, _>(0..n);
            let x_ = RingElement(T::try_from(x as u64).unwrap());
            let x_shares = rep3_ring::share_ring_element_binary(x_, &mut rng);
            let should_result_f = lut[x].to_owned();

            let nets = LocalNetwork::new_3_parties();
            let (tx1, rx1) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();
            let (tx3, rx3) = mpsc::channel();

            for (net, tx, x, lut) in izip!(
                nets,
                [tx1, tx2, tx3],
                x_shares.into_iter(),
                [lut.clone(), lut.clone(), lut]
            ) {
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                    let res =
                        gadgets::lut_field::read_public_lut_low_depth(&lut, x, &net, &mut state)
                            .unwrap();
                    tx.send(res).unwrap();
                });
            }

            let result1 = rx1.recv().unwrap();
            let result2 = rx2.recv().unwrap();
            let result3 = rx3.recv().unwrap();
            let is_result = result1 ^ result2 ^ result3;
            let should_result = should_result_f.to_uint();
            assert_eq!(is_result, should_result);
            let is_result_f = ark_bn254::Fr::from_uint_unchecked(&is_result);
            assert_eq!(is_result_f, should_result_f);
        }
    }

    #[test]
    fn rep3_lut_low_depth_test() {
        apply_to_all!(rep3_lut_low_depth_test_t, [u8, u16]);
    }

    fn rep3_shared_lut_test_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        for k in 1..T::K {
            let n = 1 << k;
            let lut = (0..n)
                .map(|_| ark_bn254::Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let x = rng.gen_range::<usize, _>(0..n);
            let x_ = RingElement(T::try_from(x as u64).unwrap());
            let x_shares = rep3_ring::share_ring_element_binary(x_, &mut rng);
            let lut_shares = rep3::share_field_elements(&lut, &mut rng);
            let should_result = lut[x].to_owned();

            let nets = LocalNetwork::new_3_parties();
            let (tx1, rx1) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();
            let (tx3, rx3) = mpsc::channel();

            for (net, tx, x, lut) in izip!(
                nets,
                [tx1, tx2, tx3],
                x_shares.into_iter(),
                lut_shares.into_iter()
            ) {
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let res =
                        gadgets::lut_field::read_shared_lut(&lut, x, &net, &mut state).unwrap();
                    tx.send(res)
                });
            }

            let result1 = rx1.recv().unwrap();
            let result2 = rx2.recv().unwrap();
            let result3 = rx3.recv().unwrap();
            let is_result = result1 + result2 + result3;
            assert_eq!(is_result, should_result);
        }
    }

    #[test]
    fn rep3_shared_lut_test() {
        apply_to_all!(rep3_shared_lut_test_t, [u8, u16]);
    }

    fn rep3_shared_curve_lut_test_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        for k in 1..T::K {
            let n = 1 << k;
            let lut = (0..n)
                .map(|_| ark_bn254::G1Projective::rand(&mut rng))
                .collect::<Vec<_>>();
            let x = rng.gen_range::<usize, _>(0..n);
            let x_ = RingElement(T::try_from(x as u64).unwrap());
            let x_shares = rep3_ring::share_ring_element_binary(x_, &mut rng);
            let lut_shares = rep3::share_curve_points(&lut, &mut rng);
            let should_result = lut[x].to_owned();

            let nets = LocalNetwork::new_3_parties();
            let (tx1, rx1) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();
            let (tx3, rx3) = mpsc::channel();

            for (net, tx, x, lut) in izip!(
                nets,
                [tx1, tx2, tx3],
                x_shares.into_iter(),
                lut_shares.into_iter()
            ) {
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let res =
                        gadgets::lut_curve::read_shared_lut(&lut, x, &net, &mut state).unwrap();
                    tx.send(res)
                });
            }

            let result1 = rx1.recv().unwrap();
            let result2 = rx2.recv().unwrap();
            let result3 = rx3.recv().unwrap();
            let is_result = result1 + result2 + result3;
            assert_eq!(is_result, should_result);
        }
    }

    #[test]
    #[ignore = "This test is a bit slow, so ignore by default"]
    fn rep3_shared_curve_lut_test() {
        apply_to_all!(rep3_shared_curve_lut_test_t, [u8, u16]);
    }

    fn rep3_write_lut_test_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        for k in 1..T::K {
            let n = 1 << k;
            let lut = (0..n)
                .map(|_| ark_bn254::Fr::rand(&mut rng))
                .collect::<Vec<_>>();
            let x = rng.gen_range::<usize, _>(0..n);
            let x_ = RingElement(T::try_from(x as u64).unwrap());
            let y = ark_bn254::Fr::rand(&mut rng);
            let x_shares = rep3_ring::share_ring_element_binary(x_, &mut rng);
            let lut_shares = rep3::share_field_elements(&lut, &mut rng);
            let y_shares = rep3::share_field_element(y, &mut rng);
            let mut should_result = lut;
            should_result[x] = y;

            let nets = LocalNetwork::new_3_parties();
            let (tx1, rx1) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();
            let (tx3, rx3) = mpsc::channel();

            for (net, tx, x, y, mut lut) in izip!(
                nets,
                [tx1, tx2, tx3],
                x_shares.into_iter(),
                y_shares.into_iter(),
                lut_shares.into_iter()
            ) {
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                    gadgets::lut_field::write_lut(&y, &mut lut, x, &net, &mut state).unwrap();
                    tx.send(lut)
                });
            }

            let result1 = rx1.recv().unwrap();
            let result2 = rx2.recv().unwrap();
            let result3 = rx3.recv().unwrap();
            let is_result = rep3::combine_field_elements(&result1, &result2, &result3);
            assert_eq!(is_result, should_result);
        }
    }

    #[test]
    fn rep3_write_lut_test() {
        apply_to_all!(rep3_write_lut_test_t, [u8, u16]);
    }
    fn rep3_write_curve_lut_test_t<T: IntRing2k>()
    where
        Standard: Distribution<T>,
    {
        let mut rng = thread_rng();
        for k in 1..T::K {
            let n = 1 << k;
            let lut = (0..n)
                .map(|_| ark_bn254::G1Projective::rand(&mut rng))
                .collect::<Vec<_>>();
            let x = rng.gen_range::<usize, _>(0..n);
            let x_ = RingElement(T::try_from(x as u64).unwrap());
            let y = ark_bn254::G1Projective::rand(&mut rng);
            let x_shares = rep3_ring::share_ring_element_binary(x_, &mut rng);
            let lut_shares = rep3::share_curve_points(&lut, &mut rng);
            let y_shares = rep3::share_curve_point(y, &mut rng);
            let mut should_result = lut;
            should_result[x] = y;

            let nets = LocalNetwork::new_3_parties();
            let (tx1, rx1) = mpsc::channel();
            let (tx2, rx2) = mpsc::channel();
            let (tx3, rx3) = mpsc::channel();

            for (net, tx, x, y, mut lut) in izip!(
                nets,
                [tx1, tx2, tx3],
                x_shares.into_iter(),
                y_shares.into_iter(),
                lut_shares.into_iter()
            ) {
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();

                    gadgets::lut_curve::write_lut(&y, &mut lut, x, &net, &mut state).unwrap();
                    tx.send(lut)
                });
            }

            let result1 = rx1.recv().unwrap();
            let result2 = rx2.recv().unwrap();
            let result3 = rx3.recv().unwrap();
            let is_result = rep3::combine_curve_points(&result1, &result2, &result3);
            assert_eq!(is_result, should_result);
        }
    }

    #[test]
    fn rep3_write_curve_lut_test() {
        apply_to_all!(rep3_write_curve_lut_test_t, [u8, u16]);
    }
}

/// The lookup table provider for tables with only a few entries, where the index has less than two bits.
mod short_lookup_tables {
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};
    use ark_std::UniformRand;
    use itertools::izip;
    use mpc_core::lut::LookupTableProvider;
    use mpc_core::protocols::rep3::{self, conversion::A2BType, Rep3PrimeFieldShare, Rep3State};
    use mpc_core::protocols::rep3_ring::lut_field::{PublicPrivateLut, Rep3FieldLookupTable};
    use mpc_net::local::LocalNetwork;
    use rand::thread_rng;

    type Share = Rep3PrimeFieldShare<Fr>;

    /// What every party computes: the values read from the public LUT, the shared LUT and from two public LUTs at once, the one-hot-encoded vector of the index, and the public and the shared LUT after writing `value` to the index.
    struct Output {
        read_public: Share,
        read_shared: Share,
        read_public_many: Vec<Share>,
        ohv: Vec<Share>,
        written_public: Vec<Share>,
        written_shared: Vec<Share>,
    }

    fn into_shared(lut: PublicPrivateLut<Fr>) -> Vec<Share> {
        match lut {
            PublicPrivateLut::Shared(shares) => shares,
            PublicPrivateLut::Public(_) => panic!("the LUT must be shared after a write"),
        }
    }

    fn run(lut: &[Fr], other_lut: &[Fr], index: usize, value: Fr) -> [Output; 3] {
        let mut rng = thread_rng();
        let index_shares = rep3::share_field_element(Fr::from(index as u64), &mut rng);
        let value_shares = rep3::share_field_element(value, &mut rng);
        let lut_shares = rep3::share_field_elements(lut, &mut rng);

        let threads = izip!(
            LocalNetwork::new_3_parties(),
            index_shares,
            value_shares,
            lut_shares
        )
        .map(|(net, index, value, lut_share)| {
            let (lut, other_lut) = (lut.to_vec(), other_lut.to_vec());
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mut provider = Rep3FieldLookupTable::<Fr>::new();
                let mut public = provider.init_public(lut.clone());
                let mut shared = provider.init_private(lut_share);

                let read_public = provider
                    .get_from_lut(index, &public, &net, &mut state)
                    .unwrap();
                let read_shared = provider
                    .get_from_lut(index, &shared, &net, &mut state)
                    .unwrap();
                let read_public_many = Rep3FieldLookupTable::get_from_public_luts(
                    index,
                    &[lut.clone(), other_lut],
                    &net,
                    &mut state,
                )
                .unwrap();
                let ohv = Rep3FieldLookupTable::ohv_from_index(index, lut.len(), &net, &mut state)
                    .unwrap();
                provider
                    .write_to_lut(index, value, &mut public, &net, &mut state)
                    .unwrap();
                provider
                    .write_to_lut(index, value, &mut shared, &net, &mut state)
                    .unwrap();
                Output {
                    read_public,
                    read_shared,
                    read_public_many,
                    ohv,
                    written_public: into_shared(public),
                    written_shared: into_shared(shared),
                }
            })
        })
        .collect::<Vec<_>>();
        let mut outputs = threads.into_iter().map(|thread| thread.join().unwrap());
        std::array::from_fn(|_| outputs.next().unwrap())
    }

    fn check(len: usize) {
        let mut rng = thread_rng();
        for index in 0..len {
            let lut = (0..len).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let other_lut = (0..len).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let value = Fr::rand(&mut rng);
            let [o0, o1, o2] = run(&lut, &other_lut, index, value);

            let open = |a: Share, b: Share, c: Share| rep3::combine_field_element(a, b, c);
            let open_many =
                |a: &[Share], b: &[Share], c: &[Share]| rep3::combine_field_elements(a, b, c);

            assert_eq!(
                open(o0.read_public, o1.read_public, o2.read_public),
                lut[index]
            );
            assert_eq!(
                open(o0.read_shared, o1.read_shared, o2.read_shared),
                lut[index]
            );
            assert_eq!(
                open_many(
                    &o0.read_public_many,
                    &o1.read_public_many,
                    &o2.read_public_many
                ),
                vec![lut[index], other_lut[index]]
            );

            let mut expected_ohv = vec![Fr::zero(); len];
            expected_ohv[index] = Fr::one();
            let ohv = open_many(&o0.ohv, &o1.ohv, &o2.ohv);
            assert_eq!(&ohv[..len], expected_ohv);
            assert!(ohv[len..].iter().all(|e| e.is_zero()));

            let mut expected_lut = lut.clone();
            expected_lut[index] = value;
            assert_eq!(
                open_many(&o0.written_public, &o1.written_public, &o2.written_public),
                expected_lut
            );
            assert_eq!(
                open_many(&o0.written_shared, &o1.written_shared, &o2.written_shared),
                expected_lut
            );
        }
    }

    #[test]
    fn lut_with_one_entry() {
        check(1);
    }

    #[test]
    fn lut_with_two_entries() {
        check(2);
    }

    #[test]
    fn lut_with_three_entries() {
        check(3);
    }
}
