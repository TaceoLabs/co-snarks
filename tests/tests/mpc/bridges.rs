mod translate_share {
    use ark_std::UniformRand;
    use itertools::Itertools;
    use mpc_core::protocols::{
        rep3::{self, id::PartyID},
        shamir::{self, ShamirState},
    };
    use rand::thread_rng;
    use std::{sync::mpsc, thread};

    #[test]
    fn fieldshare() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (i, (tx, x)) in [tx1, tx2, tx3].into_iter().zip(x_shares).enumerate() {
            thread::spawn(move || {
                let share =
                    ShamirState::translate_primefield_repshare(x, PartyID::try_from(i).unwrap());
                tx.send(share)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result0 =
            shamir::combine_field_element(&[result1, result2], &(1..3).collect_vec(), 1).unwrap();
        let is_result1 =
            shamir::combine_field_element(&[result2, result3], &(2..=3).collect_vec(), 1).unwrap();
        let is_result2 = shamir::combine_field_element(&[result1, result3], &[1, 3], 1).unwrap();

        assert_eq!(is_result0, x);
        assert_eq!(is_result1, x);
        assert_eq!(is_result2, x);
    }

    #[test]
    fn fieldshare_vec() {
        let mut rng = thread_rng();
        for size in [0, 10, 4095, 4096, 16384] {
            let secrets = (0..size)
                .map(|_| ark_bn254::Fr::rand(&mut rng))
                .collect_vec();
            let rep3_shares = rep3::share_field_elements(&secrets, &mut rng);
            let mut translated = Vec::with_capacity(3);

            for (party, shares) in rep3_shares.into_iter().enumerate() {
                let id = PartyID::try_from(party).unwrap();
                let expected = shares
                    .iter()
                    .map(|share| ShamirState::translate_primefield_repshare(*share, id))
                    .collect_vec();
                let actual = ShamirState::translate_primefield_repshare_vec(shares, id);

                assert_eq!(
                    actual, expected,
                    "translation mismatch for party {party}, size {size}"
                );
                translated.push(actual);
            }

            for (parties, points) in [([0, 1], [1, 2]), ([1, 2], [2, 3]), ([0, 2], [1, 3])] {
                let reconstructed = shamir::combine_field_elements(
                    &[
                        translated[parties[0]].clone(),
                        translated[parties[1]].clone(),
                    ],
                    &points,
                    1,
                )
                .unwrap();
                assert_eq!(
                    reconstructed, secrets,
                    "reconstruction mismatch for size {size}"
                );
            }
        }
    }

    #[test]
    fn pointshare() {
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rep3::share_curve_point(x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (i, (tx, x)) in [tx1, tx2, tx3].into_iter().zip(x_shares).enumerate() {
            thread::spawn(move || {
                let share = ShamirState::translate_point_repshare(x, PartyID::try_from(i).unwrap());
                tx.send(share)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result0 =
            shamir::combine_curve_point(&[result1, result2], &(1..3).collect_vec(), 1).unwrap();
        let is_result1 =
            shamir::combine_curve_point(&[result2, result3], &(2..=3).collect_vec(), 1).unwrap();
        let is_result2 = shamir::combine_curve_point(&[result1, result3], &[1, 3], 1).unwrap();

        assert_eq!(is_result0, x);
        assert_eq!(is_result1, x);
        assert_eq!(is_result2, x);
    }
}
