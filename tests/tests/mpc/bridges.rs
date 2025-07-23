mod translate_share {
    use ark_std::UniformRand;
    use itertools::Itertools;
    use mpc_core::protocols::{
        rep3::{self, id::PartyID},
        shamir::{self, ShamirState},
    };
    use rand::thread_rng;
    use std::{sync::mpsc, thread};

    const VEC_SIZE: usize = 10;

    #[test]
    fn fieldshare() {
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rep3::share_field_element(x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (i, (tx, x)) in [tx1, tx2, tx3]
            .into_iter()
            .zip(x_shares.into_iter())
            .enumerate()
        {
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
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (i, (tx, x)) in [tx1, tx2, tx3]
            .into_iter()
            .zip(x_shares.into_iter())
            .enumerate()
        {
            thread::spawn(move || {
                let share = ShamirState::translate_primefield_repshare_vec(
                    x,
                    PartyID::try_from(i).unwrap(),
                );
                tx.send(share)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result0 = shamir::combine_field_elements(
            &[result1.clone(), result2.clone()],
            &(1..3).collect_vec(),
            1,
        )
        .unwrap();
        let is_result1 =
            shamir::combine_field_elements(&[result2, result3.clone()], &(2..=3).collect_vec(), 1)
                .unwrap();
        let is_result2 = shamir::combine_field_elements(&[result1, result3], &[1, 3], 1).unwrap();

        assert_eq!(is_result0, x);
        assert_eq!(is_result1, x);
        assert_eq!(is_result2, x);
    }

    #[test]
    fn pointshare() {
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rep3::share_curve_point(x, &mut rng);
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let (tx3, rx3) = mpsc::channel();
        for (i, (tx, x)) in [tx1, tx2, tx3]
            .into_iter()
            .zip(x_shares.into_iter())
            .enumerate()
        {
            thread::spawn(move || {
                let share = ShamirState::translate_point_repshare(x, PartyID::try_from(i).unwrap());
                tx.send(share)
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result0 = shamir::combine_curve_point(
            &[result1.clone(), result2.clone()],
            &(1..3).collect_vec(),
            1,
        )
        .unwrap();
        let is_result1 =
            shamir::combine_curve_point(&[result2, result3.clone()], &(2..=3).collect_vec(), 1)
                .unwrap();
        let is_result2 = shamir::combine_curve_point(&[result1, result3], &[1, 3], 1).unwrap();

        assert_eq!(is_result0, x);
        assert_eq!(is_result1, x);
        assert_eq!(is_result2, x);
    }
}
