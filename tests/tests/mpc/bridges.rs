mod translate_share {
    use ark_std::UniformRand;
    use itertools::Itertools;
    use mpc_core::protocols::{
        bridges::network::RepToShamirNetwork,
        rep3::{self},
        shamir::{self, ShamirPreprocessing, ShamirProtocol},
    };
    use rand::thread_rng;
    use std::{sync::mpsc, thread};
    use tests::rep3_network::Rep3TestNetwork;

    const VEC_SIZE: usize = 10;

    #[test]
    fn fieldshare() {
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
                let preprocessing = ShamirPreprocessing::new(1, net.to_shamir_net(), 1).unwrap();
                let mut shamir = ShamirProtocol::from(preprocessing);
                let share = shamir.translate_primefield_repshare(x);
                tx.send(share.unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result =
            shamir::combine_field_element(&[result1, result2, result3], &(1..=3).collect_vec(), 1)
                .unwrap();

        assert_eq!(is_result, x);
    }

    #[test]
    fn fieldshare_vec() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut rng))
            .collect_vec();
        let x_shares = rep3::share_field_elements(&x, &mut rng);
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
                let preprecessing =
                    ShamirPreprocessing::new(1, net.to_shamir_net(), x.len()).unwrap();
                let mut shamir = ShamirProtocol::from(preprecessing);
                let share = shamir.translate_primefield_repshare_vec(x);
                tx.send(share.unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result =
            shamir::combine_field_elements(&[result1, result2, result3], &(1..=3).collect_vec(), 1)
                .unwrap();

        assert_eq!(is_result, x);
    }

    #[test]
    fn pointshare() {
        let test_network = Rep3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rep3::share_curve_point(x, &mut rng);
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
                let preprecessing = ShamirPreprocessing::new(1, net.to_shamir_net(), 1).unwrap();
                let mut shamir = ShamirProtocol::from(preprecessing);
                let share = shamir.translate_point_repshare(x);
                tx.send(share.unwrap())
            });
        }
        let result1 = rx1.recv().unwrap();
        let result2 = rx2.recv().unwrap();
        let result3 = rx3.recv().unwrap();

        let is_result =
            shamir::combine_curve_point(&[result1, result2, result3], &(1..=3).collect_vec(), 1)
                .unwrap();

        assert_eq!(is_result, x);
    }
}
