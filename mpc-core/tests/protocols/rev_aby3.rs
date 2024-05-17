mod field_share {
    use crate::protocols::aby3::Aby3TestNetwork;
    use ark_ff::Field;
    use ark_std::{UniformRand, Zero};
    use mpc_core::protocols::rev_aby3::{self, RevAby3Protocol};
    use mpc_core::traits::PrimeFieldMpcProtocol;
    use rand::thread_rng;
    use std::{collections::HashSet, thread};
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn rev_aby3_add() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rev_aby3::utils::share_field_element(x, &mut rng);
        let y_shares = rev_aby3::utils::share_field_element(y, &mut rng);
        let should_result = x + y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();
                tx.send(aby3.add(&x, &y))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rev_aby3_sub() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rev_aby3::utils::share_field_element(x, &mut rng);
        let y_shares = rev_aby3::utils::share_field_element(y, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();
                tx.send(aby3.sub(&x, &y))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }
    #[tokio::test]
    async fn rev_aby3_mul2_then_add() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let y = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rev_aby3::utils::share_field_element(x, &mut rng);
        let y_shares = rev_aby3::utils::share_field_element(y, &mut rng);
        let should_result = ((x * y) * y) + x;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();
                let mul = aby3.mul(&x, &y).unwrap();
                let mul = aby3.mul(&mul, &y).unwrap();
                tx.send(aby3.add(&mul, &x))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    use std::str::FromStr;
    #[tokio::test]
    async fn rev_aby3_mul_vec_bn() {
        let test_network = Aby3TestNetwork::default();
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
            let [x1, x2, x3] = rev_aby3::utils::share_field_element(*x, &mut rng);
            let [y1, y2, y3] = rev_aby3::utils::share_field_element(*y, &mut rng);
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
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(
                [
                    Vec::from(x_shares1),
                    Vec::from(x_shares2),
                    Vec::from(x_shares3),
                ]
                .into_iter()
                .zip([
                    Vec::from(y_shares1),
                    Vec::from(y_shares2),
                    Vec::from(y_shares3),
                ]),
            )
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();

                let x_slice = &x;
                let y_slice = &y;
                let mul = aby3.mul_vec(&x_slice, &y_slice).unwrap();
                tx.send(mul)
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_field_elements(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rev_aby3_mul_vec() {
        let test_network = Aby3TestNetwork::default();
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
            let [x1, x2, x3] = rev_aby3::utils::share_field_element(*x, &mut rng);
            let [y1, y2, y3] = rev_aby3::utils::share_field_element(*y, &mut rng);
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
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(
                [
                    Vec::from(x_shares1),
                    Vec::from(x_shares2),
                    Vec::from(x_shares3),
                ]
                .into_iter()
                .zip([
                    Vec::from(y_shares1),
                    Vec::from(y_shares2),
                    Vec::from(y_shares3),
                ]),
            )
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();

                let x_slice = &x;
                let y_slice = &y;
                let mul = aby3.mul_vec(&x_slice, &y_slice).unwrap();
                let mul_slice = &mul;
                let mul = aby3.mul_vec(&mul_slice, &y_slice).unwrap();
                tx.send(mul)
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_field_elements(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rev_aby3_neg() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::Fr::rand(&mut rng);
        let x_shares = rev_aby3::utils::share_field_element(x, &mut rng);
        let should_result = -x;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), x) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter())
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();
                tx.send(aby3.neg(&x))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rev_aby3_inv() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let mut x = ark_bn254::Fr::rand(&mut rng);
        while x.is_zero() {
            x = ark_bn254::Fr::rand(&mut rng);
        }
        let x_shares = rev_aby3::utils::share_field_element(x, &mut rng);
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
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();
                tx.send(aby3.inv(&x).unwrap())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_field_element(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rev_aby3_random() {
        let test_network = Aby3TestNetwork::default();
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for (net, tx) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::<ark_bn254::Fr, _>::new(net).unwrap();
                tx.send((0..10).map(|_| aby3.rand().unwrap()).collect::<Vec<_>>())
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        assert_eq!(result1.iter().collect::<HashSet<_>>().len(), 10);
        assert_eq!(result2.iter().collect::<HashSet<_>>().len(), 10);
        assert_eq!(result3.iter().collect::<HashSet<_>>().len(), 10);
    }
}

mod curve_share {
    use ark_std::UniformRand;
    use std::thread;

    use mpc_core::protocols::rev_aby3::{self, RevAby3Protocol};
    use rand::thread_rng;
    use tokio::sync::oneshot;

    use crate::protocols::aby3::Aby3TestNetwork;
    use mpc_core::traits::EcMpcProtocol;

    #[tokio::test]
    async fn rev_aby3_add() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let y = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rev_aby3::utils::share_curve_point(x, &mut rng);
        let y_shares = rev_aby3::utils::share_curve_point(y, &mut rng);
        let should_result = x + y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();
                tx.send(aby3.add_points(&x, &y))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rev_aby3_sub() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let x = ark_bn254::G1Projective::rand(&mut rng);
        let y = ark_bn254::G1Projective::rand(&mut rng);
        let x_shares = rev_aby3::utils::share_curve_point(x, &mut rng);
        let y_shares = rev_aby3::utils::share_curve_point(y, &mut rng);
        let should_result = x - y;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), (x, y)) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(x_shares.into_iter().zip(y_shares))
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();
                tx.send(aby3.sub_points(&x, &y))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rev_aby3_scalar_mul_public_point() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let public_point = ark_bn254::G1Projective::rand(&mut rng);
        let scalar = ark_bn254::Fr::rand(&mut rng);
        let scalar_shares = rev_aby3::utils::share_field_element(scalar, &mut rng);
        let should_result = public_point * scalar;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), scalar) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(scalar_shares.into_iter())
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();
                tx.send(aby3.scalar_mul_public_point(&public_point, &scalar))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }

    #[tokio::test]
    async fn rev_aby3_scalar_mul_public_scalar() {
        let test_network = Aby3TestNetwork::default();
        let mut rng = thread_rng();
        let point = ark_bn254::G1Projective::rand(&mut rng);
        let public_scalar = ark_bn254::Fr::rand(&mut rng);
        let point_shares = rev_aby3::utils::share_curve_point(point, &mut rng);
        let should_result = point * public_scalar;
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();
        for ((net, tx), point) in test_network
            .get_party_networks()
            .into_iter()
            .zip([tx1, tx2, tx3])
            .zip(point_shares.into_iter())
        {
            thread::spawn(move || {
                let mut aby3 = RevAby3Protocol::new(net).unwrap();
                tx.send(aby3.scalar_mul_public_scalar(&point, &public_scalar))
            });
        }
        let result1 = rx1.await.unwrap();
        let result2 = rx2.await.unwrap();
        let result3 = rx3.await.unwrap();
        let is_result = rev_aby3::utils::combine_curve_point(result1, result2, result3);
        assert_eq!(is_result, should_result);
    }
}
