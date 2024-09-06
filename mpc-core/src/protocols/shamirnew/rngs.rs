use ark_ff::PrimeField;
use itertools::{izip, Itertools};

use crate::RngType;
use rand::SeedableRng;

use super::network::ShamirNetwork;

pub(super) struct ShamirRng<F> {
    pub(super) rng: RngType,
    pub(super) threshold: usize,
    pub(super) num_parties: usize,
    pub(super) r_t: Vec<F>,
    pub(super) r_2t: Vec<F>,
    pub(super) remaining: usize,
}

impl<F: PrimeField> ShamirRng<F> {
    const BATCH_SIZE: usize = 1024;

    pub fn new(seed: [u8; crate::SEED_SIZE], threshold: usize, num_parties: usize) -> Self {
        let r_t = Vec::with_capacity(Self::BATCH_SIZE * (threshold + 1));
        let r_2t = Vec::with_capacity(Self::BATCH_SIZE * (threshold + 1));
        Self {
            rng: RngType::from_seed(seed),
            threshold,
            num_parties,
            r_t,
            r_2t,
            remaining: 0,
        }
    }

    // I use the following matrix:
    // [1, 1  , 1  , 1  , ..., 1  ]
    // [1, 2  , 3  , 4  , ..., n  ]
    // [1, 2^2, 3^2, 4^2, ..., n^2]
    // ...
    // [1, 2^t, 3^t, 4^t, ..., n^t]
    fn vandermonde_mul(inputs: &[F], res: &mut [F], num_parties: usize, threshold: usize) {
        debug_assert_eq!(inputs.len(), num_parties);
        debug_assert_eq!(res.len(), threshold + 1);

        let row = (1..=num_parties as u64).map(F::from).collect::<Vec<_>>();
        let mut current_row = row.clone();

        res[0] = inputs.iter().sum();

        for ri in res.iter_mut().skip(1) {
            *ri = F::zero();
            for (c, r, i) in izip!(&mut current_row, &row, inputs) {
                *ri += *c * i;
                *c *= r; // Update current_row
            }
        }
    }

    // Generates amount * (self.threshold + 1) random double shares
    pub(super) async fn buffer_triples<N: ShamirNetwork>(
        &mut self,
        network: &mut N,
        amount: usize,
    ) -> std::io::Result<()> {
        debug_assert_eq!(self.remaining, self.r_t.len());
        debug_assert_eq!(self.remaining, self.r_2t.len());

        let rand = (0..amount)
            .map(|_| F::rand(&mut self.rng))
            .collect::<Vec<_>>();

        let mut send = (0..self.num_parties)
            .map(|_| Vec::with_capacity(amount * 2))
            .collect::<Vec<_>>();

        for r in rand {
            let shares_t = super::core::share(r, self.num_parties, self.threshold, &mut self.rng);
            let shares_2t =
                super::core::share(r, self.num_parties, 2 * self.threshold, &mut self.rng);

            for (des, src1, src2) in izip!(&mut send, shares_t, shares_2t) {
                des.push(src1);
                des.push(src2);
            }
        }

        let my_id = network.get_id();
        let mut my_send = Vec::new();
        // Send
        for (other_id, shares) in send.into_iter().enumerate() {
            if my_id == other_id {
                my_send = shares;
            } else {
                network.send_many(other_id, &shares).await?;
            }
        }
        // Receive
        let mut rcv_rt = (0..amount)
            .map(|_| Vec::with_capacity(self.num_parties))
            .collect_vec();
        let mut rcv_r2t = (0..amount)
            .map(|_| Vec::with_capacity(self.num_parties))
            .collect_vec();

        for other_id in 0..self.num_parties {
            if my_id == other_id {
                for (des_r, des_r2, src) in
                    izip!(&mut rcv_rt, &mut rcv_r2t, my_send.chunks_exact(2))
                {
                    des_r.push(src[0]);
                    des_r2.push(src[1]);
                }
            } else {
                let r = network.recv_many::<F>(other_id).await?;
                if r.len() != 2 * amount {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "During execution of buffer_triples in MPC: Invalid number of elements received",
                    ));
                }
                for (des_r, des_r2, src) in izip!(&mut rcv_rt, &mut rcv_r2t, r.chunks_exact(2)) {
                    des_r.push(src[0]);
                    des_r2.push(src[1]);
                }
            }
        }

        // reserve buffer
        self.r_t
            .resize(self.remaining + amount * (self.threshold + 1), F::default());
        self.r_2t
            .resize(self.remaining + amount * (self.threshold + 1), F::default());

        // Now make vandermonde multiplication
        let r_t_chunks = self.r_t[self.remaining..].chunks_exact_mut(self.threshold + 1);
        let r_2t_chunks = self.r_2t[self.remaining..].chunks_exact_mut(self.threshold + 1);

        for (r_t_des, r_2t_des, r_t_src, r_2t_src) in
            izip!(r_t_chunks, r_2t_chunks, rcv_rt, rcv_r2t)
        {
            Self::vandermonde_mul(&r_t_src, r_t_des, self.num_parties, self.threshold);
            Self::vandermonde_mul(&r_2t_src, r_2t_des, self.num_parties, self.threshold);
        }
        self.remaining += amount * (self.threshold + 1);

        Ok(())
    }

    pub(super) async fn get_pair<N: ShamirNetwork>(
        &mut self,
        network: &mut N,
    ) -> std::io::Result<(F, F)> {
        if self.remaining == 0 {
            self.buffer_triples(network, Self::BATCH_SIZE).await?;
            debug_assert_eq!(self.remaining, Self::BATCH_SIZE * (self.threshold + 1));
            debug_assert_eq!(self.r_t.len(), Self::BATCH_SIZE * (self.threshold + 1));
            debug_assert_eq!(self.r_2t.len(), Self::BATCH_SIZE * (self.threshold + 1));
        }

        let r1 = self.r_t.pop().unwrap();
        let r2 = self.r_2t.pop().unwrap();
        self.remaining -= 1;
        Ok((r1, r2))
    }
}
