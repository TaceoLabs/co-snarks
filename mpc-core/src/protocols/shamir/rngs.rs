use std::cmp::Ordering;

use ark_ff::PrimeField;
use itertools::{Itertools, izip};
use mpc_net::Network;

use crate::{RngType, protocols::shamir::interpolate_poly_from_precomputed};
use rand::{Rng, SeedableRng};

use super::{evaluate_poly, network::ShamirNetworkExt, precompute_interpolation_polys};

pub(super) struct ShamirRng<F> {
    pub(super) id: usize,
    pub(super) rng: RngType,
    pub(super) threshold: usize,
    pub(super) num_parties: usize,
    precomputed_interpolation_r_t: Vec<Vec<F>>,
    precomputed_interpolation_r_2t: Vec<Vec<F>>,
    pub(super) shared_rngs: Vec<RngType>,
    pub(super) matrix: Vec<Vec<F>>,
    pub(super) r_t: Vec<F>,
    pub(super) r_2t: Vec<F>,
}

impl<F: PrimeField> ShamirRng<F> {
    pub fn new<N: Network>(
        seed: [u8; crate::SEED_SIZE],
        num_parties: usize,
        threshold: usize,
        net: &N,
    ) -> eyre::Result<Self> {
        let mut rng = RngType::from_seed(seed);

        let shared_rngs = Self::get_shared_rngs(net, num_parties, &mut rng)?;

        // We use the DN07 Vandermonde matrix to create t+1 random double shares at once.
        // We do not use Atlas to create n shares at once, since only t+1 out of n shares would be uniformly random, thus the King server during multiplication would have to be rotated.

        // let atlas_dn_matrix = Self::generate_atlas_dn_matrix(num_parties, threshold);
        let matrix = Self::create_vandermonde_matrix(num_parties, threshold);

        let id = net.id();
        let mut ids = Vec::with_capacity(threshold + 1);
        for i in 1..=threshold + 1 {
            let id_ = (id + i) % num_parties + 1;
            ids.push(id_);
        }
        let precomputed_interpolation_r_t = precompute_interpolation_polys::<F>(&ids);

        // let p_r_t = Self::precompute_interpolation_polys(id, threshold + 1, num_parties);
        let precomputed_interpolation_r_2t =
            Self::precompute_interpolation_polys(id, threshold * 2, num_parties);

        Ok(Self {
            id,
            rng,
            threshold,
            num_parties,
            shared_rngs,
            precomputed_interpolation_r_t,
            precomputed_interpolation_r_2t,
            matrix,
            r_t: Vec::new(),
            r_2t: Vec::new(),
        })
    }

    // For DN07 we generate t+1 double shares at once, for Atlas it is n
    pub fn get_size_per_batch(&self) -> usize {
        self.matrix.len()
    }

    /// Create a forked [`ShamirRng`] that consumes `amount` number of corr rand pairs from its parent
    pub(super) fn fork_with_pairs(&mut self, amount: usize) -> Self {
        let rng = RngType::from_seed(self.rng.r#gen());
        let mut shared_rngs = Vec::with_capacity(self.shared_rngs.len());
        for rng in self.shared_rngs.iter_mut() {
            shared_rngs.push(RngType::from_seed(rng.r#gen()));
        }
        // TODO return err? pass in net and generate more?
        if amount > self.r_t.len() {
            panic!("not enough corr rand pairs");
        }
        Self {
            id: self.id,
            rng,
            threshold: self.threshold,
            num_parties: self.num_parties,
            precomputed_interpolation_r_t: self.precomputed_interpolation_r_t.clone(),
            precomputed_interpolation_r_2t: self.precomputed_interpolation_r_2t.clone(),
            shared_rngs,
            matrix: self.matrix.clone(),
            r_t: self.r_t.drain(..amount).collect(),
            r_2t: self.r_2t.drain(..amount).collect(),
        }
    }

    fn get_shared_rngs<N: Network>(
        net: &N,
        num_parties: usize,
        rng: &mut RngType,
    ) -> eyre::Result<Vec<RngType>> {
        type SeedType = [u8; crate::SEED_SIZE];
        let id = net.id();

        let mut rngs = Vec::with_capacity(num_parties - 1);
        let mut seeds = vec![<SeedType>::default(); num_parties];
        let to_interact_with_parties = num_parties - 1;

        let mut send = to_interact_with_parties / 2;
        if to_interact_with_parties & 1 == 1 && id < num_parties / 2 {
            send += 1;
        }
        let receive = to_interact_with_parties - send;
        for id_off in 1..=send {
            let rcv_id = (id + id_off) % num_parties;
            let seed: SeedType = rng.r#gen();
            seeds[rcv_id] = seed;
            net.send_to(rcv_id, seed)?;
        }
        for id_off in 1..=receive {
            let send_id = (id + num_parties - id_off) % num_parties;
            let seed = net.recv_from(send_id)?;
            seeds[send_id] = seed;
        }

        let after = seeds.split_off(id);
        for seed in seeds {
            debug_assert_ne!(seed, SeedType::default());
            rngs.push(RngType::from_seed(seed));
        }
        debug_assert_eq!(after[0], SeedType::default());
        for seed in after.into_iter().skip(1) {
            debug_assert_ne!(seed, SeedType::default());
            rngs.push(RngType::from_seed(seed));
        }

        Ok(rngs)
    }

    // We use the following (t+1 x n) Vandermonde matrix for DN07:
    // [1, 1  , 1  , 1  , ..., 1  ]
    // [1, 2  , 3  , 4  , ..., n  ]
    // [1, 2^2, 3^2, 4^2, ..., n^2]
    // ...
    // [1, 2^t, 3^t, 4^t, ..., n^t]
    fn create_vandermonde_matrix(num_parties: usize, threshold: usize) -> Vec<Vec<F>> {
        let mut result = Vec::with_capacity(threshold + 1);
        let first_row = vec![F::one(); num_parties];
        result.push(first_row);
        for row in 1..=threshold {
            let tmp = (1..=num_parties as u64)
                .map(|col| F::from(col).pow([row as u64]))
                .collect::<Vec<_>>();
            result.push(tmp);
        }
        result
    }

    // We use the following (t+1 x n) Vandermonde matrix for DN07:
    // [1, 1  , 1  , 1  , ..., 1  ]
    // [1, 2  , 3  , 4  , ..., n  ]
    // [1, 2^2, 3^2, 4^2, ..., n^2]
    // ...
    // [1, 2^t, 3^t, 4^t, ..., n^t]

    // We use the following (n x t+1) Vandermonde matrix for Atlas:
    // [1, 1  , 1  , 1  , ..., 1  ]
    // [1, 2  , 3  , 4  , ..., t  ]
    // [1, 2^2, 3^2, 4^2, ..., t^2]
    // ...
    // [1, 2^n, 3^n, 4^n, ..., t^n]

    // This gives the resulting (n x n) matrix = Atlas x DN07: Each cell (row, col) has the value: sum_{i=0}^{t} (i + 1) ^ row * (col + 1) ^ i
    #[expect(dead_code)]
    fn generate_atlas_dn_matrix(num_parties: usize, threshold: usize) -> Vec<Vec<F>> {
        let mut result = Vec::with_capacity(num_parties);
        for row in 0..num_parties {
            let mut row_result = Vec::with_capacity(num_parties);
            for col in 0..num_parties {
                let mut val = F::zero();
                for i in 0..=threshold {
                    val += F::from(i as u64 + 1).pow([row as u64])
                        * F::from(col as u64 + 1).pow([i as u64]);
                }
                row_result.push(val);
            }
            result.push(row_result);
        }

        result
    }

    fn matmul(mat: &[Vec<F>], inp: &[F], outp: &mut [F]) {
        debug_assert_eq!(outp.len(), mat.len());
        for (res, row) in outp.iter_mut().zip(mat.iter()) {
            debug_assert_eq!(row.len(), inp.len());
            for (v, cell) in inp.iter().cloned().zip(row.iter()) {
                *res += v * cell;
            }
        }
    }

    // get shared_rng_mut
    fn get_rng_mut(&mut self, other_id: usize) -> &mut RngType {
        match other_id.cmp(&self.id) {
            Ordering::Less => &mut self.shared_rngs[other_id],
            Ordering::Greater => &mut self.shared_rngs[other_id - 1],
            Ordering::Equal => &mut self.rng,
        }
    }

    fn receive_seeded_prev(&mut self, degree: usize, output: &mut [Vec<F>]) {
        for i in 1..=degree {
            let send_id = (self.id + self.num_parties - i) % self.num_parties;
            if send_id > self.id {
                continue;
            }
            let rng = self.get_rng_mut(send_id);
            for r in output.iter_mut() {
                r[send_id] = F::rand(rng);
            }
        }
    }

    fn receive_seeded_next(&mut self, degree: usize, output: &mut [Vec<F>]) {
        for i in 1..=degree {
            let send_id = (self.id + self.num_parties - i) % self.num_parties;
            if send_id < self.id {
                continue;
            }
            let rng = self.get_rng_mut(send_id);
            for r in output.iter_mut() {
                r[send_id] = F::rand(rng);
            }
        }
    }

    fn precompute_interpolation_polys(id: usize, degree: usize, num_parties: usize) -> Vec<Vec<F>> {
        let mut ids = Vec::with_capacity(degree + 1);
        ids.push(0); // my randomness acts as the secret
        for i in 1..=degree {
            let rcv_id = (id + i) % num_parties;
            ids.push(rcv_id + 1);
        }
        precompute_interpolation_polys::<F>(&ids)
    }

    fn get_interpolation_polys_from_precomputed<const T: bool>(
        &mut self,
        my_rands: &[F],
        degree: usize,
    ) -> Vec<Vec<F>> {
        let amount = my_rands.len();
        let mut shares = (0..amount)
            .map(|_| Vec::with_capacity(degree + 1))
            .collect_vec();
        // Put secret to first place of shares
        for (s, r) in shares.iter_mut().zip(my_rands.iter()) {
            s.push(*r);
        }
        for i in 1..=degree {
            let rcv_id = (self.id + i) % self.num_parties;
            let rng = self.get_rng_mut(rcv_id);
            for s in shares.iter_mut() {
                s.push(F::rand(rng));
            }
        }

        let precomputed = if T {
            &self.precomputed_interpolation_r_t
        } else {
            &self.precomputed_interpolation_r_2t
        };
        debug_assert_eq!(precomputed.len(), degree + 1);

        // Interpolate polys
        shares
            .into_iter()
            .map(|s| interpolate_poly_from_precomputed::<F>(&s, precomputed))
            .collect_vec()
    }

    fn set_my_share(&self, output: &mut [Vec<F>], polys: &[Vec<F>]) {
        let id_f = F::from(self.id as u64 + 1);
        for (r, p) in output.iter_mut().zip(polys.iter()) {
            r[self.id] = evaluate_poly(p, id_f);
        }
    }

    fn send_share_of_randomness<N: Network>(
        &self,
        seeded: usize,
        polys: &[Vec<F>],
        net: &N,
    ) -> eyre::Result<()> {
        let sending = self.num_parties - seeded - 1;
        if sending == 0 {
            return Ok(());
        }
        let mut to_send = vec![F::zero(); polys.len()]; // Allocate buffer only once
        for i in 1..=sending {
            let rcv_id = (self.id + i + seeded) % self.num_parties;
            let rcv_id_f = F::from(rcv_id as u64 + 1);
            for (des, p) in to_send.iter_mut().zip(polys.iter()) {
                *des = evaluate_poly(p, rcv_id_f);
            }
            net.send_many(rcv_id, &to_send)?;
        }
        Ok(())
    }

    fn receive_share_of_randomness<N: Network>(
        &self,
        seeded: usize,
        output: &mut [Vec<F>],
        net: &N,
    ) -> eyre::Result<()> {
        let receiving = self.num_parties - seeded - 1;
        if receiving == 0 {
            return Ok(());
        }
        for i in 1..=receiving {
            let send_id = (self.id + self.num_parties - seeded - i) % self.num_parties;
            let shares = net.recv_many(send_id)?;
            for (r, s) in output.iter_mut().zip(shares.iter()) {
                r[send_id] = *s;
            }
        }
        Ok(())
    }

    #[expect(clippy::type_complexity)]
    fn random_double_share<N: Network>(
        &mut self,
        amount: usize,
        net: &N,
    ) -> eyre::Result<(Vec<Vec<F>>, Vec<Vec<F>>)> {
        let mut rcv_t = vec![vec![F::default(); self.num_parties]; amount];
        let mut rcv_2t = vec![vec![F::default(); self.num_parties]; amount];

        // These are the parties for which I act as a receiver using the seeds
        // Be careful about the order of calling the rngs
        self.receive_seeded_next(self.threshold + 1, &mut rcv_t);

        // Generate the seeds
        let mut shares = (0..amount)
            .map(|_| vec![F::zero(); self.threshold + 1])
            .collect_vec();
        for i in 1..=self.threshold + 1 {
            let rcv_id = (self.id + i) % self.num_parties;
            let rng = self.get_rng_mut(rcv_id);
            for s in shares.iter_mut() {
                s[i - 1] = F::rand(rng);
            }
        }

        // Receive the remaining now to clock rngs in the correct order
        self.receive_seeded_prev(self.threshold + 1, &mut rcv_t);

        // Interpolate polys
        let polys_t = shares
            .into_iter()
            .map(|s| {
                interpolate_poly_from_precomputed::<F>(&s, &self.precomputed_interpolation_r_t)
            })
            .collect_vec();

        // Set my rand on the polynomial and calculate the share
        let mut rands = Vec::with_capacity(amount);
        for (r, p) in rcv_t.iter_mut().zip(polys_t.iter()) {
            r[self.id] = evaluate_poly(p, F::from(self.id as u64 + 1));
            rands.push(p[0]);
        }

        // Do the same for rcv_2t (do afterwards due to seeds being used here)
        // Be careful about the order of calling the rngs
        self.receive_seeded_next(self.threshold * 2, &mut rcv_2t);
        let polys_2t =
            self.get_interpolation_polys_from_precomputed::<false>(&rands, self.threshold * 2);
        self.receive_seeded_prev(self.threshold * 2, &mut rcv_2t);

        // Set my share
        self.set_my_share(&mut rcv_2t, &polys_2t);

        // Send the share of my randomness
        self.send_share_of_randomness(self.threshold + 1, &polys_t, net)?;
        self.send_share_of_randomness(self.threshold * 2, &polys_2t, net)?;

        // Receive the remaining shares
        self.receive_share_of_randomness(self.threshold + 1, &mut rcv_t, net)?;
        self.receive_share_of_randomness(self.threshold * 2, &mut rcv_2t, net)?;

        Ok((rcv_t, rcv_2t))
    }

    // Generates amount * matrix.len() random double shares
    // We use DN07 to generate t+1 double shares from the randomness of the n parties.
    // With Atlas we would be able to expand this to n double shares, but only t+1 of them would be uniformly random.
    // Thus, with Atlas we would have to rotate the King server during multiplication.
    pub(super) fn buffer_triples<N: Network>(
        &mut self,
        net: &N,
        amount: usize,
    ) -> eyre::Result<()> {
        let (rcv_rt, rcv_r2t) = self.random_double_share(amount, net)?;

        // reserve buffer
        let size = self.matrix.len();
        let mut r_t = vec![F::default(); amount * size];
        let mut r_2t = vec![F::default(); amount * size];

        // Now make the matrix multiplication
        let r_t_chunks = r_t.chunks_exact_mut(size);
        let r_2t_chunks = r_2t.chunks_exact_mut(size);

        for (des, src) in izip!(r_t_chunks, rcv_rt) {
            Self::matmul(&self.matrix, &src, des);
        }
        for (des, src) in izip!(r_2t_chunks, rcv_r2t) {
            Self::matmul(&self.matrix, &src, des);
        }

        self.r_t.extend(r_t);
        self.r_2t.extend(r_2t);

        Ok(())
    }
}
