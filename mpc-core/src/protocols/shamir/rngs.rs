use std::{cmp::Ordering, sync::Arc};

use ark_ff::PrimeField;
use mpc_net::Network;
use rayon::prelude::*;

use crate::RngType;
use rand::{Rng, SeedableRng};

use super::network::{ShamirNetworkExt, for_each_received, serialize_field_elements};

type SeedType = [u8; crate::SEED_SIZE];

/// The number of batches (of n-t double shares each) that are generated per unit of parallel work.
const BATCHES_PER_CHUNK: usize = 256;

/// Everything that is needed to deal and combine the double sharings, precomputed once.
///
/// As a dealer, a party never interpolates its sharing polynomials. The shares of the other
/// parties, which are not derived from a shared seed, are linear combinations of the seeded
/// shares, so we precompute the corresponding Lagrange basis evaluations.
struct DoubleShareTables<F> {
    /// Maps the t+1 seeded shares of a degree-t sharing to its secret.
    t_secret: Vec<F>,
    /// Maps the t+1 seeded shares of a degree-t sharing to my own share.
    t_mine: Vec<F>,
    /// Maps the t+1 seeded shares of a degree-t sharing to the shares of the parties which
    /// do not share a seeded share with me. One row of t+1 elements per such party.
    t_send: Vec<F>,
    /// Maps the secret and the 2t seeded shares of a degree-2t sharing to my own share.
    two_t_mine: Vec<F>,
    /// Same as `t_send`, but for the degree-2t sharing. One row of 2t+1 elements per party.
    two_t_send: Vec<F>,
    /// The (n-t x n) Vandermonde matrix used by DN07, stored column by column:
    /// [1, 1  , 1  , 1  , ..., 1  ]
    /// [1, 2  , 3  , 4  , ..., n  ]
    /// [1, 2^2, 3^2, 4^2, ..., n^2]
    /// ...
    /// [1, 2^(n-t-1), 3^(n-t-1), 4^(n-t-1), ..., n^(n-t-1)]
    vandermonde: Vec<F>,
    /// The number of rows of the Vandermonde matrix, i.e., n-t
    rows: usize,
}

impl<F: PrimeField> DoubleShareTables<F> {
    fn new(id: usize, num_parties: usize, threshold: usize) -> Self {
        let x_of = |offset: usize| (id + offset) % num_parties + 1;

        // In the degree-t sharing the shares of the next t+1 parties are seeded
        let points_t = (1..=threshold + 1).map(x_of).collect::<Vec<_>>();
        // In the degree-2t sharing the secret is fixed and the shares of the next 2t parties are seeded
        let points_2t = std::iter::once(0)
            .chain((1..=2 * threshold).map(x_of))
            .collect::<Vec<_>>();

        let t_send = (threshold + 2..num_parties)
            .flat_map(|offset| lagrange_basis_at(&points_t, x_of(offset)))
            .collect();
        let two_t_send = (2 * threshold + 1..num_parties)
            .flat_map(|offset| lagrange_basis_at(&points_2t, x_of(offset)))
            .collect();

        let rows = num_parties - threshold;
        let mut vandermonde = Vec::with_capacity(num_parties * rows);
        for col in 1..=num_parties as u64 {
            let x = F::from(col);
            let mut pow = F::one();
            for _ in 0..rows {
                vandermonde.push(pow);
                pow *= x;
            }
        }

        Self {
            t_secret: lagrange_basis_at(&points_t, 0),
            t_mine: lagrange_basis_at(&points_t, id + 1),
            t_send,
            two_t_mine: lagrange_basis_at(&points_2t, id + 1),
            two_t_send,
            vandermonde,
            rows,
        }
    }

    /// The column of the Vandermonde matrix which belongs to the sharing dealt by `party`.
    fn vandermonde_col(&self, party: usize) -> &[F] {
        &self.vandermonde[party * self.rows..(party + 1) * self.rows]
    }
}

/// Evaluates the Lagrange basis polynomials for the interpolation points `points` at `x`.
fn lagrange_basis_at<F: PrimeField>(points: &[usize], x: usize) -> Vec<F> {
    let x = F::from(x as u64);
    points
        .iter()
        .map(|i| {
            let i_f = F::from(*i as u64);
            let mut num = F::one();
            let mut den = F::one();
            for j in points.iter().filter(|j| *j != i) {
                let j_f = F::from(*j as u64);
                num *= x - j_f;
                den *= i_f - j_f;
            }
            num * den.inverse().expect("Interpolation points are distinct")
        })
        .collect()
}

#[inline(always)]
fn dot<F: PrimeField>(a: &[F], b: &[F]) -> F {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(a, b)| *a * b).sum()
}

/// Adds `val` times the Vandermonde column `col` to `acc`.
#[inline(always)]
fn add_scaled_col<F: PrimeField>(acc: &mut [F], col: &[F], val: F) {
    debug_assert_eq!(acc.len(), col.len());
    // The first row of the Vandermonde matrix is all ones
    acc[0] += val;
    for (acc, cell) in acc[1..].iter_mut().zip(col[1..].iter()) {
        *acc += val * cell;
    }
}

/// The randomness stream for the shares which `dealer` deals to `receiver`, restricted to the
/// given chunk of batches. All streams derived from one key are independent, which allows
/// both involved parties to generate them in any order and in parallel.
fn share_stream(
    key: &SeedType,
    dealer: usize,
    receiver: usize,
    double_degree: bool,
    chunk: usize,
) -> RngType {
    let direction = u64::from(dealer > receiver);
    let domain = (u64::from(double_degree) << 1) | direction;
    let mut rng = RngType::from_seed(*key);
    rng.set_stream((domain << 62) | chunk as u64);
    rng
}

pub(super) struct ShamirRng<F> {
    pub(super) id: usize,
    pub(super) rng: RngType,
    pub(super) threshold: usize,
    pub(super) num_parties: usize,
    tables: Arc<DoubleShareTables<F>>,
    pub(super) shared_rngs: Vec<RngType>,
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
        if num_parties < threshold + 2 {
            eyre::bail!("Too few parties for the given threshold")
        }
        let mut rng = RngType::from_seed(seed);

        let shared_rngs = Self::get_shared_rngs(net, num_parties, &mut rng)?;

        // We use the DN07 Vandermonde matrix to create n-t random double shares at once.
        // Each party deals one sharing with a uniformly random secret. Since the matrix has n-t rows and any n-t of its columns are
        // linearly independent, the n-t outputs are uniformly random as long as n-t dealers are honest, i.e., for up to t corrupted parties.
        // We do not use Atlas to create n shares at once, since only n-t out of n shares would be uniformly random, thus the King server during multiplication would have to be rotated.
        let id = net.id();
        let tables = Arc::new(DoubleShareTables::new(id, num_parties, threshold));

        Ok(Self {
            id,
            rng,
            threshold,
            num_parties,
            shared_rngs,
            tables,
            r_t: Vec::new(),
            r_2t: Vec::new(),
        })
    }

    // For DN07 we generate n-t double shares at once, for Atlas it is n
    pub fn get_size_per_batch(&self) -> usize {
        self.num_parties - self.threshold
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
            tables: Arc::clone(&self.tables),
            shared_rngs,
            r_t: self.r_t.drain(..amount).collect(),
            r_2t: self.r_2t.drain(..amount).collect(),
        }
    }

    fn get_shared_rngs<N: Network>(
        net: &N,
        num_parties: usize,
        rng: &mut RngType,
    ) -> eyre::Result<Vec<RngType>> {
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

    // get shared_rng_mut
    fn get_rng_mut(&mut self, other_id: usize) -> &mut RngType {
        match other_id.cmp(&self.id) {
            Ordering::Less => &mut self.shared_rngs[other_id],
            Ordering::Greater => &mut self.shared_rngs[other_id - 1],
            Ordering::Equal => &mut self.rng,
        }
    }

    /// Generates `amount` batches of t+1 random double shares each and appends them to the buffers.
    ///
    /// We use DN07 to generate n-t double shares from the randomness of the n parties.
    /// With Atlas we would be able to expand this to n double shares, but only n-t of them would be uniformly random.
    /// Thus, with Atlas we would have to rotate the King server during multiplication.
    pub(super) fn buffer_triples<N: Network>(
        &mut self,
        net: &N,
        amount: usize,
    ) -> eyre::Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let present = self.r_t.len();
        debug_assert_eq!(self.r_2t.len(), present);
        let res = self.random_double_shares(net, amount);
        if res.is_err() {
            // Do not keep partially computed double shares
            self.r_t.truncate(present);
            self.r_2t.truncate(present);
        }
        res
    }

    /// Every party deals `amount` random double sharings (a degree-t and a degree-2t sharing of
    /// the same random secret), which are then combined to `amount` * (n-t) double sharings with
    /// the Vandermonde matrix.
    ///
    /// In the degree-t sharing of a dealer the shares of the next t+1 parties are derived from
    /// seeds shared with these parties, which defines the secret and the remaining shares. In
    /// the degree-2t sharing the shares of the next 2t parties are derived from the seeds.
    /// Only the remaining shares need to be sent.
    fn random_double_shares<N: Network>(&mut self, net: &N, amount: usize) -> eyre::Result<()> {
        let id = self.id;
        let n = self.num_parties;
        let t = self.threshold;
        // The number of double shares per batch
        let size = n - t;
        // The number of seeded shares in a degree-t sharing
        let num_seeded_t = t + 1;
        // The number of parties to which I need to send shares / from which I receive shares
        let num_sent_t = n - t - 2;
        let num_sent_2t = n - 2 * t - 1;

        // Derive a fresh key from each shared rng. All values of this call are derived from
        // these keys, each (dealer, receiver, degree, chunk) combination with its own stream.
        let keys = (0..n)
            .map(|other| match other == id {
                true => SeedType::default(), // Never used
                false => self.get_rng_mut(other).r#gen(),
            })
            .collect::<Vec<SeedType>>();
        let tables = Arc::clone(&self.tables);

        let present = self.r_t.len();
        self.r_t.resize(present + amount * size, F::zero());
        self.r_2t.resize(present + amount * size, F::zero());
        let r_t = &mut self.r_t[present..];
        let r_2t = &mut self.r_2t[present..];
        // Stored batch by batch
        let mut send_t = vec![F::zero(); amount * num_sent_t];
        let mut send_2t = vec![F::zero(); amount * num_sent_2t];

        // Deals my sharings for one chunk of batches and already accumulates all shares I know
        // without communication (my own and the seeded ones) into the result.
        let deal_chunk = |chunk: usize,
                          r_t: &mut [F],
                          r_2t: &mut [F],
                          send_t: &mut [F],
                          send_2t: &mut [F]| {
            let streams = |offsets: std::ops::RangeInclusive<usize>, double_degree: bool| {
                let dealt = offsets
                    .clone()
                    .map(|i| {
                        let receiver = (id + i) % n;
                        share_stream(&keys[receiver], id, receiver, double_degree, chunk)
                    })
                    .collect::<Vec<_>>();
                let received = offsets
                    .map(|i| {
                        let dealer = (id + n - i) % n;
                        let rng = share_stream(&keys[dealer], dealer, id, double_degree, chunk);
                        (rng, tables.vandermonde_col(dealer))
                    })
                    .collect::<Vec<_>>();
                (dealt, received)
            };
            let (mut dealt_t, mut received_t) = streams(1..=t + 1, false);
            let (mut dealt_2t, mut received_2t) = streams(1..=2 * t, true);
            let my_col = tables.vandermonde_col(id);

            let mut send_t = send_t.iter_mut();
            let mut send_2t = send_2t.iter_mut();
            let mut points = vec![F::zero(); 2 * t + 1];
            for (r_t, r_2t) in r_t.chunks_exact_mut(size).zip(r_2t.chunks_exact_mut(size)) {
                // The degree-t sharing
                let seeded = &mut points[..num_seeded_t];
                for (share, rng) in seeded.iter_mut().zip(dealt_t.iter_mut()) {
                    *share = F::rand(rng);
                }
                let secret = dot(&tables.t_secret, seeded);
                add_scaled_col(r_t, my_col, dot(&tables.t_mine, seeded));
                // The coefficients must be the first iterator, otherwise an exhausted zip
                // would consume a share of the next batch
                for (coeffs, share) in tables.t_send.chunks_exact(num_seeded_t).zip(&mut send_t) {
                    *share = dot(coeffs, seeded);
                }
                for (rng, col) in received_t.iter_mut() {
                    add_scaled_col(r_t, col, F::rand(rng));
                }

                // The degree-2t sharing of the same secret
                points[0] = secret;
                for (share, rng) in points[1..].iter_mut().zip(dealt_2t.iter_mut()) {
                    *share = F::rand(rng);
                }
                add_scaled_col(r_2t, my_col, dot(&tables.two_t_mine, &points));
                for (coeffs, share) in tables.two_t_send.chunks_exact(2 * t + 1).zip(&mut send_2t) {
                    *share = dot(coeffs, &points);
                }
                for (rng, col) in received_2t.iter_mut() {
                    add_scaled_col(r_2t, col, F::rand(rng));
                }
            }
        };

        // Split the buffers into the chunks, which are independent of each other
        let num_chunks = amount.div_ceil(BATCHES_PER_CHUNK);
        let mut chunks = Vec::with_capacity(num_chunks);
        let mut rest = (&mut *r_t, &mut *r_2t, &mut send_t[..], &mut send_2t[..]);
        for chunk in 0..num_chunks {
            let batches = BATCHES_PER_CHUNK.min(amount - chunk * BATCHES_PER_CHUNK);
            let (r_t, rest_r_t) = std::mem::take(&mut rest.0).split_at_mut(batches * size);
            let (r_2t, rest_r_2t) = std::mem::take(&mut rest.1).split_at_mut(batches * size);
            let (s_t, rest_s_t) = std::mem::take(&mut rest.2).split_at_mut(batches * num_sent_t);
            let (s_2t, rest_s_2t) = std::mem::take(&mut rest.3).split_at_mut(batches * num_sent_2t);
            chunks.push((chunk, r_t, r_2t, s_t, s_2t));
            rest = (rest_r_t, rest_r_2t, rest_s_t, rest_s_2t);
        }
        if num_chunks == 1 {
            // Not worth involving the thread pool
            for (chunk, r_t, r_2t, s_t, s_2t) in chunks {
                deal_chunk(chunk, r_t, r_2t, s_t, s_2t);
            }
        } else {
            chunks
                .into_par_iter()
                .for_each(|(chunk, r_t, r_2t, s_t, s_2t)| deal_chunk(chunk, r_t, r_2t, s_t, s_2t));
        }

        // Send the shares of my sharings which are not seeded
        for i in 0..num_sent_t {
            let receiver = (id + t + 2 + i) % n;
            let data = serialize_field_elements(amount, |b| send_t[b * num_sent_t + i])?;
            net.send(receiver, data)?;
        }
        for i in 0..num_sent_2t {
            let receiver = (id + 2 * t + 1 + i) % n;
            let data = serialize_field_elements(amount, |b| send_2t[b * num_sent_2t + i])?;
            net.send(receiver, data)?;
        }
        drop((send_t, send_2t));

        // Receive the remaining shares and accumulate them, all dealers of a degree in one pass
        let receive = |seeded: usize, num_received: usize, acc: &mut [F]| -> eyre::Result<()> {
            let dealers = (0..num_received)
                .map(|i| (id + n - (seeded + 1 + i)) % n)
                .collect::<Vec<_>>();
            let received = dealers
                .iter()
                .map(|dealer| net.recv(*dealer))
                .collect::<eyre::Result<Vec<_>>>()?;
            for_each_received(&received, acc, size, |acc, msg, share| {
                add_scaled_col(acc, tables.vandermonde_col(dealers[msg]), share)
            })
        };
        receive(t + 1, num_sent_t, r_t)?;
        receive(2 * t, num_sent_2t, r_2t)?;

        Ok(())
    }
}
