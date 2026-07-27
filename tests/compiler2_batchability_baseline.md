# Compiler2 Rep3 batchability baseline

Measured on 2026-07-27 with:

```sh
cargo run --release -p tests --bin profile_compiler2 -- --no-batching
```

The corpus contains every source with a `component main` under `test_vectors` and
`../benchmarks-co-snarks/circom`. Inputs are tagged shared, execution uses the production
accelerator registry, and reports are weighted by the calls that would communicate in
Rep3. The same-basic-block number is an upper bound before dependency filtering; it does
not assume calls from separate component activations can be combined.

| Metric | All | test_vectors | benchmarks |
|---|---:|---:|---:|
| Discovered circuits | 97 | 70 | 27 |
| Compiled circuits | 97 | 70 | 27 |
| Dynamically traced circuits | 92 | 65 | 27 |
| Interactive driver calls | 5,767,608 | 254,863 | 5,512,745 |
| Scalar calls with a Rep3 vector protocol | 5,530,272 | 137,272 | 5,393,000 |
| Multiplications among those calls | 5,530,253 | 137,253 | 5,393,000 |
| Eq/Neq among those calls | 19 | 19 | 0 |
| Savings from adjacent same-op calls | 0 | 0 | 0 |
| Same-basic-block savings ceiling | 3,653,809 | 118,590 | 3,535,219 |

The ceiling is 66.0% of scalar calls having a vector protocol, but there are no directly
adjacent same-op candidates. A useful pass therefore needs scheduling/levelization;
simple peephole fusion has no measured dynamic yield.

Subcomponent serialization is separately material. For example,
`BatcherOddEvenMergeSortTest1000` executes 47,042 interactive multiplications but has a
zero same-body batching ceiling: they occur across synchronously executed comparator
components. `InsertionSortTest100` similarly executes 9,900 with zero same-body savings.

All 97 circuits now compile. Five test-vector circuits have no usable input file and
therefore contribute only to the static census.

## Adjacent irregular multiplication batches

With post-lowering batching enabled, 52 new `BinBatch` instructions cover 168 formerly
scalar `Mul`/`Mov` pairs. They remove 2,048 dynamic Rep3 driver calls on the corpus (936
in benchmarks and 1,112 in test vectors), reducing the total from 5,767,608 to 5,765,560.
The largest per-circuit reductions are 498 calls for `pedersen_test`, 462/442 for the two
MACI process-message variants, and 254/252 for the two `escalarmul_test` variants.

A broader same-block hoisting experiment covered 1,237 lanes but removed only 29 more
dynamic calls than adjacent-pair fusion. Most added batches contained one communicating
lane plus public work (SHA-256 gained no call reduction), so that version was rejected to
avoid extra allocation and plain-execution overhead.
