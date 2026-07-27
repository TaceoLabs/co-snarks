# Compiler2 Rep3 batchability baseline

Measured on 2026-07-27 with:

```sh
cargo run --release -p tests --bin profile_compiler2
```

The corpus contains every source with a `component main` under `test_vectors` and
`../benchmarks-co-snarks/circom`. Inputs are tagged shared, execution uses the production
accelerator registry, and reports are weighted by the calls that would communicate in
Rep3. The same-basic-block number is an upper bound before dependency filtering; it does
not assume calls from separate component activations can be combined.

| Metric | All | test_vectors | benchmarks |
|---|---:|---:|---:|
| Discovered circuits | 97 | 70 | 27 |
| Compiled circuits | 95 | 70 | 25 |
| Dynamically traced circuits | 90 | 65 | 25 |
| Interactive driver calls | 5,756,911 | 256,367 | 5,500,544 |
| Scalar calls with a Rep3 vector protocol | 5,517,752 | 137,272 | 5,380,480 |
| Multiplications among those calls | 5,517,733 | 137,253 | 5,380,480 |
| Eq/Neq among those calls | 19 | 19 | 0 |
| Savings from adjacent same-op calls | 0 | 0 | 0 |
| Same-basic-block savings ceiling | 3,643,848 | 116,959 | 3,526,889 |

The ceiling is 66.0% of scalar calls having a vector protocol, but there are no directly
adjacent same-op candidates. A useful pass therefore needs scheduling/levelization;
simple peephole fusion has no measured dynamic yield.

Subcomponent serialization is separately material. For example,
`BatcherOddEvenMergeSortTest1000` executes 47,042 interactive multiplications but has a
zero same-body batching ceiling: they occur across synchronously executed comparator
components. `InsertionSortTest100` similarly executes 9,900 with zero same-body savings.

The two uncompiled circuits are `semaphore16` and `semaphore30`; both contain a loop in a
potentially shared branch that compiler2 cannot yet prove is statically counted. Five
compiled test-vector circuits have no usable input file and therefore contribute only to
the static census.
