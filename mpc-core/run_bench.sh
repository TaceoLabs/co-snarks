#!/bin/sh
BENCHES_NUM_THREADS=1 cargo bench > bench.log
BENCHES_NUM_THREADS=2 cargo bench >> bench.log
BENCHES_NUM_THREADS=3 cargo bench >> bench.log
BENCHES_NUM_THREADS=4 cargo bench >> bench.log
BENCHES_NUM_THREADS=6 cargo bench >> bench.log
BENCHES_NUM_THREADS=8 cargo bench >> bench.log
BENCHES_NUM_THREADS=10 cargo bench >> bench.log
BENCHES_NUM_THREADS=12 cargo bench >> bench.log
BENCHES_NUM_THREADS=16 cargo bench >> bench.log
BENCHES_NUM_THREADS=20 cargo bench >> bench.log
BENCHES_NUM_THREADS=24 cargo bench >> bench.log
BENCHES_NUM_THREADS=28 cargo bench >> bench.log
BENCHES_NUM_THREADS=32 cargo bench >> bench.log
BENCHES_NUM_THREADS=36 cargo bench >> bench.log
BENCHES_NUM_THREADS=40 cargo bench >> bench.log
BENCHES_NUM_THREADS=44 cargo bench >> bench.log
