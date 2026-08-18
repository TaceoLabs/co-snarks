# Frequently Asked Questions (FAQ)

Complete guide to common questions about coCircom and coNoir.

---

## Table of Contents

- [General Questions](#general-questions)
- [Installation & Setup](#installation--setup)
- [Usage & Development](#usage--development)
- [Architecture & Technical](#architecture--technical)
- [Performance & Optimization](#performance--optimization)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## General Questions

### What are coSNARKs?

Collaborative SNARKs (coSNARKs) are a technology that enables multiple distrusting parties to jointly compute a zero-knowledge proof without revealing their private inputs. They combine Multi-Party Computation (MPC) with zkSNARKs to enable privacy-preserving collaborative computation.

### What's the difference between coCircom and coNoir?

- **coCircom**: Works with Circom circuits and is compatible with snarkjs (Groth16 and Plonk backends)
- **coNoir**: Works with Noir circuits and is compatible with Barretenberg (UltraHonk backend)

Both produce proofs that can be verified using their respective standard verifiers.

### Why would I use coSNARKs instead of regular SNARKs?

Use coSNARKs when:
- Multiple parties have private data they want to compute over jointly
- You need to prove correctness without revealing individual inputs
- You want to avoid trusting a single party with all sensitive data
- You're building privacy-preserving applications (e.g., private voting, confidential transactions, multi-party auctions)

### Are coSNARKs production-ready?

The tooling is actively developed and experimental. While the cryptography is sound, you should conduct thorough security audits before production deployment. The codebase includes a disclaimer about its experimental nature.

### What's the performance overhead compared to regular SNARKs?

coSNARKs have higher computational and communication overhead due to MPC protocols. Expect:
- 2-10x slower witness generation (depending on circuit depth and MPC protocol)
- Network communication between parties (bandwidth dependent)
- The proving step can be significantly optimized through batching

---

## Installation & Setup

### What are the system requirements?

**Minimum:**
- Rust 1.70+ (latest stable recommended)
- 4GB RAM
- 10GB disk space
- Linux, macOS, or Windows with WSL2

**Recommended:**
- 8GB+ RAM for large circuits
- Multi-core CPU (MPC benefits from parallelization)
- Low-latency network connection between parties

### How do I install coCircom?

```bash
# From source (recommended for development)
cargo install --git https://github.com/TaceoLabs/co-snarks --branch main co-circom

# Or download binary from releases
# https://github.com/TaceoLabs/co-snarks/releases
```

### How do I install coNoir?

```bash
cargo install --git https://github.com/TaceoLabs/co-snarks --branch main co-noir
```

### Do I need to install Circom/Noir separately?

Yes, for coCircom you need the Circom ecosystem:
- Circom compiler: https://docs.circom.io/getting-started/installation/
- snarkjs (for non-MPC testing): `npm install -g snarkjs`

For coNoir, you need the Noir toolchain:
- Nargo: https://noir-lang.org/docs/getting_started/installation/

### Can I use coSNARKs on Windows?

Yes, through WSL2 (Windows Subsystem for Linux). Native Windows support is not officially tested but may work. WSL2 is the recommended approach for Windows users.

### How do I verify the installation?

```bash
# For coCircom
co-circom --version

# For coNoir
co-noir --version

# Run basic tests
cargo test --workspace
```

---

## Usage & Development

### How do I convert an existing Circom circuit to a coSNARK?

Existing Circom circuits work without modification! The workflow:

1. Compile your circuit normally:
   ```bash
   circom my_circuit.circom --r1cs --wasm --sym
   ```

2. Use coCircom tools to split inputs and run MPC witness generation:
   ```bash
   co-circom split-input --circuit my_circuit.wasm --input input.json
   co-circom generate-witness --mpc-parties 3 ...
   ```

3. Prove with coCircom:
   ```bash
   co-circom prove --protocol groth16 ...
   ```

### Can I use any Circom circuit?

Almost all Circom circuits are supported. Limitations:
- Circuits must be deterministic
- Some custom templates may need verification
- Very deep circuits may have performance implications

### What MPC protocols are supported?

Currently supported:
- **Rep3**: Replicated secret sharing (3-party, semi-honest)
- **Shamir**: Shamir secret sharing (t-of-n threshold, semi-honest)

The choice depends on your security model and number of participants.

### How many parties can participate?

- **Rep3**: Exactly 3 parties
- **Shamir**: Configurable (typically 3-7 parties), with threshold t < n

More parties increase security but also increase communication overhead.

### How do I split private inputs between parties?

```bash
# For coCircom
co-circom split-input \
  --circuit circuit.wasm \
  --input input.json \
  --protocol rep3 \
  --output-dir shares/
```

This creates input shares for each party that can be distributed securely.

### Can parties have different inputs?

Yes! Each party can provide their own private inputs. The split-input command supports specifying which inputs belong to which party.

### Do all parties need to be online simultaneously?

Yes, during witness generation and proving, all parties must communicate in real-time. This is a requirement of MPC protocols.

### How do I test my circuit locally before multi-party execution?

1. Test with regular snarkjs/nargo first
2. Use coCircom/coNoir in "plain" protocol mode (single-party, no MPC)
3. Run MPC locally with loopback networking

### Where can I find example circuits?

- `test_vectors/` directory in the repository
- `examples/` directory for integration examples
- Documentation: https://docs.taceo.io

---

## Architecture & Technical

### How does the MPC witness generation work?

1. Each party has their share of private inputs
2. Parties jointly execute the circuit in MPC:
   - Arithmetic operations done on secret-shared values
   - Communication occurs for multiplication gates
   - Output is a secret-shared extended witness
3. The shared witness is used for collaborative proving

### What's the difference between `_many` and `_vec` functions?

Both refer to batched operations on multiple elements:
- **Historical**: Code used both `_vec` and `_many` inconsistently
- **Current direction**: Standardizing on `_many` suffix
- Functionally equivalent in most contexts

### What cryptographic assumptions does this rely on?

- **SNARKs**: Same as underlying proof system (Groth16/Plonk/UltraHonk)
- **MPC**: Semi-honest security in Rep3/Shamir protocols
- **Network**: Assumes authenticated channels between parties

### Can malicious parties cheat?

Current protocols assume **semi-honest** security:
- Parties follow the protocol but try to learn extra information
- Malicious security (active adversaries) is not currently supported
- For production systems, use additional security layers (attestation, auditing)

### What's the communication complexity?

Depends on circuit and protocol:
- **Rep3**: O(n) communication per multiplication gate (n = circuit size)
- **Shamir**: O(n × p) where p = number of parties
- Witness generation is the most communication-intensive step

### How does batched witness extension improve performance?

When generating witnesses for multiple instances of the same circuit:
- Shares communication costs across instances
- Better CPU utilization (parallelization)
- Can achieve near-zero marginal cost per additional instance
- See benchmarks for 10x-100x speedups in batched scenarios

---

## Performance & Optimization

### My witness generation is very slow. How can I speed it up?

**Quick wins:**
1. Use batched witness extension for multiple instances
2. Reduce circuit depth (deep circuits hurt MPC performance)
3. Use Rep3 instead of Shamir (lower overhead)
4. Ensure low-latency network between parties
5. Compile in release mode: `cargo build --release`

**Advanced:**
- Profile to find bottlenecks: `cargo flamegraph`
- Consider circuit redesign to minimize multiplication gates
- Use multi-threading (`RAYON_NUM_THREADS`)

### Should I use Rep3 or Shamir?

**Use Rep3 when:**
- You have exactly 3 parties
- Performance is critical
- Semi-honest security is sufficient

**Use Shamir when:**
- You need flexible threshold (t-of-n)
- You want more than 3 parties
- You need higher robustness (can tolerate party failures)

### How much network bandwidth do I need?

Depends on circuit size and protocol:
- Small circuits (<10K constraints): 1-10 MB total
- Medium circuits (100K constraints): 10-100 MB
- Large circuits (1M+ constraints): 100MB-1GB+

Latency is more important than bandwidth for typical use cases.

### Can I use GPU acceleration?

Partial GPU support exists:
- `co-groth16-gpu` crate for GPU-accelerated Groth16
- Requires specific GPU setup
- Most benefit in proving step, not witness generation

### What's the fastest proving backend?

For coCircom: Groth16 (fastest proofs, but trusted setup)
For coNoir: UltraHonk (no trusted setup, competitive performance)

---

## Troubleshooting

### "error: could not compile" with Rust errors

**Solution:**
```bash
# Update Rust to latest stable
rustup update stable
rustup default stable

# Clean and rebuild
cargo clean
cargo build --release
```

### "Connection refused" during MPC execution

**Causes:**
- Network configuration issues
- Firewall blocking ports
- Incorrect IP addresses in config

**Solution:**
```bash
# Check if port is available
netstat -an | grep <port>

# Test connectivity
nc -zv <host> <port>

# Check firewall (Linux)
sudo ufw status
sudo ufw allow <port>
```

### "Share verification failed" error

**Causes:**
- Input shares don't match original input
- Parties using different circuit versions
- Corrupted shares during distribution

**Solution:**
- Regenerate shares from original input
- Ensure all parties have same circuit.wasm
- Verify share integrity with checksums

### Memory issues / OOM during large circuit proving

**Solution:**
```bash
# Increase swap space (Linux)
sudo fallocate -l 16G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Or use smaller batch sizes
# Or split circuit into smaller subcircuits
```

### "Unsupported circuit" error

**Causes:**
- Circuit uses unsupported Circom features
- Custom gadgets that don't have MPC implementations

**Solution:**
- Check circuit compatibility
- Rewrite circuit using supported operations
- Open an issue with your circuit for support

### Tests are failing after updates

**Solution:**
```bash
# Update all dependencies
cargo update

# Re-run setup
cargo clean
cargo build --release

# Run tests verbosely
cargo test -- --nocapture
```

---

## Contributing

### How can I contribute?

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines. Quick options:
- Fix bugs or typos
- Improve documentation
- Add examples
- Optimize performance
- Add new features

### Do I need to sign commits?

Check the repository's CONTRIBUTING.md. Many projects require:
- DCO sign-off: `git commit -s`
- Conventional commit messages
- Passing CI checks

### Where should I ask questions?

- **GitHub Issues**: Bug reports, feature requests
- **Discord**: https://discord.gg/gWZW2TANpk
- **Telegram**: https://t.me/collaborativeSNARK
- **Documentation**: https://docs.taceo.io

### How do I run the full test suite?

```bash
# Run all tests
cargo test --workspace

# Run with specific features
cargo test --all-features

# Run benchmarks
cargo bench
```

### What's the code style?

Follow Rust conventions:
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Document public APIs
- Write tests for new features

### How long does review take?

Varies by maintainer availability and PR complexity:
- Simple docs/typos: Days to weeks
- Code changes: Weeks to months
- Major features: Requires discussion first

---

## Additional Resources

- **Documentation**: https://docs.taceo.io
- **GitHub**: https://github.com/TaceoLabs/co-snarks
- **Website**: https://taceo.io
- **Discord**: https://discord.gg/gWZW2TANpk
- **Twitter**: @TACEO_IO

---

**Last Updated:** May 2026  
**Maintained by:** TaceoLabs Community  

**Found an error or have a question not covered here?** [Open an issue](https://github.com/TaceoLabs/co-snarks/issues) or join our Discord!
