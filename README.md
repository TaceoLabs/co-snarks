**Step‑by‑Step Guide to Run the **co‑snarks** tools**

---

## 1. Prerequisites – Install Required Software

| Tool / Library | Installation Command (Linux/macOS) | Notes |
|----------------|-----------------------------------|-------|
| **Rust toolchain** (stable) | ```bash\ncurl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\nsource $HOME/.cargo/env\n``` | Adds `cargo` and `rustc` to your PATH. |
| **Git** | ```bash\nsudo apt-get install -y git   # Debian/Ubuntu\n# or\nbrew install git   # macOS\n``` | Needed to clone the repo. |
| **Node.js & npm** (v20+) | ```bash\ncurl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -\nsudo apt-get install -y nodejs   # Debian/Ubuntu\n# or\nbrew install node   # macOS\n``` | Required for `circom` and `snarkjs`. |
| **circom** (circuit compiler) | ```bash\nnpm install -g circom\n``` | |
| **snarkjs** (proof verifier) | ```bash\nnpm install -g snarkjs\n``` | |
| **Python 3.9+** (optional helpers) | ```bash\nsudo apt-get install -y python3 python3-pip   # Debian/Ubuntu\n``` | |
| **OpenSSL development headers** | ```bash\nsudo apt-get install -y libssl-dev   # Debian/Ubuntu\n``` | Needed for some Rust crates. |
| **Build‑essential tools** (gcc, make, etc.) | ```bash\nsudo apt-get install -y build-essential   # Debian/Ubuntu\n``` | macOS users need Xcode Command Line Tools (`xcode-select --install`). |

Verify installations:

```bash
rustc --version   # e.g., rustc 1.78.0
cargo --version
node -v
npm -v
circom --version
snarkjs --version
```

---

## 2. Clone the Repository

```bash
git clone https://github.com/0xgetz/co-snarks.git
cd co-snarks
```

The repo layout (relevant parts):

```
co-snarks/
├─ coCircom/
│   ├─ co-circom/          # Rust binary for Circom‑based MPC
│   └─ circom-mpc-vm/      # VM implementation
├─ coNoir/
│   └─ co-noir/            # Rust binary for Noir‑based MPC
├─ mpc-core/
└─ mpc-net/
```

---

## 3. Build the Binaries

### 3.1. Build **co‑circom**

```bash
cd coCircom/co-circom
cargo build --release
```

The compiled binary will be at `target/release/co-circom`. Add it to your PATH for convenience:

```bash
export PATH=$PWD/target/release:$PATH   # add to ~/.bashrc or ~/.zshrc for persistence
```

### 3.2. Build **co‑noir**

```bash
cd ../../coNoir/co-noir
cargo build --release
```

Again, add the binary to your PATH:

```bash
export PATH=$PWD/target/release:$PATH
```

> **Tip:** If you plan to call these binaries from other languages (Python, Go, etc.), you can also build a shared library (`cd … && cargo build --release --features python`) – see the repo’s `README` for optional features.

---

## 4. Prepare a Sample Circuit (Circom)

Create a simple multiplication circuit `example.circom`:

```circom
pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b;
}

component main = Multiplier();
```

Compile it with `circom`:

```bash
circom example.circom --r1cs --wasm --sym
```

You will obtain:

- `example.r1cs` – the arithmetic circuit
- `example.wasm` – witness generator
- `example.sym` – symbol file (optional)

---

## 5. Convert the Circuit to a **co‑SNARK** (Distributed Setup)

Run the `co-circom` setup command on the generated R1CS file:

```bash
co-circom setup example.r1cs
```

What happens:

1. The tool splits the witness generation into **shares** for each participant.
2. It creates **key shares** (proving and verification keys) that can be distributed.
3. Output files (e.g., `example.co.r1cs`, `vk_*.json`, `pk_*.json`) are placed in the same folder.

---

## 6. Run a Multi‑Party Computation (MPC) Session

`co-circom` provides two binary modes:

- **coordinator** – optional central node that only forwards messages.
- **participant** – each party that holds a private input share.

You can run a simple 2‑party demo locally.

### 6.1. Start the Coordinator (optional)

```bash
co-circom coordinator --port 9000 &
COORD_PID=$!
```

The coordinator just relays encrypted messages between participants.

### 6.2. Launch Participant 1

```bash
co-circom participant \
    --host localhost \
    --port 9000 \
    --id 1 \
    --input a=5,b=7 &
```

### 6.3. Launch Participant 2

```bash
co-circom participant \
    --host localhost \
    --port 9000 \
    --id 2 \
    --input a=5,b=7 &
```

Both participants will:

1. **Generate their share of the witness** using the `example.wasm` file.
2. **Run the MPC‑VM** to compute the multiplication securely.
3. **Produce a SNARK proof** (e.g., Groth16 or PLONK, depending on the setup).
4. **Write proof files** (`proof.json`, `public.json`) to the working directory.

### 6.4. Verify the Proof

You can verify with either `snarkjs` or the built‑in verifier:

```bash
snarkjs verify verification_key.json proof.json public.json
# or
co-circom verify \
    --vk verification_key.json \
    --proof proof.json \
    --public public.json
```

A successful verification prints `true`.

---

## 7. End‑to‑End Bash Script (2‑Party Demo)

Save the following as `run_cosnark_demo.sh` and make it executable (`chmod +x run_cosnark_demo.sh`).

```bash
#!/usr/bin/env bash
set -e

# 1. Compile the circuit
circom example.circom --r1cs --wasm --sym

# 2. Distributed setup
co-circom setup example.r1cs

# 3. Start coordinator (background)
co-circom coordinator --port 9000 &
COORD_PID=$!

# 4. Participant 1 (background)
co-circom participant --host localhost --port 9000 --id 1 --input a=3,b=4 &
P1_PID=$!

# 5. Participant 2 (background)
co-circom participant --host localhost --port 9000 --id 2 --input a=3,b=4 &
P2_PID=$!

# 6. Wait for both participants to finish
wait $P1_PID $P2_PID

# 7. Verify the generated proof
snarkjs verify verification_key.json proof.json public.json

# 8. Clean up coordinator process
kill $COORD_PID
```

Run it:

```bash
./run_cosnark_demo.sh
```

If everything works, you’ll see `true` at the verification step.

---

## 8. Using **co‑noir** (Noir Circuits)

### 8.1. Write a Noir circuit (`example.nr`)

```noir
fn main(a: Field, b: Field) -> Field {
    a * b
}
```

### 8.2. Compile with Noir CLI

```bash
cargo install noir   # if you haven’t installed it yet
noir compile example.nr
```

This produces `example.circuit` (or similar) and a proving key.

### 8.3. Distributed setup with `co-noir`

```bash
co-noir setup example.circuit
```

The rest of the flow (coordinator → participants → verify) mirrors the `co-circom` steps, just swapping the binary name.

---

## 9. Common Pitfalls & Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|---------------|-----|
| `cargo: command not found` | `$HOME/.cargo/bin` not in `$PATH` | Add `export PATH=$HOME/.cargo/bin:$PATH` to your shell rc file. |
| Build fails with `openssl` errors |
