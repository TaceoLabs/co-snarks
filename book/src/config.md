# Configuration

`co-circom` uses a configuration for general settings and network configuration.
The configuration can be done via a config file, environment variables, and cli arguments.
Values are loaded in hierarchical order `file < environment variables < cli args`.

A path to the configuration file can be passed to all commands using `--config <CONFIG>`.
Different commands have different required values that must be passed by file, env, or cli.
The network section is only required for the commands `generate-witness`, `translate-witness` and `generate-proof`.

## TOML File

The configuration file is a TOML file with the following (non-exhaustive) structure:

```toml
protocol = "REP3"
curve = "BN254"

[compiler]
version = "2.0.0"
link_library = ["circomlibs", "utils"]
allow_leaky_loops = false

[vm]
allow_leaky_logs = false

[network]
my_id = 0
bind_addr = "0.0.0.0:10000"
key_path = "data/key0.der"
[[network.parties]]
id = 0
# normally we would use DNS name here such as localhost, but localhost under windows is resolved to ::1, which causes problems since we bind to ipv4 above
dns_name = "127.0.0.1:10000"
cert_path = "data/cert0.der"
[[network.parties]]
id = 1
dns_name = "127.0.0.1:10001"
cert_path = "data/cert1.der"
[[network.parties]]
id = 2
dns_name = "127.0.0.1:10002"
cert_path = "data/cert2.der"
```

See the example configuration in the `collaborative-circom/examples/configs` folder, with pre-generated certificates and keys in the `collaborative-circom/examples/data` folder.

## Env Variables

Environment variables use the prefix `COCIRCOM_`.
The different types can be set as follows:

* Boolean: `true`, `false` (e.g. `COCIRCOM_VAR=true`)
* Strings/Enums: delimited by `"` (e.g. `COCIRCOM_VAR=\"foo\"`) or else (e.g. `COCIRCOM_VAR=foo`)
* Arrays: delimited by `[]` (e.g. `COCIRCOM_VAR=[1, 2, 3]`)
* Structs: as dictionary with `{key=value}` (e.g. `COCIRCOM_VAR={foo=1, bar=true}`)

E.g. the protocol can be set with `COCIRCOM_PROTOCOL=BN254`.
Structs such as the CompilerConfig can be set with `COCIRCOM_COMPILER={allow_leaky_loops=true}`.

## Cli Arguments

See [co-circom CLI](./co-circom.md)

## Compiler Configuration

This section configures the co-circom MPC compiler.

### Keys

* `version`: Allows leaking of secret values in loops (default: "2.0.0")
* `link_library`: A list of strings that represent paths for circom to look for library files (`-l` flag in circom) (default: `[]`)
* `allow_leaky_loops`: Allows leaking of secret values in loops (default: `false`) (*currently not implemented*).

## VM Configuration

This section configures the co-circom VM.

### Keys

* `allow_leaky_logs`: Allows leaking of secret values in logs (default: `false`).

## Network Configuration

`co-circom` requires a network configuration for establishing connections to other MPC parties for the `generate-witness` and `generate-proof` commands.

### Keys

* `my_id` is the party id of the party executing the `co-circom` binary using the configuration file.
* `bind_addr` is the local socket address this party is binding to and listening for incoming connections from other parties.
* `key_path` is a path to a DER encoded PKCS8 private key file corresponding to the public key used in the certificate for our party.
* `parties` is an array of tables containing the public information of each MPC party.
  * `id`: the party id of the MPC party
  * `dns_name`: the hostname/port combination where the party is publicly reachable. The hostname must be the a valid CN or SNI in the used certificate.
  * `cert_path`: a path to the DER encoded certificate (chain) file that is used to authenticate the connection with the party and is used to establish the secure communication channel.
