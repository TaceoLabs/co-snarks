# Example TLS keys and certificates

**For local testing only. Never use these files in a deployment.**

`key{0,1,2}.der` are the TLS private keys of the three example parties and `cert{0,1,2}.der` the matching self-signed certificates. They are used by the example configs in `../configs`, which run all parties on `127.0.0.1`.

The private keys are public, as they are part of this repository. Anyone can use them to impersonate a party or decrypt its traffic, so a network secured with them offers no protection.

For a real deployment, each party generates its own key pair, keeps the private key to itself and only hands its certificate to the other parties. The certificate has to contain the hostname or IP address under which the party is reachable, i.e., the one in its `dns_name` entry in the network config. Self-signed certificates can for example be generated with

```bash
cargo run -p mpc-net --example gen_cert -- --help
```
