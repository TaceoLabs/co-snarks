# Network Configuration

`co-circom` requires a network configuration file for establishing connections to other MPC parties for the `generate-witness` and `generate-proof` commands.

The network configuration file is a TOML file with the following structure:

```toml
my_id = 0
bind_addr = "0.0.0.0:10000"
key_path = "data/key0.der"
[[parties]]
id = 0
dns_name = "localhost:10000"
cert_path = "data/cert0.der"
[[parties]]
id = 1
dns_name = "localhost:10001"
cert_path = "data/cert1.der"
[[parties]]
id = 2
dns_name = "localhost:10002"
cert_path = "data/cert2.der"
```

See the example configuration in the `collaborative-circom/examples/configs` folder, with pre-generated certificates and keys in the `collaborative-circom/examples/data` folder.

## Keys

* `my_id` is the party id of the party executing the `co-circom` binary using the configuration file.
* `bind_addr` is the local socket address this party is binding to and listening for incoming connections from other parties.
* `key_path` is a path to a DER encoded PKCS8 private key file corresponding to the public key used in the certificate for our party.
* `parties` is an array of tables containing the public information of each MPC party.
  * `id`: the party id of the MPC party
  * `dns_name`: the hostname/port combination where the party is publicly reachable. The hostname must be the a valid CN or SNI in the used certificate.
  * `cert_path`: a path to the DER encoded certificate (chain) file that is used to authenticate the connection with the party and is used to establish the secure communication channel.
