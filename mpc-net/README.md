# MPC Net

The networking layer used by the MPC protocols in [co-snarks](https://github.com/TaceoLabs/co-snarks).

The `Network` trait is implemented for local channels, TCP, TLS and QUIC. Each backend is behind its own feature: `local`, `tcp`, `tls`, `quic`, `tcp-session`, `tcp-session-blocking`, `tls-session` and `tls-session-blocking`.

## License

Licensed under either of MIT or Apache-2.0, at your option.

## Disclaimer

This software is experimental and un-audited, see the [disclaimer](https://github.com/TaceoLabs/co-snarks#disclaimer) in the co-snarks repository.
