# RemotePairing client source

These nine Rust files are adapted from the MIT-licensed `idevice` 0.1.68 crate,
upstream revision `d32c8189c51c2789496b0768039419c3705498c3`. Copyright and
permission are retained in LICENSE.txt. Praefectus's own code remains ISC.

The upstream RemotePairing feature unnecessarily depends on vulnerable RSA 0.9
solely for randomness and signing-trait reexports. This import uses `rand_core`
and `ed25519_dalek::Signer` directly. RSA is neither used nor resolved.

The import omits the unused responder, USB wrapper, and OpenSSL helper. Paths
point to public idevice APIs. Pairing errors map to a fixed nonsensitive upstream
error. The tunnel result locally owns its stream because the upstream result's
constructor is private. Native TLS record handling and protocol operations are
retained. `native/iphone/import-transport.py` records the repeatable adaptations
and verifies source checksums before import. Run `cargo fmt --all` afterward.

The executor only verifies existing pairing. It never calls the client's new-pair
fallback. Hardware compatibility is unverified. This source is included in the
published crate; no local Cargo patch or unpublished dependency is required.
