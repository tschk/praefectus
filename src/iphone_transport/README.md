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
constructor is private. TLS now requires server Finished verification, retains
fragmented handshake messages, validates padding and record bounds, separates
control records from application data, and preserves buffered writes. CDTunnel
framing uses the byte stream, not TLS record boundaries. Pairing logs omit
credentials and payloads; OPACK nesting and TLV lengths are bounded.

Existing-record connection is disabled: the imported pair-verify flow did not
authenticate the device identity. It now returns an unsupported-authentication
error without sending pairing messages or retaining a session key. There is no
automatic new-pair fallback. A source-backed device-authentication contract is
a release blocker. No HAP wire-format assumption or invented peer-key field is
used to claim iPhone compatibility. Explicit SRP setup code remains private to
this module and is not reachable from the executor's connection path.

`native/iphone/import-transport.py` verifies the original crate checksum, imports
the baseline, formats it, and applies `transport-hardening.patch`. The patch is
part of the import, not an optional cleanup. Hardware compatibility remains
unverified. These sources ship inside the published crate; no Cargo patch or
unpublished dependency is required.
