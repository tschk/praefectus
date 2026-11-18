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

The independently written `verify.rs` replaces upstream's host-only verification
with device-authenticated Pair-Verify. It checks the encrypted state-2 identifier
and Ed25519 signature over device ephemeral key, pinned identifier and host
ephemeral key before releasing a host identity proof. Both setup and verify
interoperate with the installed Apple macOS `CUPairingSession`, including derived
session-key agreement. That is Apple pairing-primitive evidence, not physical
iPhone RemotePairing compatibility evidence.

Trusted USB setup pins the device identifier and long-term public key after
verifying the state-6 signature. These are local credential metadata, not new
wire fields. Host-only records fail closed; no network setup fallback exists.
The public iPhone setup PIN is not an authentication credential. The one-time
USB caller must trust the local host/mux daemon and physically selected device.
Subsequent sessions use fresh contributory X25519 exchanges and the pinned key.

CBC record authentication checks all possible padding lengths and their MACs
using `subtle` constant-time comparisons. Its work depends on public record
length, not decrypted padding. This deliberately costs extra HMAC work; it is
not a claim of an independently audited TLS stack. Shutdown flushes encrypted
`close_notify` exactly once before closing the transport.

`native/iphone/import-transport.py` verifies the original crate checksum, imports
the baseline, formats it, and applies `transport-hardening.patch`. The patch is
part of the import, not an optional cleanup. Hardware compatibility remains
unverified. These sources ship inside the published crate; no Cargo patch or
unpublished dependency is required.
