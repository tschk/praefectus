"""Import the RSA-free initiating client from the checksummed idevice 0.1.68 crate.

Run with the crates.io idevice-0.1.68.crate archive as the argument, then
cargo fmt --all. This is a source import, not a new protocol implementation.
"""
import hashlib
from pathlib import Path
import sys
import tarfile

source = Path(sys.argv[1])
assert hashlib.sha256(source.read_bytes()).hexdigest() == "f5d7799c8497cef60ddfd38f7d92e267b9fa5d0b18e7691d31041453007400ca"
archive = tarfile.open(source)
destination = Path(__file__).resolve().parents[2] / "src/iphone_transport"
destination.mkdir(exist_ok=True)
files = ["mod.rs", "errors.rs", "opack.rs", "peer_device.rs", "rp_pairing_file.rs", "socket.rs", "tls_psk.rs", "tlv.rs", "tunnel.rs"]
for name in files:
    relative = f"idevice-0.1.68/src/remote_pairing/{name}"
    raw = archive.extractfile(relative).read()
    text = raw.decode()
    text = text.replace("use crate::", "use idevice::").replace("pub use crate::", "pub use idevice::")
    text = text.replace("crate::plist!", "plist_macro::plist!").replace("crate::xpc!", "idevice::xpc!")
    text = text.replace("remote_pairing::RPPAIRING_MAGIC, ", "")
    text = text.replace("use rsa::{rand_core::OsRng, signature::SignerMut};", "use rand_core::OsRng;\nuse ed25519_dalek::Signer;")
    text = text.replace("use rsa::rand_core::OsRng;", "use rand_core::OsRng;")
    text = text.replace("IdeviceError::RemotePairing(", "IdeviceError::from(")
    text = text.replace('    #[cfg(feature = "remote_pairing")]\n', "")
    if name == "mod.rs":
        for line in ["mod lockdown;\n", "mod responder;\n", "pub use lockdown::RemotePairingLockdownService;\n", "pub use responder::{PAIRABLE_HOST_SERVICE_TYPE, PairableHost, PairableHostInfo};\n", '#[cfg(feature = "openssl")]\npub use tunnel::connect_tls_psk_tunnel;\n']:
            assert line in text, line
            text = text.replace(line, "")
    if name == "socket.rs":
        text = "use super::RPPAIRING_MAGIC;\n" + text
    if name == "errors.rs":
        text += '\nimpl From<RemotePairingError> for idevice::IdeviceError {\n    fn from(_: RemotePairingError) -> Self {\n        Self::UnexpectedResponse("remote pairing failed".into())\n    }\n}\n'
    if name == "tunnel.rs":
        text = text.split('/// Wraps a `tokio::net::TcpStream` with TLS-PSK using OpenSSL')[0]
        text = text.replace("pub use idevice::tunnel::{CdTunnel, TunnelInfo};", "pub use idevice::tunnel::TunnelInfo;\n\npub struct CdTunnel<S> {\n    inner: S,\n    pub info: TunnelInfo,\n}\nimpl<S> CdTunnel<S> {\n    pub fn into_inner(self) -> S { self.inner }\n}")
    (destination / name).write_text(text)
