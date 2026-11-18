//! Remote Pairing

use base64::Engine as _;
use errors::RemotePairingError;
use idevice::IdeviceError;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use idevice_srp::{client::SrpClient, groups::G_3072};
use plist_macro::plist;
use plist_macro::{PlistConvertible, PlistExt};
use rand::Rng as _;
use serde::Serialize;
use sha2::Sha512;
use tracing::{debug, warn};

pub mod errors;
mod opack;
mod peer_device;
mod rp_pairing_file;
mod socket;
pub mod tls_psk;
mod tlv;
pub mod tunnel;

// export
pub use peer_device::{PeerDevice, compute_auth_tag};
pub use rp_pairing_file::RpPairingFile;
pub use socket::{RpPairingSocket, RpPairingSocketProvider};
pub use tunnel::{CdTunnel, TunnelInfo, connect_tls_psk_tunnel_native};

const RPPAIRING_MAGIC: &[u8] = b"RPPairing";
const UNSUPPORTED_PEER_AUTHENTICATION: &str =
    "existing-record RemotePairing peer authentication is unsupported";

fn validate_pin(pin: &str) -> Result<&[u8], IdeviceError> {
    if pin.len() != 6 || !pin.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RemotePairingError::SrpAuthFailed.into());
    }
    Ok(pin.as_bytes())
}

pub struct RemotePairingClient<R: RpPairingSocketProvider> {
    inner: R,
    sequence_number: usize,
    encrypted_sequence_number: u64,
    sending_host: String,

    /// The shared secret from explicit SRP setup. Existing-record verification is disabled.
    /// Used as PSK for the TLS tunnel and to derive per-message encryption keys.
    encryption_key: Vec<u8>,

    client_cipher: ChaCha20Poly1305,
    server_cipher: ChaCha20Poly1305,

    paired_peer_device: Option<PeerDevice>,
    authenticated: bool,
}

impl<R: RpPairingSocketProvider> RemotePairingClient<R> {
    pub fn new(inner: R, sending_host: &str) -> Self {
        // Placeholder ciphers cannot be used until explicit setup authenticates the peer.
        let initial_key = vec![0u8; 32];
        let (client_cipher, server_cipher) = Self::derive_main_ciphers(&initial_key);

        Self {
            inner,
            sequence_number: 0,
            encrypted_sequence_number: 0,
            sending_host: sending_host.to_string(),
            encryption_key: Vec::new(),
            client_cipher,
            server_cipher,
            paired_peer_device: None,
            authenticated: false,
        }
    }

    fn derive_main_ciphers(key: &[u8]) -> (ChaCha20Poly1305, ChaCha20Poly1305) {
        let hk = Hkdf::<sha2::Sha512>::new(None, key);
        let mut okm = [0u8; 32];
        hk.expand(b"ClientEncrypt-main", &mut okm).unwrap();
        let client_cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&okm));

        let hk = Hkdf::<sha2::Sha512>::new(None, key);
        let mut okm = [0u8; 32];
        hk.expand(b"ServerEncrypt-main", &mut okm).unwrap();
        let server_cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&okm));

        (client_cipher, server_cipher)
    }

    /// Returns the encryption key established during pairing.
    /// This is used as TLS-PSK for tunnel connections.
    pub fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }

    /// Existing-record authentication is unsupported; fails without network I/O.
    /// Never initiates a new pairing.
    pub async fn connect<Fut>(
        &mut self,
        pairing_file: &mut RpPairingFile,
        _pin_callback: impl Fn() -> Fut,
    ) -> Result<(), IdeviceError>
    where
        Fut: std::future::Future<Output = String>,
    {
        self.validate_pairing(pairing_file).await
    }

    /// Returns peer device info captured during this client's successful `pair()` flow.
    pub fn paired_peer_device(&self) -> Result<&PeerDevice, IdeviceError> {
        self.paired_peer_device
            .as_ref()
            .ok_or(IdeviceError::UnexpectedResponse(
                "paired peer device info is only available after a successful pair() call".into(),
            ))
    }

    pub async fn validate_pairing(
        &mut self,
        _pairing_file: &mut RpPairingFile,
    ) -> Result<(), IdeviceError> {
        self.authenticated = false;
        self.encryption_key.clear();
        Err(IdeviceError::UnexpectedResponse(
            UNSUPPORTED_PEER_AUTHENTICATION.into(),
        ))
    }

    pub async fn send_pair_verified_failed(&mut self) -> Result<(), IdeviceError> {
        self.inner
            .send_plain(
                plist!({
                    "event": {
                        "_0": {
                            "pairVerifyFailed": {}
                        }
                    }
                }),
                self.sequence_number,
            )
            .await?;
        self.sequence_number += 1;
        Ok(())
    }

    pub async fn attempt_pair_verify(&mut self) -> Result<plist::Value, IdeviceError> {
        self.authenticated = false;
        self.encryption_key.clear();
        Err(IdeviceError::UnexpectedResponse(
            UNSUPPORTED_PEER_AUTHENTICATION.into(),
        ))
    }

    pub async fn pair<Fut>(
        &mut self,
        pairing_file: &mut RpPairingFile,
        pin_callback: impl Fn() -> Fut,
    ) -> Result<(), IdeviceError>
    where
        Fut: std::future::Future<Output = String>,
    {
        self.authenticated = false;
        self.encryption_key.clear();
        let (salt, public_key, pin) = self.request_pair_consent(pin_callback).await?;
        let key = self.init_srp_context(&salt, &public_key, &pin).await?;
        let mut staged_record = pairing_file.clone();
        let tlv = self
            .save_pair_record_on_peer(&mut staged_record, &key)
            .await?;
        let peer_device = peer_device::parse_peer_device_from_tlv(&tlv)?;
        staged_record.alt_irk = Some(peer_device.alt_irk.clone());
        *pairing_file = staged_record;
        self.paired_peer_device = Some(peer_device);
        self.encryption_key = key;
        (self.client_cipher, self.server_cipher) = Self::derive_main_ciphers(&self.encryption_key);
        self.encrypted_sequence_number = 0;
        self.authenticated = true;

        Ok(())
    }

    /// Returns salt and public key and pin
    async fn request_pair_consent<Fut>(
        &mut self,
        pin_callback: impl Fn() -> Fut,
    ) -> Result<(Vec<u8>, Vec<u8>, String), IdeviceError>
    where
        Fut: std::future::Future<Output = String>,
    {
        let tlv = tlv::serialize_tlv8(&[
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::Method,
                data: vec![0x00],
            },
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::State,
                data: vec![0x01],
            },
        ]);
        let tlv = R::serialize_bytes(&tlv);
        self.send_pairing_data(plist!({
            "data": tlv,
            "kind": "setupManualPairing",
            "sendingHost": &self.sending_host,
            "startNewSession": true
        }))
        .await?;

        let response = self.inner.recv_plain().await?;
        let response = match response
            .get_by("event")
            .and_then(|x| x.get_by("_0"))
            .and_then(|x| x.as_dictionary())
        {
            Some(r) => r,
            None => {
                return Err(IdeviceError::UnexpectedResponse(
                    "missing event._0 in pair consent response".into(),
                ));
            }
        };

        let mut pin = None;

        let pairing_data = match if response.contains_key("pairingRejectedWithError") {
            return Err(RemotePairingError::PairingRejected(String::new()).into());
        } else if response.get("awaitingUserConsent").is_some() {
            pin = Some("000000".to_string());
            Some(self.receive_pairing_data().await?)
        } else {
            // On Apple TV, we can get the pin now
            response
                .get_by("pairingData")
                .and_then(|x| x.get_by("_0"))
                .and_then(|x| x.get_by("data"))
                .map(|x| x.to_owned())
        } {
            Some(p) => p,
            None => {
                return Err(IdeviceError::UnexpectedResponse(
                    "missing pairing data in pair consent response".into(),
                ));
            }
        };

        let tlv = tlv::deserialize_tlv8(&match R::deserialize_bytes(pairing_data) {
            Some(t) => t,
            None => {
                return Err(IdeviceError::UnexpectedResponse(
                    "failed to deserialize pairing data bytes in pair consent".into(),
                ));
            }
        })?;

        let mut salt = Vec::new();
        let mut public_key = Vec::new();
        for t in tlv {
            match t.tlv_type {
                tlv::PairingDataComponentType::Salt => {
                    salt = t.data;
                }
                tlv::PairingDataComponentType::PublicKey => {
                    public_key.extend(t.data);
                }
                tlv::PairingDataComponentType::ErrorResponse => {
                    warn!("Pairing data contained error response");
                    return Err(IdeviceError::UnexpectedResponse(
                        "pairing data contained error response during pair consent".into(),
                    ));
                }
                _ => {
                    continue;
                }
            }
        }

        let pin = match pin {
            Some(p) => p,
            None => pin_callback().await,
        };

        if salt.is_empty() || public_key.is_empty() {
            warn!("Pairing data did not contain salt or public key");
            return Err(IdeviceError::UnexpectedResponse(
                "pairing data missing salt or public key".into(),
            ));
        }

        Ok((salt, public_key, pin))
    }

    /// Returns the encryption key
    async fn init_srp_context(
        &mut self,
        salt: &[u8],
        public_key: &[u8],
        pin: &str,
    ) -> Result<Vec<u8>, IdeviceError> {
        let pin = validate_pin(pin)?;
        let client = SrpClient::<Sha512>::new(
            &G_3072, // PRIME_3072 + generator
        );

        let mut a_private = [0u8; 32];
        rand::rng().fill_bytes(&mut a_private);

        let a_public = client.compute_public_ephemeral(&a_private);

        let verifier = match client.process_reply(
            &a_private,
            "Pair-Setup".as_bytes(),
            pin,
            salt,
            public_key,
            false,
        ) {
            Ok(v) => v,
            Err(_) => {
                warn!("SRP verifier creation failed");
                return Err(RemotePairingError::SrpAuthFailed.into());
            }
        };

        let client_proof = verifier.proof();

        let tlv = tlv::serialize_tlv8(&[
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::State,
                data: vec![0x03],
            },
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::PublicKey,
                data: a_public[..254].to_vec(),
            },
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::PublicKey,
                data: a_public[254..].to_vec(),
            },
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::Proof,
                data: client_proof.to_vec(),
            },
        ]);
        let tlv = R::serialize_bytes(&tlv);

        self.send_pairing_data(plist!({
            "data": tlv,
            "kind": "setupManualPairing",
            "sendingHost": &self.sending_host,
            "startNewSession": false,

        }))
        .await?;

        let response = self.receive_pairing_data().await?;
        let response = tlv::deserialize_tlv8(&match R::deserialize_bytes(response.to_owned()) {
            Some(r) => r,
            None => {
                return Err(IdeviceError::UnexpectedResponse(
                    "failed to deserialize SRP proof response bytes".into(),
                ));
            }
        })?;

        let proof = match response
            .iter()
            .find(|x| x.tlv_type == tlv::PairingDataComponentType::Proof)
        {
            Some(p) => &p.data,
            None => {
                warn!("Proof response did not contain server proof");
                return Err(IdeviceError::UnexpectedResponse(
                    "missing server proof in SRP response".into(),
                ));
            }
        };

        match verifier.verify_server(proof) {
            Ok(_) => Ok(verifier.key().to_vec()),
            Err(_) => {
                warn!("Server authentication failed");
                Err(RemotePairingError::SrpAuthFailed.into())
            }
        }
    }

    async fn save_pair_record_on_peer(
        &mut self,
        pairing_file: &mut RpPairingFile,
        encryption_key: &[u8],
    ) -> Result<Vec<tlv::TLV8Entry>, IdeviceError> {
        let salt = b"Pair-Setup-Encrypt-Salt";
        let info = b"Pair-Setup-Encrypt-Info";

        let hk = Hkdf::<Sha512>::new(Some(salt), encryption_key);
        let mut setup_encryption_key = [0u8; 32];
        hk.expand(info, &mut setup_encryption_key)
            .expect("HKDF expand failed");

        pairing_file.recreate_signing_keys();

        let hk = Hkdf::<Sha512>::new(Some(b"Pair-Setup-Controller-Sign-Salt"), encryption_key);

        let mut signbuf = Vec::with_capacity(32 + pairing_file.identifier.len() + 32);

        let mut hkdf_out = [0u8; 32];
        hk.expand(b"Pair-Setup-Controller-Sign-Info", &mut hkdf_out)
            .expect("HKDF expand failed");

        signbuf.extend_from_slice(&hkdf_out);

        signbuf.extend_from_slice(pairing_file.identifier.as_bytes());
        signbuf.extend_from_slice(pairing_file.e_public_key.as_bytes());

        let signature = pairing_file.e_private_key.sign(&signbuf);

        let device_info = plist_macro::plist!({
            "altIRK": b"\xe9\xe8-\xc0jIykVoT\x00\x19\xb1\xc7{".to_vec(),
            "btAddr": "11:22:33:44:55:66",
            "mac": b"\x11\x22\x33\x44\x55\x66".to_vec(),
            "remotepairing_serial_number": "AAAAAAAAAAAA",
            "accountID": pairing_file.identifier.as_str(),
            "model": "computer-model",
            "name": self.sending_host.as_str()
        });
        let device_info = opack::plist_to_opack(&device_info);

        let tlv = tlv::serialize_tlv8(&[
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::Identifier,
                data: pairing_file.identifier.as_bytes().to_vec(),
            },
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::PublicKey,
                data: pairing_file.e_public_key.to_bytes().to_vec(),
            },
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::Signature,
                data: signature.to_vec(),
            },
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::Info,
                data: device_info,
            },
        ]);

        let key = Key::from_slice(&setup_encryption_key); // 32 bytes
        let cipher = ChaCha20Poly1305::new(key);

        let nonce = Nonce::from_slice(b"\x00\x00\x00\x00PS-Msg05"); // 12 bytes

        let plaintext = &tlv;

        let ciphertext = match cipher.encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: b"",
            },
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!("Chacha encryption failed");
                return Err(RemotePairingError::ChachaEncryption(e).into());
            }
        };
        debug!("ciphertext len: {}", ciphertext.len());

        let tlv = tlv::serialize_tlv8(&[
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::EncryptedData,
                data: ciphertext[..254].to_vec(),
            },
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::EncryptedData,
                data: ciphertext[254..].to_vec(),
            },
            tlv::TLV8Entry {
                tlv_type: tlv::PairingDataComponentType::State,
                data: vec![0x05],
            },
        ]);
        let tlv = R::serialize_bytes(&tlv);

        debug!("Sending encrypted data");
        self.send_pairing_data(plist!({
            "data": tlv,
            "kind": "setupManualPairing",
            "sendingHost": &self.sending_host,
            "startNewSession": false,
        }))
        .await?;

        debug!("Waiting for encrypted data");
        let response = match R::deserialize_bytes(self.receive_pairing_data().await?) {
            Some(r) => r,
            None => {
                warn!("Pairing data response was not deserializable");
                return Err(IdeviceError::UnexpectedResponse(
                    "failed to deserialize pair record response bytes".into(),
                ));
            }
        };

        let tlv = tlv::deserialize_tlv8(&response)?;

        let mut encrypted_data = Vec::new();
        for t in tlv {
            match t.tlv_type {
                tlv::PairingDataComponentType::EncryptedData => encrypted_data.extend(t.data),
                tlv::PairingDataComponentType::ErrorResponse => {
                    warn!("TLV contained error response");
                    return Err(IdeviceError::UnexpectedResponse(
                        "TLV error response in pair record save".into(),
                    ));
                }
                _ => {}
            }
        }

        let nonce = Nonce::from_slice(b"\x00\x00\x00\x00PS-Msg06");

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &encrypted_data,
                    aad: b"",
                },
            )
            .map_err(|_| RemotePairingError::PairVerifyFailed)?;

        let tlv = tlv::deserialize_tlv8(&plaintext)?;

        Ok(tlv)
    }

    /// Send an encrypted request and receive an encrypted response.
    /// Used for post-pairing RPCs like creating tunnel listeners.
    pub async fn send_receive_encrypted_request(
        &mut self,
        request: plist::Value,
    ) -> Result<plist::Value, IdeviceError> {
        if !self.authenticated {
            return Err(RemotePairingError::PairVerifyFailed.into());
        }
        let plaintext = serde_json::to_vec(
            &plist::to_value(&request).map_err(|e| IdeviceError::InternalError(e.to_string()))?,
        )
        .map_err(|e| IdeviceError::InternalError(e.to_string()))?;

        // Build nonce: 8-byte LE sequence number + 4 zero bytes
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.encrypted_sequence_number.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .client_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: b"",
                },
            )
            .map_err(|e| IdeviceError::from(RemotePairingError::ChachaEncryption(e)))?;

        self.inner
            .send_encrypted(ciphertext, self.sequence_number)
            .await?;
        self.sequence_number += 1;

        // Receive encrypted response
        let response = self.inner.recv_plain().await?;
        let encrypted_data = response
            .get_by("message")
            .and_then(|m| m.get_by("streamEncrypted"))
            .and_then(|s| s.get_by("_0"))
            .and_then(|d| {
                // Could be bytes directly or base64
                R::deserialize_bytes(d.to_owned())
            })
            .ok_or(IdeviceError::UnexpectedResponse(
                "missing encrypted data in streamEncrypted response".into(),
            ))?;

        let decrypted = self
            .server_cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &encrypted_data,
                    aad: b"",
                },
            )
            .map_err(|e| IdeviceError::from(RemotePairingError::ChachaEncryption(e)))?;

        self.encrypted_sequence_number += 1;

        let value: plist::Value = serde_json::from_slice(&decrypted)
            .map_err(|e| IdeviceError::InternalError(e.to_string()))?;

        // Extract response._1
        let result = value
            .get_by("response")
            .and_then(|r| r.get_by("_1"))
            .cloned()
            .ok_or(IdeviceError::UnexpectedResponse(
                "missing response._1 in encrypted response".into(),
            ))?;

        Ok(result)
    }

    /// Send a request to create a TCP tunnel listener on the device.
    /// Returns the port the device is listening on.
    ///
    /// Not every endpoint that accepts pairing serves this. tvOS advertises a
    /// second `_remotepairing-manual-pairing._tcp` service which handles both
    /// pair-setup and pair-verify but reportedly rejects this request, so a device
    /// paired over that service must be reconnected over `_remotepairing._tcp`
    /// before a tunnel can be requested.
    pub async fn create_tcp_listener(&mut self) -> Result<u16, IdeviceError> {
        let request = plist!({
            "request": {
                "_0": {
                    "createListener": {
                        "key": base64::engine::general_purpose::STANDARD.encode(&self.encryption_key),
                        "transportProtocolType": "tcp"
                    }
                }
            }
        });

        let response = self.send_receive_encrypted_request(request).await?;

        let port = response
            .get_by("createListener")
            .and_then(|c| c.get_by("port"))
            .and_then(|p| p.as_unsigned_integer())
            .ok_or_else(|| {
                IdeviceError::UnexpectedResponse("missing createListener.port".into())
            })?;

        Ok(port as u16)
    }

    async fn send_pairing_data(
        &mut self,
        pairing_data: impl Serialize + PlistConvertible,
    ) -> Result<(), IdeviceError> {
        self.inner
            .send_plain(
                plist!({
                    "event": {
                        "_0": {
                            "pairingData": {
                                "_0": pairing_data
                            }
                        }
                    }
                }),
                self.sequence_number,
            )
            .await?;

        self.sequence_number += 1;
        Ok(())
    }

    async fn receive_pairing_data(&mut self) -> Result<plist::Value, IdeviceError> {
        let response = self.inner.recv_plain().await?;

        let response = match response.get_by("event").and_then(|x| x.get_by("_0")) {
            Some(r) => r,
            None => {
                return Err(IdeviceError::UnexpectedResponse(
                    "missing event._0 in pairing data response".into(),
                ));
            }
        };

        if let Some(data) = response
            .get_by("pairingData")
            .and_then(|x| x.get_by("_0"))
            .and_then(|x| x.get_by("data"))
        {
            Ok(data.to_owned())
        } else if response.get_by("pairingRejectedWithError").is_some() {
            Err(RemotePairingError::PairingRejected(String::new()).into())
        } else {
            Err(IdeviceError::UnexpectedResponse(
                "pairing data response contained neither data nor rejection".into(),
            ))
        }
    }
}

impl<R: RpPairingSocketProvider> std::fmt::Debug for RemotePairingClient<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemotePairingClient")
            .field("inner", &self.inner)
            .field("sequence_number", &self.sequence_number)
            .field("sending_host", &self.sending_host)
            .finish()
    }
}

#[cfg(test)]
mod authentication_tests {
    use super::*;
    use tlv::{PairingDataComponentType as T, TLV8Entry};

    fn entry(tlv_type: T, data: Vec<u8>) -> TLV8Entry {
        TLV8Entry { tlv_type, data }
    }

    fn envelope(entries: &[TLV8Entry]) -> plist::Value {
        plist!({"event": {"_0": {"pairingData": {"_0": {
            "data": RpPairingSocket::<tokio::io::DuplexStream>::serialize_bytes(&tlv::serialize_tlv8(entries))
        }}}}})
    }

    #[test]
    fn pin_validation_rejects_short_long_and_unicode_without_panicking() {
        for pin in ["", "12345", "1234567", "ééé", "abcdef", "123 56"] {
            assert!(validate_pin(pin).is_err());
        }
        assert_eq!(validate_pin("012345").unwrap(), b"012345");
    }

    #[test]
    fn existing_record_authentication_never_contacts_peer_or_exposes_key() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            use tokio::io::AsyncReadExt;
            let (host, mut device) = tokio::io::duplex(16_384);
            let mut record = RpPairingFile::generate("test-host");
            let mut client = RemotePairingClient::new(RpPairingSocket::new(host), "test-host");
            for operation in 0..3 {
                client.encryption_key = vec![7; 32];
                client.authenticated = true;
                let error = match operation {
                    0 => client.validate_pairing(&mut record).await.unwrap_err(),
                    1 => client.connect(&mut record, || async { panic!("must not request a PIN") }).await.unwrap_err(),
                    _ => client.attempt_pair_verify().await.unwrap_err(),
                };
                assert!(matches!(error, IdeviceError::UnexpectedResponse(message) if message == UNSUPPORTED_PEER_AUTHENTICATION));
                assert!(client.encryption_key().is_empty());
                assert!(!client.authenticated);
                assert!(client.send_receive_encrypted_request(plist!({})).await.is_err());
                assert!(client.create_tcp_listener().await.is_err());
                assert_eq!(client.sequence_number, 0);
            }
            drop(client);
            let mut byte = [0; 1];
            assert_eq!(device.read(&mut byte).await.unwrap(), 0, "no network bytes may be emitted");
        });
    }

    #[test]
    fn invalid_setup_ciphertext_fails_without_panicking() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (host, device) = tokio::io::duplex(16_384);
            let mut record = RpPairingFile::generate("test-host");
            let mut client = RemotePairingClient::new(RpPairingSocket::new(host), "test-host");
            assert!(client.validate_pairing(&mut record).await.is_err());
            assert!(client.encryption_key().is_empty());
            let task = tokio::spawn(async move {
                let mut peer = RpPairingSocket::new_device(device);
                peer.recv_plain().await.unwrap();
                peer.send_plain(envelope(&[entry(T::EncryptedData, vec![0; 16])]), 0)
                    .await
                    .unwrap();
            });
            assert!(
                client
                    .save_pair_record_on_peer(&mut record, &[7; 32])
                    .await
                    .is_err()
            );
            assert!(client.encryption_key().is_empty());
            assert!(!client.authenticated);
            task.await.unwrap();
        });
    }
}
