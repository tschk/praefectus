//! Device-authenticated Pair-Verify, interoperated with Apple's CUPairingSession.
use super::*;
use ed25519_dalek::Signature;
use tlv::{PairingDataComponentType as T, TLV8Entry};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn rejected() -> IdeviceError {
    RemotePairingError::PairVerifyFailed.into()
}

fn component(entries: &[TLV8Entry], kind: T) -> Vec<u8> {
    tlv::collect_component_data(entries, kind)
}

pub(super) fn require_state(entries: &[TLV8Entry], state: u8) -> Result<(), IdeviceError> {
    if tlv::contains_component(entries, T::ErrorResponse) || component(entries, T::State) != [state]
    {
        return Err(rejected());
    }
    Ok(())
}

/// Only the trusted-USB setup caller may pin this self-signed identity.
pub(super) fn setup_identity(
    entries: &[TLV8Entry],
    shared: &[u8],
) -> Result<PeerIdentity, IdeviceError> {
    let identifier = component(entries, T::Identifier);
    if identifier.is_empty() || identifier.len() > 256 {
        return Err(rejected());
    }
    let key: [u8; 32] = component(entries, T::PublicKey)
        .try_into()
        .map_err(|_| rejected())?;
    let public_key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| rejected())?;
    if public_key.is_weak() {
        return Err(rejected());
    }
    let mut material = [0; 32];
    Hkdf::<Sha512>::new(Some(b"Pair-Setup-Accessory-Sign-Salt"), shared)
        .expand(b"Pair-Setup-Accessory-Sign-Info", &mut material)
        .map_err(|_| rejected())?;
    let mut transcript = material.to_vec();
    transcript.extend_from_slice(&identifier);
    transcript.extend_from_slice(&key);
    let signature =
        Signature::from_slice(&component(entries, T::Signature)).map_err(|_| rejected())?;
    public_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| rejected())?;
    Ok(PeerIdentity {
        identifier,
        public_key,
    })
}

impl<R: RpPairingSocketProvider> RemotePairingClient<R> {
    pub(super) async fn verify_peer(&mut self, record: &RpPairingFile) -> Result<(), IdeviceError> {
        // Clear first, including when a previously authenticated client is reused.
        self.authenticated = false;
        self.encryption_key.clear();
        let peer = record.peer_identity.as_ref().ok_or_else(rejected)?;
        let private = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&private);
        self.send_pairing_data(plist!({
            "data": R::serialize_bytes(&tlv::serialize_tlv8(&[
                TLV8Entry { tlv_type: T::State, data: vec![1] },
                TLV8Entry { tlv_type: T::PublicKey, data: public.as_bytes().to_vec() },
            ])),
            "kind": "verifyManualPairing", "startNewSession": true
        }))
        .await?;
        let response =
            R::deserialize_bytes(self.receive_pairing_data().await?).ok_or_else(rejected)?;
        let entries = tlv::deserialize_tlv8(&response)?;
        require_state(&entries, 2)?;
        let peer_ephemeral: [u8; 32] = component(&entries, T::PublicKey)
            .try_into()
            .map_err(|_| rejected())?;
        let shared = private.diffie_hellman(&PublicKey::from(peer_ephemeral));
        if !shared.was_contributory() {
            return Err(rejected());
        }
        let mut key = [0; 32];
        Hkdf::<Sha512>::new(Some(b"Pair-Verify-Encrypt-Salt"), shared.as_bytes())
            .expand(b"Pair-Verify-Encrypt-Info", &mut key)
            .map_err(|_| rejected())?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(b"\0\0\0\0PV-Msg02"),
                component(&entries, T::EncryptedData).as_slice(),
            )
            .map_err(|_| rejected())?;
        let proof = tlv::deserialize_tlv8(&plaintext)?;
        if component(&proof, T::Identifier) != peer.identifier {
            return Err(rejected());
        }
        let signature =
            Signature::from_slice(&component(&proof, T::Signature)).map_err(|_| rejected())?;
        let mut transcript = Vec::with_capacity(64 + peer.identifier.len());
        transcript.extend_from_slice(&peer_ephemeral);
        transcript.extend_from_slice(&peer.identifier);
        transcript.extend_from_slice(public.as_bytes());
        peer.public_key
            .verify_strict(&transcript, &signature)
            .map_err(|_| rejected())?;

        // No host identity proof is released before authenticating the device.
        transcript.clear();
        transcript.extend_from_slice(public.as_bytes());
        transcript.extend_from_slice(record.identifier.as_bytes());
        transcript.extend_from_slice(&peer_ephemeral);
        let plaintext = tlv::serialize_tlv8(&[
            TLV8Entry {
                tlv_type: T::Identifier,
                data: record.identifier.as_bytes().to_vec(),
            },
            TLV8Entry {
                tlv_type: T::Signature,
                data: record.e_private_key.sign(&transcript).to_bytes().to_vec(),
            },
        ]);
        let encrypted = cipher
            .encrypt(Nonce::from_slice(b"\0\0\0\0PV-Msg03"), plaintext.as_slice())
            .map_err(|_| rejected())?;
        self.send_pairing_data(plist!({
            "data": R::serialize_bytes(&tlv::serialize_tlv8(&[
                TLV8Entry { tlv_type: T::State, data: vec![3] },
                TLV8Entry { tlv_type: T::EncryptedData, data: encrypted },
            ])),
            "kind": "verifyManualPairing", "startNewSession": false
        }))
        .await?;
        let response =
            R::deserialize_bytes(self.receive_pairing_data().await?).ok_or_else(rejected)?;
        require_state(&tlv::deserialize_tlv8(&response)?, 4)?;
        self.encryption_key = shared.as_bytes().to_vec();
        (self.client_cipher, self.server_cipher) = Self::derive_main_ciphers(&self.encryption_key);
        self.encrypted_sequence_number = 0;
        self.authenticated = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    #[cfg(target_os = "macos")]
    use ed25519_dalek::VerifyingKey;

    fn entry(tlv_type: T, data: impl Into<Vec<u8>>) -> TLV8Entry {
        TLV8Entry {
            tlv_type,
            data: data.into(),
        }
    }
    fn envelope(entries: &[TLV8Entry]) -> plist::Value {
        plist!({"event": {"_0": {"pairingData": {"_0": {
            "data": RpPairingSocket::<tokio::io::DuplexStream>::serialize_bytes(&tlv::serialize_tlv8(entries))
        }}}}})
    }
    fn payload(value: plist::Value) -> Vec<TLV8Entry> {
        let data = value
            .get_by("event")
            .unwrap()
            .get_by("_0")
            .unwrap()
            .get_by("pairingData")
            .unwrap()
            .get_by("_0")
            .unwrap()
            .get_by("data")
            .unwrap()
            .clone();
        tlv::deserialize_tlv8(
            &RpPairingSocket::<tokio::io::DuplexStream>::deserialize_bytes(data).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn setup_identity_rejects_modified_identity_key_and_signature() {
        let signer = SigningKey::from_bytes(&[36; 32]);
        let shared = [9; 64];
        let mut material = [0; 32];
        Hkdf::<Sha512>::new(Some(b"Pair-Setup-Accessory-Sign-Salt"), &shared)
            .expand(b"Pair-Setup-Accessory-Sign-Info", &mut material)
            .unwrap();
        let identifier = b"usb-device-identity";
        let mut transcript = material.to_vec();
        transcript.extend(identifier);
        transcript.extend(signer.verifying_key().as_bytes());
        let proof = vec![
            entry(T::Identifier, identifier),
            entry(T::PublicKey, signer.verifying_key().to_bytes()),
            entry(T::Signature, signer.sign(&transcript).to_bytes()),
        ];
        let identity = setup_identity(&proof, &shared).unwrap();
        assert_eq!(identity.identifier, identifier);
        assert_eq!(identity.public_key, signer.verifying_key());
        for index in 0..3 {
            let mut tampered = proof.clone();
            tampered[index].data[0] ^= 1;
            assert!(setup_identity(&tampered, &shared).is_err());
        }
        assert!(setup_identity(&proof, &[10; 64]).is_err());
    }

    #[test]
    fn authenticated_rpc_and_adversarial_handshakes() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for fault in [
                "none",
                "wrong-key",
                "wrong-id",
                "tampered",
                "wrong-transcript",
                "missing-proof",
                "bad-state",
                "low-order",
                "bad-final",
            ] {
                let (host, device) = tokio::io::duplex(16_384);
                let signer = SigningKey::from_bytes(&[19; 32]);
                let mut record = RpPairingFile::generate("test-host");
                record.peer_identity = Some(PeerIdentity {
                    identifier: b"test-device".to_vec(),
                    public_key: if fault == "wrong-key" {
                        SigningKey::from_bytes(&[28; 32]).verifying_key()
                    } else {
                        signer.verifying_key()
                    },
                });
                let host_identity = record.e_public_key;
                let host_identifier = record.identifier.clone();
                let task = tokio::spawn(async move {
                    let mut peer = RpPairingSocket::new_device(device);
                    let start = payload(peer.recv_plain().await.unwrap());
                    let host_public: [u8; 32] = component(&start, T::PublicKey).try_into().unwrap();
                    let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
                    let public = PublicKey::from(&secret);
                    let shared = secret.diffie_hellman(&PublicKey::from(host_public));
                    let mut key = [0; 32];
                    Hkdf::<Sha512>::new(Some(b"Pair-Verify-Encrypt-Salt"), shared.as_bytes())
                        .expand(b"Pair-Verify-Encrypt-Info", &mut key)
                        .unwrap();
                    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
                    let id = if fault == "wrong-id" {
                        b"other-phone".as_slice()
                    } else {
                        b"test-device".as_slice()
                    };
                    let mut transcript = public.as_bytes().to_vec();
                    transcript.extend_from_slice(id);
                    transcript.extend_from_slice(&host_public);
                    if fault == "wrong-transcript" {
                        transcript.reverse();
                    }
                    let proof = tlv::serialize_tlv8(&[
                        entry(T::Identifier, id),
                        entry(T::Signature, signer.sign(&transcript).to_bytes()),
                    ]);
                    let mut encrypted = cipher
                        .encrypt(Nonce::from_slice(b"\0\0\0\0PV-Msg02"), proof.as_slice())
                        .unwrap();
                    if fault == "tampered" {
                        encrypted[0] ^= 1;
                    }
                    let mut response = vec![
                        entry(T::State, [if fault == "bad-state" { 4 } else { 2 }]),
                        entry(
                            T::PublicKey,
                            if fault == "low-order" {
                                [0; 32]
                            } else {
                                *public.as_bytes()
                            },
                        ),
                    ];
                    if fault != "missing-proof" {
                        response.push(entry(T::EncryptedData, encrypted));
                    }
                    peer.send_plain(envelope(&response), 0).await.unwrap();
                    if fault != "none" && fault != "bad-final" {
                        use tokio::io::AsyncReadExt;
                        let mut byte = [0];
                        assert_eq!(
                            peer.inner.read(&mut byte).await.unwrap(),
                            0,
                            "must not release a host proof to a wrong peer"
                        );
                        return;
                    }
                    let finish = payload(peer.recv_plain().await.unwrap());
                    let proof = cipher
                        .decrypt(
                            Nonce::from_slice(b"\0\0\0\0PV-Msg03"),
                            component(&finish, T::EncryptedData).as_slice(),
                        )
                        .unwrap();
                    let proof = tlv::deserialize_tlv8(&proof).unwrap();
                    assert_eq!(component(&proof, T::Identifier), host_identifier.as_bytes());
                    let mut transcript = host_public.to_vec();
                    transcript.extend_from_slice(host_identifier.as_bytes());
                    transcript.extend_from_slice(public.as_bytes());
                    host_identity
                        .verify_strict(
                            &transcript,
                            &Signature::from_slice(&component(&proof, T::Signature)).unwrap(),
                        )
                        .unwrap();
                    peer.send_plain(
                        envelope(&[entry(T::State, [if fault == "bad-final" { 2 } else { 4 }])]),
                        1,
                    )
                    .await
                    .unwrap();
                    if fault == "bad-final" {
                        return;
                    }
                    let (client_cipher, server_cipher) = RemotePairingClient::<
                        RpPairingSocket<tokio::io::DuplexStream>,
                    >::derive_main_ciphers(
                        shared.as_bytes()
                    );
                    let request = peer.recv_plain().await.unwrap();
                    let encrypted = request
                        .get_by("message")
                        .unwrap()
                        .get_by("streamEncrypted")
                        .unwrap()
                        .get_by("_0")
                        .unwrap()
                        .clone();
                    let encrypted =
                        RpPairingSocket::<tokio::io::DuplexStream>::deserialize_bytes(encrypted)
                            .unwrap();
                    let request = client_cipher
                        .decrypt(Nonce::from_slice(&[0; 12]), encrypted.as_slice())
                        .unwrap();
                    let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
                    assert_eq!(
                        request["request"]["_0"]["createListener"]["transportProtocolType"],
                        "tcp"
                    );
                    let response = server_cipher
                        .encrypt(
                            Nonce::from_slice(&[0; 12]),
                            br#"{"response":{"_1":{"createListener":{"port":54321}}}}"#.as_slice(),
                        )
                        .unwrap();
                    peer.send_encrypted(response, 2).await.unwrap();
                });
                let mut client = RemotePairingClient::new(RpPairingSocket::new(host), "test-host");
                // Prior session material must not survive any failing reauthentication.
                client.encryption_key = vec![99; 32];
                client.authenticated = true;
                let result = client.validate_pairing(&mut record).await;
                if fault == "none" {
                    result.unwrap();
                    assert_eq!(client.create_tcp_listener().await.unwrap(), 54321);
                } else {
                    assert!(result.is_err(), "{fault}");
                    assert!(client.encryption_key().is_empty());
                    assert!(client.create_tcp_listener().await.is_err());
                }
                drop(client);
                task.await.unwrap();
            }
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires installed private Apple CoreUtils framework and clang; run explicitly on macOS"]
    fn apple_pairing_framework_interoperability() {
        use std::io::{BufRead, Write};
        use std::process::{Command, Stdio};
        #[derive(Debug)]
        struct ApplePeer {
            process: std::process::Child,
            input: std::process::ChildStdin,
            output: std::io::BufReader<std::process::ChildStdout>,
        }
        impl Drop for ApplePeer {
            fn drop(&mut self) {
                let _ = self.process.kill();
                let _ = self.process.wait();
            }
        }
        impl ApplePeer {
            fn line(&mut self, prefix: &str) -> Vec<u8> {
                let mut line = String::new();
                self.output.read_line(&mut line).unwrap();
                let encoded = line
                    .trim()
                    .strip_prefix(prefix)
                    .expect("unexpected Apple pairing response");
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap()
            }
        }
        impl RpPairingSocketProvider for ApplePeer {
            fn serialize_bytes(b: &[u8]) -> plist::Value {
                plist::Value::Data(b.to_vec())
            }
            fn deserialize_bytes(v: plist::Value) -> Option<Vec<u8>> {
                v.into_data()
            }
            fn send_plain(
                &mut self,
                value: impl Serialize,
                _: usize,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + '_>>
            {
                let value = plist::to_value(&value).unwrap();
                let data = value
                    .get_by("event")
                    .unwrap()
                    .get_by("_0")
                    .unwrap()
                    .get_by("pairingData")
                    .unwrap()
                    .get_by("_0")
                    .unwrap()
                    .get_by("data")
                    .unwrap()
                    .as_data()
                    .unwrap();
                writeln!(
                    self.input,
                    "{}",
                    base64::engine::general_purpose::STANDARD.encode(data)
                )
                .unwrap();
                self.input.flush().unwrap();
                Box::pin(async { Ok(()) })
            }
            fn send_encrypted(
                &mut self,
                _: Vec<u8>,
                _: usize,
            ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), IdeviceError>> + Send + '_>>
            {
                unreachable!()
            }
            fn recv_plain(
                &mut self,
            ) -> std::pin::Pin<
                Box<dyn Future<Output = Result<plist::Value, IdeviceError>> + Send + '_>,
            > {
                let data = self.line("TLV ");
                Box::pin(async move {
                    Ok(plist!({"event":{"_0":{"pairingData":{"_0":{"data":data}}}}}))
                })
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("ApplePairingPeer");
        assert!(
            Command::new("clang")
                .args(["-fobjc-arc", "-framework", "Foundation"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/native/iphone/ApplePairingPeer.m"
                ))
                .arg("-o")
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
        for mode in ["verify", "setup"] {
            let mut record = RpPairingFile::generate("interop-host");
            let mut process = Command::new(&binary)
                .args([
                    mode,
                    &record.identifier,
                    &base64::engine::general_purpose::STANDARD
                        .encode(record.e_public_key.as_bytes()),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut peer = ApplePeer {
                input: process.stdin.take().unwrap(),
                output: std::io::BufReader::new(process.stdout.take().unwrap()),
                process,
            };
            let public_key =
                VerifyingKey::from_bytes(&peer.line("PUB ").try_into().unwrap()).unwrap();
            record.peer_identity = Some(PeerIdentity {
                identifier: b"D733FF81-410B-4F4D-9836-A963FD2C844B".to_vec(),
                public_key,
            });
            let mut client = RemotePairingClient::new(peer, "interop-host");
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                if mode == "verify" {
                    client.validate_pairing(&mut record).await.unwrap();
                } else {
                    client
                        .pair(&mut record, || async { "000000".into() })
                        .await
                        .unwrap();
                    assert_eq!(
                        record.peer_identity.as_ref().unwrap().public_key,
                        public_key
                    );
                }
            });
            let native_key = client.inner.line("DONE ");
            let mut expected = [0; 32];
            Hkdf::<Sha512>::new(None, client.encryption_key())
                .expand(b"ServerEncrypt-main", &mut expected)
                .unwrap();
            assert_eq!(
                native_key, expected,
                "must derive the same authenticated RPC key as Apple"
            );
        }
    }
}
