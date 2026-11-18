// Jackson Coxson
//! Manual TLS 1.2 PSK-AES128-CBC-SHA implementation.
//!
//! This implements just enough of TLS 1.2 to negotiate
//! `TLS_PSK_WITH_AES_128_CBC_SHA` (0x008C) with no certificates or DH.
//! The result is an encrypted stream suitable for CDTunnel.
//! We did this ourselves because rustls won't :(

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use std::pin::Pin;
use std::task::{Context, Poll};
use subtle::{Choice, ConstantTimeEq};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use idevice::IdeviceError;

// TLS 1.2 constants
const TLS_12: [u8; 2] = [0x03, 0x03];
const CT_HANDSHAKE: u8 = 0x16;
const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CT_APPLICATION_DATA: u8 = 0x17;
const CT_ALERT: u8 = 0x15;
/// Maximum plaintext bytes per TLS record (RFC 5246 §6.2.1)
const TLS_MAX_PLAINTEXT: usize = 16384;
const TLS_MAX_CIPHERTEXT: usize = TLS_MAX_PLAINTEXT + 2048;
const MAX_HANDSHAKE: usize = 65536;
const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const HS_SERVER_HELLO_DONE: u8 = 0x0E;
const HS_CLIENT_KEY_EXCHANGE: u8 = 0x10;
const HS_FINISHED: u8 = 0x14;
// Offer both; device typically picks AES256-CBC-SHA384
const PSK_CIPHER_SUITES: &[[u8; 2]] = &[
    [0x00, 0xAF], // TLS_PSK_WITH_AES_256_CBC_SHA384 (preferred by iOS)
    [0x00, 0x8C], // TLS_PSK_WITH_AES_128_CBC_SHA (fallback)
];

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;
type HmacSha384 = Hmac<sha2::Sha384>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Selected cipher suite parameters
#[derive(Clone, Copy, Debug)]
enum CipherSuite {
    Aes128CbcSha,    // 0x008C: 16-byte key, 20-byte MAC (SHA1), PRF=SHA256
    Aes256CbcSha384, // 0x00AF: 32-byte key, 48-byte MAC (SHA384), PRF=SHA384
}

impl CipherSuite {
    fn from_bytes(b: [u8; 2]) -> Option<Self> {
        match b {
            [0x00, 0x8C] => Some(Self::Aes128CbcSha),
            [0x00, 0xAF] => Some(Self::Aes256CbcSha384),
            _ => None,
        }
    }
    fn enc_key_len(self) -> usize {
        match self {
            Self::Aes128CbcSha => 16,
            Self::Aes256CbcSha384 => 32,
        }
    }
    fn mac_key_len(self) -> usize {
        match self {
            Self::Aes128CbcSha => 20,
            Self::Aes256CbcSha384 => 48,
        }
    }
}

struct KeyBlock {
    client_mac_key: Vec<u8>,
    server_mac_key: Vec<u8>,
    client_write_key: Vec<u8>,
    server_write_key: Vec<u8>,
    suite: CipherSuite,
}

fn hmac_compute(key: &[u8], data: &[u8], suite: CipherSuite) -> Vec<u8> {
    match suite {
        CipherSuite::Aes128CbcSha => {
            // PRF uses SHA256 for P_hash, but record MAC uses SHA1
            let mut mac = HmacSha256::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        CipherSuite::Aes256CbcSha384 => {
            let mut mac = HmacSha384::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// TLS 1.2 PRF: P_hash with the suite's PRF hash
fn prf(secret: &[u8], label: &[u8], seed: &[u8], len: usize, suite: CipherSuite) -> Vec<u8> {
    let mut label_seed = label.to_vec();
    label_seed.extend_from_slice(seed);

    let mut a = hmac_compute(secret, &label_seed, suite);
    let mut out = Vec::with_capacity(len);

    while out.len() < len {
        let mut input = a.clone();
        input.extend_from_slice(&label_seed);
        out.extend_from_slice(&hmac_compute(secret, &input, suite));
        a = hmac_compute(secret, &a, suite);
    }
    out.truncate(len);
    out
}

/// PSK premaster secret (RFC 4279 §2)
fn psk_premaster(psk: &[u8]) -> Vec<u8> {
    let psk_len = psk.len() as u16;
    let mut pm = Vec::with_capacity(4 + psk.len() * 2);
    pm.extend_from_slice(&psk_len.to_be_bytes());
    pm.extend(std::iter::repeat_n(0u8, psk.len()));
    pm.extend_from_slice(&psk_len.to_be_bytes());
    pm.extend_from_slice(psk);
    pm
}

fn derive_master_secret(
    psk: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: CipherSuite,
) -> Vec<u8> {
    let premaster = psk_premaster(psk);
    let mut seed = client_random.to_vec();
    seed.extend_from_slice(server_random);
    prf(&premaster, b"master secret", &seed, 48, suite)
}

fn derive_key_block(
    master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: CipherSuite,
) -> KeyBlock {
    let mut seed = server_random.to_vec();
    seed.extend_from_slice(client_random);
    let mac_len = suite.mac_key_len();
    let key_len = suite.enc_key_len();
    let total = mac_len * 2 + key_len * 2;
    let kb = prf(master, b"key expansion", &seed, total, suite);
    let mut pos = 0;
    let client_mac_key = kb[pos..pos + mac_len].to_vec();
    pos += mac_len;
    let server_mac_key = kb[pos..pos + mac_len].to_vec();
    pos += mac_len;
    let client_write_key = kb[pos..pos + key_len].to_vec();
    pos += key_len;
    let server_write_key = kb[pos..pos + key_len].to_vec();
    KeyBlock {
        client_mac_key,
        server_mac_key,
        client_write_key,
        server_write_key,
        suite,
    }
}

fn compute_mac(mac_key: &[u8], seq: u64, ct: u8, data: &[u8], suite: CipherSuite) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&[ct, 0x03, 0x03]);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);

    match suite {
        CipherSuite::Aes128CbcSha => {
            let mut mac = HmacSha1::new_from_slice(mac_key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
        CipherSuite::Aes256CbcSha384 => {
            let mut mac = HmacSha384::new_from_slice(mac_key).unwrap();
            mac.update(&buf);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn encrypt_record(keys: &KeyBlock, seq: u64, ct: u8, plaintext: &[u8]) -> Vec<u8> {
    let mac = compute_mac(&keys.client_mac_key, seq, ct, plaintext, keys.suite);

    let mut payload = plaintext.to_vec();
    payload.extend_from_slice(&mac);

    // PKCS#7 padding (block size = 16 for both AES-128 and AES-256)
    let pad_len = 16 - (payload.len() % 16);
    payload.extend(std::iter::repeat_n(pad_len as u8 - 1, pad_len));

    let mut iv = [0u8; 16];
    rand::fill(&mut iv);

    let ciphertext = match keys.suite {
        CipherSuite::Aes128CbcSha => {
            let enc = Aes128CbcEnc::new(keys.client_write_key[..16].into(), &iv.into());
            enc.encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(&payload)
        }
        CipherSuite::Aes256CbcSha384 => {
            let enc = Aes256CbcEnc::new(keys.client_write_key[..32].into(), &iv.into());
            enc.encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(&payload)
        }
    };

    let mut result = iv.to_vec();
    result.extend_from_slice(&ciphertext);
    result
}

fn decrypt_record(
    keys: &KeyBlock,
    is_server: bool,
    seq: u64,
    ct: u8,
    encrypted: &[u8],
) -> Result<Vec<u8>, IdeviceError> {
    if encrypted.len() < 32 || encrypted.len() > TLS_MAX_CIPHERTEXT {
        return Err(record_authentication_error());
    }

    let iv = &encrypted[..16];
    let ciphertext = &encrypted[16..];
    let read_key = if is_server {
        &keys.server_write_key
    } else {
        &keys.client_write_key
    };
    let mac_key = if is_server {
        &keys.server_mac_key
    } else {
        &keys.client_mac_key
    };

    let decrypted = match keys.suite {
        CipherSuite::Aes128CbcSha => {
            let dec = Aes128CbcDec::new(read_key[..16].into(), iv.into());
            dec.decrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(ciphertext)
                .map_err(|_| record_authentication_error())?
        }
        CipherSuite::Aes256CbcSha384 => {
            let dec = Aes256CbcDec::new(read_key[..32].into(), iv.into());
            dec.decrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(ciphertext)
                .map_err(|_| record_authentication_error())?
        }
    };

    if decrypted.is_empty() {
        return Err(record_authentication_error());
    }

    let mac_len = keys.suite.mac_key_len();
    // Authenticate every possible TLS padding length. Loop bounds, slices and
    // HMAC work depend only on public ciphertext length, never the decrypted
    // padding byte. This deliberately trades throughput for fixed work rather
    // than attempting a custom constant-time variable-length HMAC primitive.
    let mut accepted = Choice::from(0);
    for padding in 1..=256.min(decrypted.len().saturating_sub(mac_len)) {
        let content_len = decrypted.len() - padding;
        let plaintext = &decrypted[..content_len - mac_len];
        let received_mac = &decrypted[content_len - mac_len..content_len];
        let padding_valid = decrypted[content_len..]
            .iter()
            .fold(Choice::from(1), |valid, byte| {
                valid & byte.ct_eq(&((padding - 1) as u8))
            });
        let expected = compute_mac(mac_key, seq, ct, plaintext, keys.suite);
        accepted |= padding_valid
            & expected.ct_eq(received_mac)
            & Choice::from((plaintext.len() <= TLS_MAX_PLAINTEXT) as u8);
    }
    if !bool::from(accepted) {
        return Err(record_authentication_error());
    }
    let plaintext_len = decrypted.len() - (*decrypted.last().unwrap() as usize + 1) - mac_len;
    Ok(decrypted[..plaintext_len].to_vec())
}

fn record_authentication_error() -> IdeviceError {
    IdeviceError::InternalError("TLS record authentication failed".into())
}

fn finished_verify_data(
    master: &[u8],
    label: &[u8],
    transcript: &[u8],
    suite: CipherSuite,
) -> [u8; 12] {
    use sha2::Digest;
    let hash: Vec<u8> = match suite {
        CipherSuite::Aes128CbcSha => sha2::Sha256::digest(transcript).to_vec(),
        CipherSuite::Aes256CbcSha384 => sha2::Sha384::digest(transcript).to_vec(),
    };
    prf(master, label, &hash, 12, suite).try_into().unwrap()
}

fn make_record(ct: u8, payload: &[u8]) -> Vec<u8> {
    let mut rec = vec![ct, 0x03, 0x03];
    rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    rec.extend_from_slice(payload);
    rec
}

fn make_handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = vec![msg_type];
    let len = body.len() as u32;
    msg.extend_from_slice(&len.to_be_bytes()[1..]); // 3-byte length
    msg.extend_from_slice(body);
    msg
}

async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u8, Vec<u8>), IdeviceError> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    if header[1..3] != TLS_12 {
        return Err(record_authentication_error());
    }
    let ct = header[0];
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > TLS_MAX_CIPHERTEXT {
        return Err(record_authentication_error());
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok((ct, payload))
}

/// Consume complete messages, retaining a partial message for the next record.
fn parse_handshake_messages(data: &mut Vec<u8>) -> Result<Vec<(u8, Vec<u8>)>, IdeviceError> {
    let mut msgs = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let msg_type = data[pos];
        let msg_len = u32::from_be_bytes([0, data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        if msg_len > MAX_HANDSHAKE {
            return Err(record_authentication_error());
        }
        if pos + 4 + msg_len > data.len() {
            break;
        }
        msgs.push((msg_type, data[pos..pos + 4 + msg_len].to_vec()));
        pos += 4 + msg_len;
    }
    data.drain(..pos);
    Ok(msgs)
}

/// Perform TLS 1.2 PSK handshake and return an encrypted stream.
pub async fn tls_psk_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut stream: S,
    psk: &[u8],
) -> Result<TlsPskStream<S>, IdeviceError> {
    let mut client_random = [0u8; 32];
    rand::fill(&mut client_random);
    let mut server_random = [0u8; 32];
    let mut selected_cipher = [0u8; 2];
    let mut transcript = Vec::new();

    // 1. ClientHello
    let mut ch_body = Vec::new();
    ch_body.extend_from_slice(&TLS_12);
    ch_body.extend_from_slice(&client_random);
    ch_body.push(0x00); // session_id len = 0
    let suites_len = (PSK_CIPHER_SUITES.len() * 2) as u16;
    ch_body.extend_from_slice(&suites_len.to_be_bytes());
    for suite in PSK_CIPHER_SUITES {
        ch_body.extend_from_slice(suite);
    }
    ch_body.extend_from_slice(&[0x01, 0x00]); // compression: null
    let ch = make_handshake(HS_CLIENT_HELLO, &ch_body);
    transcript.extend_from_slice(&ch);
    stream.write_all(&make_record(CT_HANDSHAKE, &ch)).await?;
    debug!("Sent ClientHello");

    // Reassemble messages independently of record boundaries. Do not mistake
    // bytes inside a random or PSK identity hint for ServerHelloDone.
    let mut pending_handshake = Vec::new();
    let mut hello_seen = false;
    let mut hello_done = false;
    while !hello_done {
        let (ct, payload) = read_record(&mut stream).await?;
        if ct != CT_HANDSHAKE || transcript.len() + payload.len() > MAX_HANDSHAKE {
            return Err(record_authentication_error());
        }
        pending_handshake.extend_from_slice(&payload);
        for (msg_type, message) in parse_handshake_messages(&mut pending_handshake)? {
            if hello_done {
                return Err(record_authentication_error());
            }
            match msg_type {
                HS_SERVER_HELLO if !hello_seen => {
                    if message.len() < 42 || message[4..6] != TLS_12 {
                        return Err(record_authentication_error());
                    }
                    let sid_len = message[38] as usize;
                    let end = 42 + sid_len;
                    if sid_len > 32 || message.len() < end || message[end - 1] != 0 {
                        return Err(record_authentication_error());
                    }
                    // No TLS extensions were offered by this client.
                    if message.len() != end
                        && (message.len() != end + 2 || message[end..] != [0, 0])
                    {
                        return Err(record_authentication_error());
                    }
                    server_random.copy_from_slice(&message[6..38]);
                    selected_cipher.copy_from_slice(&message[39 + sid_len..41 + sid_len]);
                    hello_seen = true;
                }
                0x0c if hello_seen => {
                    if message.len() < 6
                        || u16::from_be_bytes([message[4], message[5]]) as usize
                            != message.len() - 6
                    {
                        return Err(record_authentication_error());
                    }
                }
                HS_SERVER_HELLO_DONE if hello_seen && message.len() == 4 => hello_done = true,
                _ => return Err(record_authentication_error()),
            }
            transcript.extend_from_slice(&message);
        }
    }
    if !pending_handshake.is_empty() {
        return Err(record_authentication_error());
    }

    // 3. Determine cipher suite and derive keys
    let suite = CipherSuite::from_bytes(selected_cipher).ok_or_else(|| {
        IdeviceError::InternalError(format!(
            "Server selected unsupported cipher: {selected_cipher:02x?}"
        ))
    })?;
    debug!("Using cipher suite: {suite:?}");

    let master = derive_master_secret(psk, &client_random, &server_random, suite);
    let keys = derive_key_block(&master, &client_random, &server_random, suite);

    // 4. ClientKeyExchange (empty PSK identity)
    let cke = make_handshake(HS_CLIENT_KEY_EXCHANGE, &[0x00, 0x00]);
    transcript.extend_from_slice(&cke);
    stream.write_all(&make_record(CT_HANDSHAKE, &cke)).await?;
    debug!("Sent ClientKeyExchange");

    // 5. ChangeCipherSpec
    stream
        .write_all(&make_record(CT_CHANGE_CIPHER_SPEC, &[0x01]))
        .await?;
    debug!("Sent ChangeCipherSpec");

    // 6. Client Finished (encrypted)
    let vd = finished_verify_data(&master, b"client finished", &transcript, suite);
    let fin = make_handshake(HS_FINISHED, &vd);
    transcript.extend_from_slice(&fin);
    let enc_fin = encrypt_record(&keys, 0, CT_HANDSHAKE, &fin);
    stream
        .write_all(&make_record(CT_HANDSHAKE, &enc_fin))
        .await?;
    stream.flush().await?;
    debug!("Sent encrypted Finished");

    // 7. Read server ChangeCipherSpec + Finished
    let mut server_seq: u64 = 0;
    let mut cipher_changed = false;
    loop {
        let (ct, payload) = read_record(&mut stream).await?;
        match ct {
            CT_CHANGE_CIPHER_SPEC if !cipher_changed && payload == [1] => {
                cipher_changed = true;
            }
            CT_HANDSHAKE if cipher_changed => {
                let plaintext = decrypt_record(&keys, true, server_seq, CT_HANDSHAKE, &payload)?;
                server_seq += 1;
                pending_handshake.extend_from_slice(&plaintext);
                if pending_handshake.len() > 16 {
                    return Err(record_authentication_error());
                }
                let messages = parse_handshake_messages(&mut pending_handshake)?;
                if let Some((msg_type, message)) = messages.first() {
                    if *msg_type != HS_FINISHED
                        || messages.len() != 1
                        || message.len() != 16
                        || !pending_handshake.is_empty()
                    {
                        return Err(record_authentication_error());
                    }
                    // A valid record MAC does not substitute for transcript authentication.
                    let server_vd =
                        finished_verify_data(&master, b"server finished", &transcript, suite);
                    if message[4..] != server_vd {
                        return Err(record_authentication_error());
                    }
                    break;
                }
            }
            _ => return Err(record_authentication_error()),
        }
    }

    debug!("TLS-PSK handshake complete");

    Ok(TlsPskStream {
        inner: stream,
        keys,
        write_seq: 1, // seq 0 was used for client Finished
        read_seq: server_seq,
        read_buf: Vec::new(),
        pending_record: Vec::new(),
        pending_record_total: 0,
        write_buf: Vec::new(),
        write_closing: false,
        closed: false,
    })
}

/// An encrypted TLS-PSK stream implementing AsyncRead + AsyncWrite.
pub struct TlsPskStream<S> {
    inner: S,
    keys: KeyBlock,
    write_seq: u64,
    read_seq: u64,
    /// Decrypted plaintext buffered for reads
    read_buf: Vec<u8>,
    /// Partial inbound TLS record being assembled
    pending_record: Vec<u8>,
    /// Expected total bytes for the current inbound record (5 + body_len), 0 if unknown
    pending_record_total: usize,
    /// Partial outbound TLS record waiting to be flushed
    write_buf: Vec<u8>,
    write_closing: bool,
    closed: bool,
}

impl<S> std::fmt::Debug for TlsPskStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsPskStream")
            .field("write_seq", &self.write_seq)
            .field("read_seq", &self.read_seq)
            .finish()
    }
}

// AsyncRead: assemble complete TLS records across multiple poll_read calls
impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncRead for TlsPskStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 || this.closed {
            return Poll::Ready(Ok(()));
        }

        // 1. Serve from decrypted buffer first
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        // 2. Continue assembling a TLS record
        loop {
            // If we have the header (5 bytes), compute total needed
            if this.pending_record.len() >= 5 && this.pending_record_total == 0 {
                let body_len =
                    u16::from_be_bytes([this.pending_record[3], this.pending_record[4]]) as usize;
                if this.pending_record[1..3] != TLS_12 || body_len > TLS_MAX_CIPHERTEXT {
                    this.closed = true;
                    return Poll::Ready(Err(std::io::Error::other("Invalid TLS record")));
                }
                this.pending_record_total = 5 + body_len;
            }

            // If we have a complete record, decrypt it
            if this.pending_record_total > 0
                && this.pending_record.len() >= this.pending_record_total
            {
                let ct = this.pending_record[0];
                let body = this.pending_record[5..this.pending_record_total].to_vec();
                this.pending_record.drain(..this.pending_record_total);
                this.pending_record_total = 0;

                match decrypt_record(&this.keys, true, this.read_seq, ct, &body) {
                    Ok(plaintext) => {
                        this.read_seq += 1;
                        match ct {
                            CT_APPLICATION_DATA if plaintext.is_empty() => continue,
                            CT_APPLICATION_DATA => {}
                            CT_ALERT if plaintext == [1, 0] => {
                                this.closed = true;
                                return Poll::Ready(Ok(()));
                            }
                            _ => {
                                this.closed = true;
                                return Poll::Ready(Err(std::io::Error::other(
                                    "Unexpected TLS control record",
                                )));
                            }
                        }
                        let n = buf.remaining().min(plaintext.len());
                        buf.put_slice(&plaintext[..n]);
                        if n < plaintext.len() {
                            this.read_buf.extend_from_slice(&plaintext[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Err(_) => {
                        this.closed = true;
                        return Poll::Ready(Err(std::io::Error::other(
                            "TLS record authentication failed",
                        )));
                    }
                }
            }

            // Need more data from the underlying stream
            let mut tmp = [0u8; 16384];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = tmp_buf.filled().len();
                    if n == 0 {
                        this.closed = true;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "TLS stream ended without close_notify",
                        )));
                    }
                    this.pending_record.extend_from_slice(&tmp[..n]);
                    // Loop back to check if we now have a complete record
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncWrite for TlsPskStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if this.write_closing {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        // Flush any pending partial write first
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Clamp to TLS max record size to avoid oversized records
        let chunk = &data[..data.len().min(TLS_MAX_PLAINTEXT)];

        // Encrypt the new data into a TLS record
        let encrypted = encrypt_record(&this.keys, this.write_seq, CT_APPLICATION_DATA, chunk);
        let record = make_record(CT_APPLICATION_DATA, &encrypted);
        this.write_seq += 1;

        match Pin::new(&mut this.inner).poll_write(cx, &record) {
            Poll::Ready(Ok(0)) => {
                this.write_seq -= 1;
                Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Ok(written)) => {
                if written < record.len() {
                    // Buffer the unsent remainder
                    this.write_buf.extend_from_slice(&record[written..]);
                }
                Poll::Ready(Ok(chunk.len()))
            }
            Poll::Ready(Err(e)) => {
                this.write_seq -= 1;
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                // Buffer the entire record for later flush
                this.write_buf = record;
                Poll::Ready(Ok(chunk.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Flush buffered write data first
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        let this = self.as_mut().get_mut();
        if !this.write_closing {
            let encrypted = encrypt_record(&this.keys, this.write_seq, CT_ALERT, &[1, 0]);
            this.write_buf = make_record(CT_ALERT, &encrypted);
            this.write_seq += 1;
            this.write_closing = true;
        }
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn keys(suite: CipherSuite) -> KeyBlock {
        derive_key_block(&[7; 48], &[2; 32], &[3; 32], suite)
    }

    fn server_keys(keys: &KeyBlock) -> KeyBlock {
        KeyBlock {
            client_mac_key: keys.server_mac_key.clone(),
            server_mac_key: keys.client_mac_key.clone(),
            client_write_key: keys.server_write_key.clone(),
            server_write_key: keys.client_write_key.clone(),
            suite: keys.suite,
        }
    }

    #[derive(Default)]
    struct Wire {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        pending: bool,
        shutdown: bool,
        next_write_result: Option<std::io::Result<usize>>,
    }
    impl AsyncRead for Wire {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.input).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for Wire {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if let Some(result) = self.next_write_result.take() {
                return Poll::Ready(result);
            }
            if std::mem::take(&mut self.pending) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let count = bytes.len().min(7);
            self.output.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.shutdown = true;
            Poll::Ready(Ok(()))
        }
    }

    fn encrypted_stream(input: Vec<u8>, suite: CipherSuite) -> TlsPskStream<Wire> {
        TlsPskStream {
            inner: Wire {
                input: Cursor::new(input),
                pending: true,
                ..Wire::default()
            },
            keys: keys(suite),
            write_seq: 0,
            read_seq: 0,
            read_buf: Vec::new(),
            pending_record: Vec::new(),
            pending_record_total: 0,
            write_buf: Vec::new(),
            write_closing: false,
            closed: false,
        }
    }

    #[test]
    fn buffered_writes_deliver_each_plaintext_once_and_shutdown_flushes() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for suite in [CipherSuite::Aes128CbcSha, CipherSuite::Aes256CbcSha384] {
                let mut stream = encrypted_stream(Vec::new(), suite);
                stream.write_all(b"first").await.unwrap();
                stream.write_all(b"second message").await.unwrap();
                stream.flush().await.unwrap();
                stream.inner.pending = true;
                stream.shutdown().await.unwrap();
                stream.shutdown().await.unwrap();
                assert!(stream.inner.shutdown);
                let mut wire = stream.inner.output.as_slice();
                for (seq, expected) in [b"first".as_slice(), b"second message"]
                    .into_iter()
                    .enumerate()
                {
                    let (ct, body) = read_record(&mut wire).await.unwrap();
                    assert_eq!(ct, CT_APPLICATION_DATA);
                    assert_eq!(
                        decrypt_record(&stream.keys, false, seq as u64, ct, &body).unwrap(),
                        expected
                    );
                }
                let (ct, body) = read_record(&mut wire).await.unwrap();
                assert_eq!(ct, CT_ALERT);
                assert_eq!(
                    decrypt_record(&stream.keys, false, 2, ct, &body).unwrap(),
                    [1, 0]
                );
                assert!(
                    wire.is_empty(),
                    "plaintext must not be sent twice after Pending"
                );
                let mut receiver = encrypted_stream(stream.inner.output.clone(), suite);
                receiver.keys = server_keys(&stream.keys);
                let mut plaintext = Vec::new();
                receiver.read_to_end(&mut plaintext).await.unwrap();
                assert_eq!(plaintext, b"firstsecond message");
                assert!(stream.write(b"after shutdown").await.is_err());
            }
        });
    }

    #[test]
    fn initial_write_failures_allow_retry_without_skipping_record_sequence() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for suite in [CipherSuite::Aes128CbcSha, CipherSuite::Aes256CbcSha384] {
                for kind in [
                    std::io::ErrorKind::BrokenPipe,
                    std::io::ErrorKind::WriteZero,
                ] {
                    let mut stream = encrypted_stream(Vec::new(), suite);
                    stream.inner.next_write_result = Some(match kind {
                        std::io::ErrorKind::WriteZero => Ok(0),
                        _ => Err(kind.into()),
                    });
                    assert_eq!(stream.write(b"retry").await.unwrap_err().kind(), kind);
                    assert!(stream.inner.output.is_empty());
                    stream.write_all(b"retry").await.unwrap();
                    stream.write_all(b"next").await.unwrap();
                    stream.flush().await.unwrap();

                    let mut wire = stream.inner.output.as_slice();
                    for (seq, expected) in [b"retry".as_slice(), b"next"].into_iter().enumerate() {
                        let (ct, body) = read_record(&mut wire).await.unwrap();
                        assert_eq!(ct, CT_APPLICATION_DATA);
                        assert_eq!(
                            decrypt_record(&stream.keys, false, seq as u64, ct, &body)
                                .unwrap_or_else(|error| panic!("{suite:?}, {kind:?}: {error}")),
                            expected
                        );
                    }
                    assert!(
                        wire.is_empty(),
                        "failed writes must not duplicate plaintext"
                    );
                }
            }
        });
    }

    #[test]
    fn reads_skip_empty_data_and_never_expose_control_records() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for suite in [CipherSuite::Aes128CbcSha, CipherSuite::Aes256CbcSha384] {
                let keys = server_keys(&keys(suite));
                let mut wire = Vec::new();
                for (seq, ct, data) in [
                    (0, CT_APPLICATION_DATA, b"".as_slice()),
                    (1, CT_APPLICATION_DATA, b"payload"),
                    (2, CT_ALERT, &[1, 0]),
                ] {
                    wire.extend(make_record(ct, &encrypt_record(&keys, seq, ct, data)));
                }
                let mut stream = encrypted_stream(wire, suite);
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                assert_eq!(data, b"payload");
                for ct in [CT_HANDSHAKE, CT_ALERT] {
                    let wire = make_record(ct, &encrypt_record(&keys, 0, ct, &[2, 40]));
                    assert!(encrypted_stream(wire, suite).read_u8().await.is_err());
                }
                let wire = make_record(
                    CT_APPLICATION_DATA,
                    &encrypt_record(&keys, 0, CT_APPLICATION_DATA, b"cut"),
                );
                assert!(
                    encrypted_stream(wire.clone(), suite)
                        .read_to_end(&mut Vec::new())
                        .await
                        .is_err(),
                    "complete application record without close_notify is still truncation"
                );
                assert!(
                    encrypted_stream(wire[..wire.len() - 1].to_vec(), suite)
                        .read_u8()
                        .await
                        .is_err()
                );
            }
        });
    }

    #[test]
    fn malformed_padding_and_macs_return_uniform_errors_without_panicking() {
        for suite in [CipherSuite::Aes128CbcSha, CipherSuite::Aes256CbcSha384] {
            let keys = keys(suite);
            for padding in [1, 16, 17, 255, 256] {
                let plaintext = vec![71; (16 - (keys.suite.mac_key_len() + padding) % 16) % 16];
                let mut payload = plaintext.clone();
                payload.extend(compute_mac(
                    &keys.client_mac_key,
                    12,
                    CT_APPLICATION_DATA,
                    &plaintext,
                    suite,
                ));
                payload.extend(std::iter::repeat_n((padding - 1) as u8, padding));
                for fault in ["none", "padding", "mac"] {
                    let mut content = payload.clone();
                    if fault == "padding" {
                        *content.last_mut().unwrap() ^= 1;
                    }
                    if fault == "mac" {
                        content[plaintext.len()] ^= 1;
                    }
                    let iv = [0; 16];
                    let encrypted = match suite {
                        CipherSuite::Aes128CbcSha => {
                            Aes128CbcEnc::new(keys.client_write_key[..16].into(), &iv.into())
                                .encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(
                                &content,
                            )
                        }
                        CipherSuite::Aes256CbcSha384 => {
                            Aes256CbcEnc::new(keys.client_write_key[..32].into(), &iv.into())
                                .encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(
                                &content,
                            )
                        }
                    };
                    let mut record = iv.to_vec();
                    record.extend(encrypted);
                    let result = decrypt_record(&keys, false, 12, CT_APPLICATION_DATA, &record);
                    if fault == "none" {
                        assert_eq!(result.unwrap(), plaintext);
                    } else {
                        assert_eq!(
                            result.unwrap_err().to_string(),
                            record_authentication_error().to_string()
                        );
                    }
                }
            }
        }
        let keys = keys(CipherSuite::Aes128CbcSha);
        for last in [0, 1, 15, 16, 255] {
            let mut block = [0; 16];
            block[15] = last;
            let iv = [0; 16];
            let ciphertext =
                Aes128CbcEnc::new(keys.client_write_key[..16].into(), &iv.into())
                    .encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(&block);
            let mut record = iv.to_vec();
            record.extend(ciphertext);
            assert_eq!(
                decrypt_record(&keys, false, 0, CT_APPLICATION_DATA, &record)
                    .unwrap_err()
                    .to_string(),
                record_authentication_error().to_string()
            );
        }
        let record = encrypt_record(&keys, 1, CT_APPLICATION_DATA, b"valid");
        assert_eq!(
            decrypt_record(&keys, false, 1, CT_APPLICATION_DATA, &record).unwrap(),
            b"valid"
        );
        assert!(decrypt_record(&keys, false, 2, CT_APPLICATION_DATA, &record).is_err());
    }

    async fn server(mut stream: tokio::io::DuplexStream, suite: CipherSuite, bad_finished: bool) {
        let (_, hello) = read_record(&mut stream).await.unwrap();
        let client_random: [u8; 32] = hello[6..38].try_into().unwrap();
        let random = [0x0e; 32];
        let mut body = TLS_12.to_vec();
        body.extend(random);
        body.push(0);
        body.extend(match suite {
            CipherSuite::Aes128CbcSha => [0, 0x8c],
            CipherSuite::Aes256CbcSha384 => [0, 0xaf],
        });
        body.push(0);
        let server_hello = make_handshake(HS_SERVER_HELLO, &body);
        let done = make_handshake(HS_SERVER_HELLO_DONE, &[]);
        let mut transcript = hello;
        transcript.extend(&server_hello);
        transcript.extend(&done);
        let mut flight = server_hello;
        flight.extend(done);
        for chunk in flight.chunks(2) {
            stream
                .write_all(&make_record(CT_HANDSHAKE, chunk))
                .await
                .unwrap();
        }
        let (_, exchange) = read_record(&mut stream).await.unwrap();
        transcript.extend(exchange);
        assert_eq!(
            read_record(&mut stream).await.unwrap(),
            (CT_CHANGE_CIPHER_SPEC, vec![1])
        );
        let (_, encrypted) = read_record(&mut stream).await.unwrap();
        let master = derive_master_secret(b"test psk", &client_random, &random, suite);
        let keys = derive_key_block(&master, &client_random, &random, suite);
        let client_finished = decrypt_record(&keys, false, 0, CT_HANDSHAKE, &encrypted).unwrap();
        assert_eq!(
            client_finished,
            make_handshake(
                HS_FINISHED,
                &finished_verify_data(&master, b"client finished", &transcript, suite)
            )
        );
        transcript.extend(client_finished);
        let mut verify = finished_verify_data(&master, b"server finished", &transcript, suite);
        if bad_finished {
            verify[0] ^= 1;
        }
        stream
            .write_all(&make_record(CT_CHANGE_CIPHER_SPEC, &[1]))
            .await
            .unwrap();
        let finished = make_handshake(HS_FINISHED, &verify);
        for (seq, chunk) in finished.chunks(3).enumerate() {
            let record = encrypt_record(&server_keys(&keys), seq as u64, CT_HANDSHAKE, chunk);
            stream
                .write_all(&make_record(CT_HANDSHAKE, &record))
                .await
                .unwrap();
        }
    }

    #[test]
    fn handshake_reassembles_fragments_and_requires_server_finished_proof() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for suite in [CipherSuite::Aes128CbcSha, CipherSuite::Aes256CbcSha384] {
                for bad_finished in [false, true] {
                    let (client, peer) = tokio::io::duplex(65536);
                    let peer = tokio::spawn(server(peer, suite, bad_finished));
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        tls_psk_handshake(client, b"test psk"),
                    )
                    .await
                    .unwrap();
                    peer.await.unwrap();
                    assert_eq!(result.is_err(), bad_finished);
                }
            }
            let mut malformed = make_handshake(HS_SERVER_HELLO, &[0; 34]);
            malformed = make_record(CT_HANDSHAKE, &malformed);
            let wire = Wire {
                input: Cursor::new(malformed),
                ..Wire::default()
            };
            assert!(tls_psk_handshake(wire, b"test psk").await.is_err());
        });
    }
}
