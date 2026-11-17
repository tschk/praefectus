// Jackson Coxson
//! TLS-PSK tunnel connect helpers for remote pairing.
//!
//! These functions combine TLS-PSK handshake + CDTunnel handshake into a single call.
//! The CDTunnel protocol itself lives in [`crate::tunnel`].

use tracing::debug;

use idevice::{IdeviceError, ReadWrite};

// Re-export for backwards compatibility
pub use idevice::tunnel::TunnelInfo;

pub struct CdTunnel<S> {
    inner: S,
    pub info: TunnelInfo,
}
impl<S> CdTunnel<S> {
    pub fn into_inner(self) -> S {
        self.inner
    }
}

const CDTUNNEL_MAGIC: &[u8] = b"CDTunnel";
const DEFAULT_MTU: u16 = 16000;

/// Wraps a `tokio::net::TcpStream` with TLS-PSK using a pure-Rust implementation
/// and performs the CDTunnel handshake, returning a ready-to-use tunnel.
///
/// `encryption_key` is the key from `RemotePairingClient::encryption_key()`.
///
/// This uses a built-in TLS 1.2 PSK-AES256-CBC-SHA384 implementation with no
/// external TLS library dependency.
pub async fn connect_tls_psk_tunnel_native<S: ReadWrite>(
    stream: S,
    encryption_key: &[u8],
) -> Result<CdTunnel<super::tls_psk::TlsPskStream<S>>, IdeviceError> {
    let mut tls_stream = super::tls_psk::tls_psk_handshake(stream, encryption_key).await?;
    debug!("Native TLS-PSK handshake complete");

    // CDTunnel handshake over TLS using the record-level API
    let request = serde_json::json!({
        "type": "clientHandshakeRequest",
        "mtu": DEFAULT_MTU
    });
    let body = serde_json::to_vec(&request)?;

    let mut pkt = Vec::new();
    pkt.extend_from_slice(CDTUNNEL_MAGIC);
    pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&body);
    tls_stream.write_app_data(&pkt).await?;

    debug!("Sent CDTunnel handshake request via TLS");

    let response_data = tls_stream.read_app_data().await?;
    if response_data.len() < CDTUNNEL_MAGIC.len() + 2 {
        return Err(IdeviceError::UnexpectedResponse(
            "CDTunnel handshake response too short".into(),
        ));
    }
    if &response_data[..CDTUNNEL_MAGIC.len()] != CDTUNNEL_MAGIC {
        return Err(IdeviceError::UnexpectedResponse(
            "CDTunnel handshake response missing magic header".into(),
        ));
    }
    let body_len = u16::from_be_bytes([
        response_data[CDTUNNEL_MAGIC.len()],
        response_data[CDTUNNEL_MAGIC.len() + 1],
    ]) as usize;
    let body_start = CDTUNNEL_MAGIC.len() + 2;
    let response_body = &response_data[body_start..body_start + body_len];

    let response: serde_json::Value = serde_json::from_slice(response_body)
        .map_err(|e| IdeviceError::InternalError(e.to_string()))?;

    debug!("CDTunnel handshake response: {response:#?}");

    let client_params =
        response
            .get("clientParameters")
            .ok_or(IdeviceError::UnexpectedResponse(
                "missing clientParameters in CDTunnel response".into(),
            ))?;

    let client_address = client_params
        .get("address")
        .and_then(|a| a.as_str())
        .ok_or(IdeviceError::UnexpectedResponse(
            "missing client address in CDTunnel response".into(),
        ))?
        .to_string();

    let mtu = client_params
        .get("mtu")
        .and_then(|m| m.as_u64())
        .unwrap_or(1500) as u16;

    let server_address = response
        .get("serverAddress")
        .and_then(|a| a.as_str())
        .ok_or(IdeviceError::UnexpectedResponse(
            "missing server address in CDTunnel response".into(),
        ))?
        .to_string();

    let server_rsd_port = response
        .get("serverRSDPort")
        .and_then(|p| p.as_u64())
        .unwrap_or(0) as u16;

    let info = TunnelInfo {
        client_address,
        netmask: client_params
            .get("netmask")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string(),
        server_address,
        mtu,
        server_rsd_port,
    };

    debug!("CDTunnel established: {info:?}");

    Ok(CdTunnel {
        inner: tls_stream,
        info,
    })
}
