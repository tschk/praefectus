// Jackson Coxson
//! TLS-PSK tunnel connect helpers for remote pairing.
//!
//! These functions combine TLS-PSK handshake + CDTunnel handshake into a single call.
//! The CDTunnel protocol itself lives in [`crate::tunnel`].

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
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

    let request = serde_json::json!({
        "type": "clientHandshakeRequest",
        "mtu": DEFAULT_MTU
    });
    let body = serde_json::to_vec(&request)?;

    let mut pkt = Vec::new();
    pkt.extend_from_slice(CDTUNNEL_MAGIC);
    pkt.extend_from_slice(&(body.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&body);
    tls_stream.write_all(&pkt).await?;
    tls_stream.flush().await?;

    debug!("Sent CDTunnel handshake request via TLS");

    let info = read_tunnel_info(&mut tls_stream).await?;
    Ok(CdTunnel {
        inner: tls_stream,
        info,
    })
}

async fn read_tunnel_info<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<TunnelInfo, IdeviceError> {
    let mut header = [0; 10];
    stream.read_exact(&mut header).await?;
    if &header[..8] != CDTUNNEL_MAGIC {
        return Err(IdeviceError::UnexpectedResponse(
            "CDTunnel handshake response missing magic header".into(),
        ));
    }
    let body_len = u16::from_be_bytes([header[8], header[9]]) as usize;
    let mut response_body = vec![0; body_len];
    stream.read_exact(&mut response_body).await?;

    let response: serde_json::Value = serde_json::from_slice(&response_body)
        .map_err(|_| IdeviceError::UnexpectedResponse("Invalid CDTunnel response".into()))?;

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

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_response_preserves_surplus_and_refuses_truncation() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let body = br#"{"clientParameters":{"address":"fd00::2","mtu":1500},"serverAddress":"fd00::1","serverRSDPort":49152}"#;
            let mut frame = CDTUNNEL_MAGIC.to_vec();
            frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
            frame.extend_from_slice(body);
            let (mut peer, mut stream) = tokio::io::duplex(1);
            let outgoing = frame.clone();
            let writer = tokio::spawn(async move {
                peer.write_all(&outgoing).await.unwrap();
                peer.write_all(b"subsequent packet").await.unwrap();
            });
            let info = read_tunnel_info(&mut stream).await.unwrap();
            assert_eq!(info.client_address, "fd00::2");
            assert_eq!(info.server_rsd_port, 49152);
            let mut surplus = Vec::new();
            stream.read_to_end(&mut surplus).await.unwrap();
            assert_eq!(surplus, b"subsequent packet");
            writer.await.unwrap();
            for end in [0, 7, 9, 10, frame.len() - 1] {
                assert!(read_tunnel_info(&mut &frame[..end]).await.is_err());
            }
        });
    }
}
