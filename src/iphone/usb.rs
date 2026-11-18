//! Existing-trust, USB-assisted legacy observation. This is not phone-side control.
use super::{
    CancellationToken, IphoneScreen, ProtocolError, Wire, bounded, check_protocol_boundary,
    screen_from_png, service_error,
};
use idevice::IdeviceService;
use idevice::lockdown::LockdownClient;
use idevice::provider::IdeviceProvider;
use idevice::usbmuxd::{Connection, UsbmuxdAddr};
use plist::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Includes room for an XML plist's base64 overhead above the 32 MiB PNG limit.
const MAX_LINK_FRAME: usize = 48 * 1024 * 1024;

/// Observe one explicitly selected USB phone using its existing lockdown trust.
/// Runs on a trusted macOS/Linux host, not on the phone or a Tokio worker.
/// Never pairs, mounts an image, installs an app, dispatches input, or falls back
/// to a network device. Cancellation closes the connection without retrying.
/// The returned screen does not become any CoreDevice executor's input fence.
pub fn observe_iphone_over_usb(
    udid: &str,
    cancellation: &CancellationToken,
    deadline: i64,
) -> Result<IphoneScreen, ProtocolError> {
    check_protocol_boundary(cancellation, deadline)?;
    if udid.is_empty() || udid.len() > 128 {
        return Err(ProtocolError::InvalidRequest(
            "invalid USB device selection".into(),
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| service_error())?;
    // Upstream tracing includes pairing plists. Suppress only this blocking
    // operation's thread, including cleanup, without changing the host subscriber.
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        runtime.block_on(bounded(cancellation, deadline, async {
            let address = UsbmuxdAddr::UnixSocket("/var/run/usbmuxd".into());
            let mut mux = address.connect(0).await.map_err(|_| service_error())?;
            let devices = mux.get_devices().await.map_err(|_| service_error())?;
            let mut matches = devices
                .into_iter()
                .filter(|device| device.udid == udid && device.connection_type == Connection::Usb);
            let device = matches.next().ok_or_else(service_error)?;
            if matches.next().is_some() {
                return Err(service_error());
            }
            drop(mux);
            let provider = device.to_provider(address, "praefectus-usb-observe");
            let credentials = provider
                .get_pairing_file()
                .await
                .map_err(|_| service_error())?;
            let mut lockdown = LockdownClient::connect(&provider)
                .await
                .map_err(|_| service_error())?;
            let legacy = lockdown
                .start_session(&credentials)
                .await
                .map_err(|_| service_error())?;
            let identity = lockdown
                .get_value(Some("UniqueDeviceID"), None)
                .await
                .map_err(|_| service_error())?;
            if identity.as_string() != Some(udid) {
                return Err(service_error());
            }
            let (port, ssl) = lockdown
                .start_service("com.apple.mobile.screenshotr")
                .await
                .map_err(|_| service_error())?;
            if port == 0 {
                return Err(service_error());
            }
            let mut service = provider.connect(port).await.map_err(|_| service_error())?;
            if ssl {
                service
                    .start_session(&credentials, legacy)
                    .await
                    .map_err(|_| service_error())?;
            }
            let mut stream = service.get_socket().ok_or_else(service_error)?;
            let png = capture_link(&mut stream).await?;
            drop(stream);
            lockdown.stop_session().await.map_err(|_| service_error())?;
            drop(lockdown);
            check_protocol_boundary(cancellation, deadline)?;
            let screen = screen_from_png(png, &format!("usb-screenshotr:{udid}"))?;
            check_protocol_boundary(cancellation, deadline)?;
            Ok(screen)
        }))
    })
}

async fn read_link(stream: &mut Wire, tag: &str) -> Result<Vec<Value>, ProtocolError> {
    let length = stream.read_u32().await.map_err(|_| service_error())? as usize;
    if length == 0 || length > MAX_LINK_FRAME {
        return Err(service_error());
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| service_error())?;
    let value = Value::from_reader(std::io::Cursor::new(bytes)).map_err(|_| service_error())?;
    let values = value.into_array().ok_or_else(service_error)?;
    if values.first().and_then(Value::as_string) != Some(tag) {
        return Err(service_error());
    }
    Ok(values)
}

async fn write_link(stream: &mut Wire, values: Vec<Value>) -> Result<(), ProtocolError> {
    let mut bytes = Vec::new();
    Value::Array(values)
        .to_writer_binary(&mut bytes)
        .map_err(|_| service_error())?;
    let length = u32::try_from(bytes.len()).map_err(|_| service_error())?;
    stream
        .write_u32(length)
        .await
        .map_err(|_| service_error())?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| service_error())?;
    stream.flush().await.map_err(|_| service_error())
}

async fn capture_link(stream: &mut Wire) -> Result<Vec<u8>, ProtocolError> {
    read_link(stream, "DLMessageVersionExchange").await?;
    write_link(
        stream,
        vec![
            "DLMessageVersionExchange".into(),
            "DLVersionsOk".into(),
            400u64.into(),
        ],
    )
    .await?;
    read_link(stream, "DLMessageDeviceReady").await?;
    let mut request = plist::Dictionary::new();
    request.insert("MessageType".into(), "ScreenShotRequest".into());
    write_link(
        stream,
        vec!["DLMessageProcessMessage".into(), Value::Dictionary(request)],
    )
    .await?;
    let mut reply = read_link(stream, "DLMessageProcessMessage").await?;
    if reply.len() != 2 {
        return Err(service_error());
    }
    let mut reply = reply
        .pop()
        .and_then(Value::into_dictionary)
        .ok_or_else(service_error)?;
    if reply.get("MessageType").and_then(Value::as_string) != Some("ScreenShotReply") {
        return Err(service_error());
    }
    match reply.remove("ScreenShotData") {
        Some(Value::Data(png)) => Ok(png),
        _ => Err(service_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::now_ms;

    #[test]
    fn legacy_capture_validates_wire_reply_pixels_and_frame_bounds() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut png = Vec::new();
            {
                let mut encoder = png::Encoder::new(&mut png, 2, 3);
                encoder.set_color(png::ColorType::Rgb);
                encoder
                    .write_header()
                    .unwrap()
                    .write_image_data(&[
                        1, 9, 3, 4, 5, 6, 7, 8, 2, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                    ])
                    .unwrap();
            }
            for valid_reply in [true, false] {
                let (client, mut peer) = tokio::io::duplex(7);
                let expected = png.clone();
                let server = tokio::spawn(async move {
                    async fn send(peer: &mut tokio::io::DuplexStream, value: Value) {
                        let mut bytes = Vec::new();
                        value.to_writer_binary(&mut bytes).unwrap();
                        peer.write_u32(bytes.len() as u32).await.unwrap();
                        peer.write_all(&bytes).await.unwrap();
                    }
                    async fn receive(peer: &mut tokio::io::DuplexStream) -> Value {
                        let length = peer.read_u32().await.unwrap();
                        let mut bytes = vec![0; length as usize];
                        peer.read_exact(&mut bytes).await.unwrap();
                        Value::from_reader(std::io::Cursor::new(bytes)).unwrap()
                    }
                    send(
                        &mut peer,
                        Value::Array(vec![
                            "DLMessageVersionExchange".into(),
                            400u64.into(),
                            0u64.into(),
                        ]),
                    )
                    .await;
                    assert_eq!(
                        receive(&mut peer).await,
                        Value::Array(vec![
                            "DLMessageVersionExchange".into(),
                            "DLVersionsOk".into(),
                            400u64.into()
                        ])
                    );
                    send(&mut peer, Value::Array(vec!["DLMessageDeviceReady".into()])).await;
                    let request = receive(&mut peer).await;
                    assert_eq!(
                        request.as_array().unwrap()[0].as_string(),
                        Some("DLMessageProcessMessage")
                    );
                    let request = request.as_array().unwrap()[1].as_dictionary().unwrap();
                    assert_eq!(request.len(), 1);
                    assert_eq!(
                        request.get("MessageType").and_then(Value::as_string),
                        Some("ScreenShotRequest")
                    );
                    let mut reply = plist::Dictionary::new();
                    reply.insert(
                        "MessageType".into(),
                        if valid_reply {
                            "ScreenShotReply"
                        } else {
                            "UnrelatedReply"
                        }
                        .into(),
                    );
                    reply.insert("ScreenShotData".into(), Value::Data(expected));
                    send(
                        &mut peer,
                        Value::Array(vec![
                            "DLMessageProcessMessage".into(),
                            Value::Dictionary(reply),
                        ]),
                    )
                    .await;
                    let mut after = [0];
                    assert_eq!(
                        peer.read(&mut after).await.unwrap(),
                        0,
                        "no second capture or other request"
                    );
                });
                let mut client: Wire = Box::new(client);
                let result = capture_link(&mut client).await;
                drop(client);
                server.await.unwrap();
                if valid_reply {
                    let screen =
                        screen_from_png(result.unwrap(), "usb-screenshotr:test-phone").unwrap();
                    assert_eq!(
                        (
                            screen.coordinates.displays[0].width,
                            screen.coordinates.displays[0].height
                        ),
                        (2, 3)
                    );
                    assert_eq!(screen.png(), png);
                    assert!(screen.target(1, 2).is_ok());
                    assert!(screen.target(2, 2).is_err());
                } else {
                    assert!(
                        result.is_err(),
                        "valid image in the wrong reply must not become an observation"
                    );
                }
            }
            for length in [0, MAX_LINK_FRAME as u32 + 1] {
                let (mut peer, client) = tokio::io::duplex(8);
                peer.write_u32(length).await.unwrap();
                let mut client: Wire = Box::new(client);
                let result = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    read_link(&mut client, "DLMessageProcessMessage"),
                )
                .await
                .unwrap();
                assert!(
                    result.is_err(),
                    "reject the prefix without allocating or awaiting a body"
                );
            }
        });
    }

    #[test]
    fn usb_observation_refuses_cancelled_expired_and_invalid_selection_before_io() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert!(matches!(
            observe_iphone_over_usb("not-a-device", &cancellation, now_ms() - 1),
            Err(ProtocolError::ObservationCancelled)
        ));
        let cancellation = CancellationToken::default();
        assert!(matches!(
            observe_iphone_over_usb("not-a-device", &cancellation, now_ms() - 1),
            Err(ProtocolError::ObservationExpired)
        ));
        assert!(matches!(
            observe_iphone_over_usb("", &cancellation, now_ms() + 1000),
            Err(ProtocolError::InvalidRequest(_))
        ));
    }
}
