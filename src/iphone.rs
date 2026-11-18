//! Experimental Apple CoreDevice executor. Pairing and authority belong to the host.
//!
//! This client runs inside an iOS host as well as on a computer. On iOS a VPN
//! must route 10.7.0.1 back to the phone. No desktop relay is involved in that mode.
use std::future::Future;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::iphone_transport::{
    RemotePairingClient, RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native,
};
use idevice::ReadWrite;
use idevice::core_device::{
    AppServiceClient, ButtonState, CallInfoBlob, DisplayServiceClient, ImageFormat,
    IndigoHidClient, KeyboardUsage, MainKeyboardService, PasteboardServiceClient,
    ScreenCaptureServiceClient, UniversalHidServiceClient, build_screen_audio_offer,
    build_screen_video_offer, build_start_audio_parameters, build_start_video_parameters,
};
use idevice::rsd::RsdHandshake;
use idevice::tcp::{adapter::Adapter, handle::AdapterHandle};
use serde::Serialize;
use serde_json::json;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::{
    Action, ActionCapability, ApplicationOperation, BackgroundSupport, CancellationToken,
    Capabilities, CoordinateObservation, DeliveryRoute, Direction, DispatchError, DispatchReceipt,
    DisplayGeometry, EffectKnowledge, Evidence, Executor, FailureCode, MouseButton, NativePoint,
    Observation, PROTOCOL_VERSION, ProtocolError, ResolvedTarget, SessionIsolation, TargetRef,
    VerificationPolicy, check_protocol_boundary, global_input_allowed, hash_bytes,
    hash_serializable, now_ms,
};

const BACKEND: &str = "praefectus-iphone-coredevice";
const DISPLAY: &str = "iphone-primary";
const IO_TIMEOUT: Duration = Duration::from_secs(15);
type Wire = Box<dyn ReadWrite>;

/// Host-only connection configuration, never part of an action proposal.
pub struct IphoneConfig {
    endpoint: SocketAddr,
    pairing: RpPairingFile,
}

impl IphoneConfig {
    /// The port is the phone's current RemotePairing port, obtained during setup.
    pub fn on_phone(port: u16, pairing_plist: &[u8]) -> Result<Self, ProtocolError> {
        Self::computer_assisted(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1)), port),
            pairing_plist,
        )
    }

    /// An explicitly host-selected device address. This mode needs a computer
    /// only when the caller itself runs on one; it does not imply standalone use.
    pub fn computer_assisted(
        endpoint: SocketAddr,
        pairing_plist: &[u8],
    ) -> Result<Self, ProtocolError> {
        if endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || endpoint.ip().is_multicast()
            || pairing_plist.len() > 64 * 1024
        {
            return Err(ProtocolError::InvalidRequest(
                "invalid iPhone configuration".into(),
            ));
        }
        let pairing = RpPairingFile::from_bytes(pairing_plist).map_err(|_| service_error())?;
        Ok(Self { endpoint, pairing })
    }
}

/// Bounded device discovery through the authenticated Remote Service Discovery handshake.
#[derive(Clone, Debug, Serialize)]
pub struct IphoneSession {
    pub device_id: String,
    pub services: Vec<String>,
    pub native_capture: bool,
    pub native_input: bool,
}

/// Screenshot bytes are deliberately not serializable or printable. The host
/// may consume them out of band; they never enter Engine receipts or ledgers.
pub struct IphoneScreen {
    coordinates: CoordinateObservation,
    png: Vec<u8>,
}

impl IphoneScreen {
    pub fn coordinates(&self) -> &CoordinateObservation {
        &self.coordinates
    }

    pub fn png(&self) -> &[u8] {
        &self.png
    }

    /// Coordinates are screenshot pixels, not UIKit points or normalized HID units.
    pub fn target(&self, x: i64, y: i64) -> Result<TargetRef, ProtocolError> {
        let display = &self.coordinates.displays[0];
        if x < 0 || y < 0 || x >= display.width || y >= display.height {
            return Err(ProtocolError::InvalidRequest(
                "point outside iPhone display".into(),
            ));
        }
        Ok(TargetRef::Coordinates {
            x,
            y,
            display_id: DISPLAY.into(),
            display_geometry_hash: self.coordinates.display_geometry_hash.clone(),
            snapshot_id: self.coordinates.snapshot_id.clone(),
            snapshot_content_hash: self.coordinates.snapshot_content_hash.clone(),
        })
    }
}

struct Device {
    adapter: AdapterHandle,
    rsd: RsdHandshake,
    capture: ScreenCaptureServiceClient<Wire>,
    last: Option<CoordinateObservation>,
    media: Option<Media>,
    broken: bool,
    _pairing: RemotePairingClient<RpPairingSocket<tokio::net::TcpStream>>,
}

struct Inner {
    runtime: Runtime,
    device: Mutex<Device>,
    session: IphoneSession,
}

/// Clone shares one serialized device session and observation fence.
#[derive(Clone)]
pub struct IphoneExecutor(Arc<Inner>);

fn service_error() -> ProtocolError {
    ProtocolError::Executor("iPhone service unavailable".into())
}

fn stale() -> ProtocolError {
    ProtocolError::StaleTarget("iPhone observation changed or expired".into())
}

impl IphoneExecutor {
    /// Call synchronous methods from a blocking host queue, not a Tokio worker.
    /// Setup only verifies existing pairing: it never silently pairs a new host.
    pub fn connect(config: IphoneConfig) -> Result<Self, ProtocolError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| service_error())?;
        let device = runtime.block_on(async {
            tokio::time::timeout(IO_TIMEOUT, async {
                let stream = tokio::net::TcpStream::connect(config.endpoint)
                    .await
                    .map_err(|_| service_error())?;
                let mut pairing =
                    RemotePairingClient::new(RpPairingSocket::new(stream), "praefectus");
                let mut record = config.pairing;
                pairing
                    .attempt_pair_verify()
                    .await
                    .map_err(|_| service_error())?;
                pairing
                    .validate_pairing(&mut record)
                    .await
                    .map_err(|_| service_error())?;
                let port = pairing
                    .create_tcp_listener()
                    .await
                    .map_err(|_| service_error())?;
                let stream =
                    tokio::net::TcpStream::connect(SocketAddr::new(config.endpoint.ip(), port))
                        .await
                        .map_err(|_| service_error())?;
                let tunnel = connect_tls_psk_tunnel_native(stream, pairing.encryption_key())
                    .await
                    .map_err(|_| service_error())?;
                let info = tunnel.info.clone();
                let mut adapter = Adapter::new(
                    Box::new(tunnel.into_inner()),
                    info.client_address.parse().map_err(|_| service_error())?,
                    info.server_address.parse().map_err(|_| service_error())?,
                )
                .to_async_handle();
                let stream = adapter
                    .connect(info.server_rsd_port)
                    .await
                    .map_err(|_| service_error())?;
                let mut rsd = RsdHandshake::new(stream)
                    .await
                    .map_err(|_| service_error())?;
                if rsd.services.len() > 512 {
                    return Err(service_error());
                }
                let capture = rsd
                    .connect(&mut adapter)
                    .await
                    .map_err(|_| service_error())?;
                Ok(Device {
                    adapter,
                    rsd,
                    capture,
                    last: None,
                    media: None,
                    broken: false,
                    _pairing: pairing,
                })
            })
            .await
            .map_err(|_| service_error())?
        })?;
        let mut services: Vec<_> = device.rsd.services.keys().cloned().collect();
        services.sort();
        let native_input = [
            "com.apple.coredevice.displayservice",
            "com.apple.coredevice.hid.universalhidservice",
            "com.apple.coredevice.hid.indigo",
        ]
        .iter()
        .all(|name| device.rsd.services.contains_key(*name));
        let session = IphoneSession {
            device_id: device.rsd.uuid.clone(),
            services,
            native_capture: true,
            native_input,
        };
        Ok(Self(Arc::new(Inner {
            runtime,
            device: Mutex::new(device),
            session,
        })))
    }

    pub fn session(&self) -> &IphoneSession {
        &self.0.session
    }

    fn run<T>(
        &self,
        cancellation: &CancellationToken,
        deadline: i64,
        operation: impl AsyncFnOnce(&mut Device) -> Result<T, ProtocolError>,
    ) -> Result<T, ProtocolError> {
        check_protocol_boundary(cancellation, deadline)?;
        let mut device = loop {
            match self.0.device.try_lock() {
                Ok(device) => break device,
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(service_error()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    check_protocol_boundary(cancellation, deadline)?;
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        };
        if device.broken {
            return Err(service_error());
        }
        let result =
            self.0
                .runtime
                .block_on(bounded(cancellation, deadline, operation(&mut device)));
        if matches!(
            result,
            Err(ProtocolError::Executor(_)
                | ProtocolError::ObservationCancelled
                | ProtocolError::ObservationExpired)
        ) {
            device.broken = true;
            device.media = None;
            let _ = self.0.runtime.block_on(device.adapter.close());
        }
        result
    }

    pub fn observe_screen(
        &self,
        cancellation: &CancellationToken,
        deadline: i64,
    ) -> Result<IphoneScreen, ProtocolError> {
        self.run(cancellation, deadline, async |device| {
            let (png, coordinates) = capture(device).await?;
            device.last = Some(coordinates.clone());
            Ok(IphoneScreen { png, coordinates })
        })
    }

    /// Read-only installed application discovery. No launch or activation occurs.
    pub fn applications(
        &self,
        cancellation: &CancellationToken,
        deadline: i64,
    ) -> Result<Vec<String>, ProtocolError> {
        self.run(cancellation, deadline, async |device| {
            let mut client: AppServiceClient<Wire> = device
                .rsd
                .connect(&mut device.adapter)
                .await
                .map_err(|_| service_error())?;
            let apps = client
                .list_apps(true, true, true, false, true)
                .await
                .map_err(|_| service_error())?;
            if apps.len() > 4096 {
                return Err(service_error());
            }
            Ok(apps.into_iter().map(|app| app.bundle_identifier).collect())
        })
    }
}

async fn bounded<T>(
    cancellation: &CancellationToken,
    deadline: i64,
    future: impl Future<Output = Result<T, ProtocolError>>,
) -> Result<T, ProtocolError> {
    let duration =
        Duration::from_millis(deadline.saturating_sub(now_ms()).max(0) as u64).min(IO_TIMEOUT);
    let stop = async {
        loop {
            check_protocol_boundary(cancellation, deadline)?;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), ProtocolError>(())
    };
    tokio::pin!(stop);
    tokio::select! {
        result = tokio::time::timeout(duration, future) => match result {
            Ok(result) => result,
            Err(_) => {
                check_protocol_boundary(cancellation, deadline)?;
                Err(service_error())
            }
        },
        result = &mut stop => { result?; Err(service_error()) }
    }
}

async fn capture(device: &mut Device) -> Result<(Vec<u8>, CoordinateObservation), ProtocolError> {
    let png = device
        .capture
        .take_screenshot(None, ImageFormat::Png)
        .await
        .map_err(|_| service_error())?;
    let (width, height, content) = image_fence(&png)?;
    let displays = vec![DisplayGeometry {
        display_id: DISPLAY.into(),
        x: 0,
        y: 0,
        width,
        height,
    }];
    let geometry = hash_serializable(&(device.rsd.uuid.as_str(), &displays))?;
    Ok((
        png,
        CoordinateObservation {
            protocol_version: PROTOCOL_VERSION,
            snapshot_id: format!("iphone-{}", Uuid::new_v4()),
            display_geometry_hash: geometry,
            snapshot_content_hash: content,
            observed_at_ms: now_ms(),
            displays,
        },
    ))
}

fn image_fence(bytes: &[u8]) -> Result<(i64, i64, String), ProtocolError> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(service_error());
    }
    let mut decoder = png::Decoder::new_with_limits(
        Cursor::new(bytes),
        png::Limits {
            bytes: 64 * 1024 * 1024,
        },
    );
    decoder.set_transformations(png::Transformations::EXPAND);
    let mut reader = decoder.read_info().map_err(|_| service_error())?;
    let size = reader
        .output_buffer_size()
        .filter(|size| *size <= 64 * 1024 * 1024)
        .ok_or_else(service_error)?;
    let mut pixels = vec![0; size];
    let info = reader
        .next_frame(&mut pixels)
        .map_err(|_| service_error())?;
    if info.width == 0 || info.height == 0 || info.width > 16384 || info.height > 16384 {
        return Err(service_error());
    }
    let hash = hash_serializable(&(
        info.width,
        info.height,
        format!("{:?}{:?}", info.color_type, info.bit_depth),
        hash_bytes(&pixels[..info.buffer_size()]),
    ))?;
    Ok((info.width.into(), info.height.into(), hash))
}

fn validate_fence(
    record: &CoordinateObservation,
    live: &CoordinateObservation,
    target: &TargetRef,
) -> Result<NativePoint, ProtocolError> {
    let TargetRef::Coordinates {
        x,
        y,
        display_id,
        display_geometry_hash,
        snapshot_id,
        snapshot_content_hash,
    } = target
    else {
        return Err(stale());
    };
    let display = record.displays.first().ok_or_else(stale)?;
    if record.observed_at_ms > now_ms()
        || now_ms().saturating_sub(record.observed_at_ms) > 30_000
        || snapshot_id != &record.snapshot_id
        || display_id != DISPLAY
        || display_geometry_hash != &record.display_geometry_hash
        || snapshot_content_hash != &record.snapshot_content_hash
        || live.display_geometry_hash != record.display_geometry_hash
        || live.snapshot_content_hash != record.snapshot_content_hash
        || *x < 0
        || *y < 0
        || *x >= display.width
        || *y >= display.height
    {
        return Err(stale());
    }
    Ok(NativePoint { x: *x, y: *y })
}

impl Executor for IphoneExecutor {
    fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
        let mut actions = Vec::new();
        if self.session().native_input && global_input_allowed() {
            actions.extend(
                ["click", "drag", "scroll", "press"]
                    .into_iter()
                    .map(str::to_string),
            );
            if self
                .session()
                .services
                .iter()
                .any(|s| s == "com.apple.coredevice.pasteboardservice")
            {
                actions.extend(["paste", "type_text"].into_iter().map(str::to_string));
            }
        }
        if self
            .session()
            .services
            .iter()
            .any(|s| s == "com.apple.coredevice.appservice")
            && global_input_allowed()
        {
            actions.push("application".into());
        }
        let geometry = self
            .0
            .device
            .lock()
            .map_err(|_| service_error())?
            .last
            .as_ref()
            .map(|last| last.display_geometry_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        Ok(Capabilities {
            platform: "ios".into(),
            backend: BACKEND.into(),
            session_isolation: SessionIsolation::SharedDesktop,
            action_capabilities: actions
                .iter()
                .map(|action| ActionCapability {
                    action: action.clone(),
                    delivery_route: DeliveryRoute::Pointer,
                    background_support: BackgroundSupport::Unavailable,
                })
                .collect(),
            supported_actions: actions,
            display_geometry_hash: geometry,
            permissions: [
                ("paired_device".into(), true),
                ("native_capture".into(), true),
                ("global_input".into(), global_input_allowed()),
            ]
            .into(),
        })
    }

    fn observe(&self, target: &TargetRef) -> Result<Observation, ProtocolError> {
        self.observe_with_boundary(target, &CancellationToken::default(), now_ms() + 15_000)
    }

    fn observe_with_boundary(
        &self,
        _target: &TargetRef,
        cancellation: &CancellationToken,
        deadline: i64,
    ) -> Result<Observation, ProtocolError> {
        self.run(cancellation, deadline, async |device| {
            let (_, live) = capture(device).await?;
            Ok(Observation {
                evidence: Evidence {
                    observation_hash: live.snapshot_content_hash,
                    target_fingerprint_hash: None,
                    display_geometry_hash: live.display_geometry_hash,
                    observed_at_ms: live.observed_at_ms,
                },
                element: None,
                state: json!({}),
            })
        })
    }

    fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, ProtocolError> {
        self.resolve_with_boundary(target, &CancellationToken::default(), now_ms() + 15_000)
    }

    fn resolve_with_boundary(
        &self,
        target: &TargetRef,
        cancellation: &CancellationToken,
        deadline: i64,
    ) -> Result<ResolvedTarget, ProtocolError> {
        if matches!(target, TargetRef::None) {
            check_protocol_boundary(cancellation, deadline)?;
            return Ok(ResolvedTarget::None);
        }
        self.run(cancellation, deadline, async |device| {
            let (_, live) = capture(device).await?;
            let record = device.last.as_ref().ok_or_else(stale)?;
            validate_fence(record, &live, target)?;
            Ok(ResolvedTarget::IphoneCoordinates(target.clone()))
        })
    }

    fn dispatch(
        &self,
        action: &Action,
        target: &ResolvedTarget,
        verification: &VerificationPolicy,
        cancellation: &CancellationToken,
        deadline: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        let fail = |code, effect| DispatchError {
            message: "iPhone action did not complete".into(),
            code,
            effect,
        };
        if !global_input_allowed() {
            return Err(fail(
                FailureCode::PermissionDenied,
                EffectKnowledge::NoEffect,
            ));
        }
        if !matches!(
            verification,
            VerificationPolicy::None | VerificationPolicy::SnapshotChanged
        ) {
            return Err(fail(FailureCode::Unsupported, EffectKnowledge::NoEffect));
        }
        let mut started = false;
        let result = self.run(cancellation, deadline, async |device| {
            validate_action(action)?;
            if let (Action::Application { name, .. }, ResolvedTarget::None) = (action, target) {
                let mut app: AppServiceClient<Wire> = device
                    .rsd
                    .connect(&mut device.adapter)
                    .await
                    .map_err(|_| service_error())?;
                check_protocol_boundary(cancellation, deadline)?;
                started = true;
                app.launch_application(name, &[], false, false, None, None, None)
                    .await
                    .map_err(|_| service_error())?;
                return Ok(());
            }
            let ResolvedTarget::IphoneCoordinates(target) = target else {
                return Err(ProtocolError::InvalidRequest(
                    "iPhone action requires a fenced coordinate".into(),
                ));
            };
            let (_, live) = capture(device).await?;
            let record = device.last.clone().ok_or_else(stale)?;
            validate_fence(&record, &live, target)?;
            if let Action::Drag { to, .. } = action {
                validate_fence(&record, &live, to)?;
            }
            // Stream negotiation itself is an externally visible device effect.
            check_protocol_boundary(cancellation, deadline)?;
            started = true;
            if device.media.is_none() {
                device.media = Some(Media::start(device).await?);
            }
            check_protocol_boundary(cancellation, deadline)?;
            perform(device, action, target, cancellation, deadline).await
        });
        match result {
            Ok(()) => Ok(DispatchReceipt {
                backend: BACKEND.into(),
                fallback_chain: vec![],
            }),
            Err(error) => {
                let effect = if started {
                    EffectKnowledge::Unknown
                } else {
                    match error {
                        ProtocolError::ObservationCancelled => {
                            EffectKnowledge::CancelledBeforeEffect
                        }
                        ProtocolError::ObservationExpired => EffectKnowledge::ExpiredBeforeEffect,
                        _ => EffectKnowledge::NoEffect,
                    }
                };
                let code = match error {
                    ProtocolError::StaleTarget(_) => FailureCode::StaleTarget,
                    ProtocolError::InvalidRequest(_) => FailureCode::Unsupported,
                    _ => FailureCode::DispatchFailed,
                };
                Err(fail(code, effect))
            }
        }
    }
}

fn validate_action(action: &Action) -> Result<(), ProtocolError> {
    let valid = match action {
        Action::Click {
            button: MouseButton::Left,
            count: 1,
            ..
        } => true,
        Action::Drag {
            button: MouseButton::Left,
            ..
        } => true,
        Action::Scroll { amount: 1, .. } => true,
        Action::Press {
            key,
            count: 1,
            delay_ms: None,
        } => ["home", "return", "backspace", "escape"].contains(&key.as_str()),
        Action::Paste { text } => text.len() <= 64 * 1024,
        Action::TypeText {
            text,
            clear: false,
            delay_ms: None,
            ..
        } => text.len() <= 64 * 1024,
        Action::Application {
            operation: ApplicationOperation::Launch,
            name,
        } => {
            !name.is_empty()
                && name.len() <= 255
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ProtocolError::InvalidRequest(
            "unsupported iPhone action variant".into(),
        ))
    }
}

struct Media {
    tasks: Vec<JoinHandle<()>>,
    _client: DisplayServiceClient<Wire>,
}

impl Media {
    async fn start(device: &mut Device) -> Result<Self, ProtocolError> {
        let mut client: DisplayServiceClient<Wire> = device
            .rsd
            .connect(&mut device.adapter)
            .await
            .map_err(|_| service_error())?;
        let audio = device
            .adapter
            .bind_udp(0)
            .await
            .map_err(|_| service_error())?;
        let video = device
            .adapter
            .bind_udp(0)
            .await
            .map_err(|_| service_error())?;
        let receiver = device.adapter.host_ip().to_string();
        let sender = device.adapter.peer_ip().to_string();
        let session = Uuid::new_v4();
        let info = CallInfoBlob {
            client_version: 1,
            device_type: "iPhone".into(),
            framework_version: "2205.3.1".into(),
            os_version: "27.0".into(),
            ..Default::default()
        };
        let offer = build_screen_audio_offer(&Uuid::new_v4().to_string(), &info)
            .map_err(|_| service_error())?;
        // Audio refusal does not prevent a video session from authorizing HID.
        let _ = client
            .start_media_stream(build_start_audio_parameters(
                &receiver,
                audio.local_port(),
                &sender,
                50000,
                offer,
                140,
                session,
            ))
            .await;
        let offer = build_screen_video_offer(&Uuid::new_v4().to_string(), &info, 1)
            .map_err(|_| service_error())?;
        client
            .start_media_stream(build_start_video_parameters(
                &receiver,
                video.local_port(),
                &sender,
                50001,
                offer,
                140,
                1,
                session,
            ))
            .await
            .map_err(|_| service_error())?;
        let mut tasks = Vec::new();
        for socket in [audio, video] {
            tasks.push(tokio::spawn(
                async move { while socket.recv().await.is_ok() {} },
            ));
        }
        // Own the tasks before yielding so cancellation aborts them too.
        let media = Self {
            tasks,
            _client: client,
        };
        // Allow the device to publish the authenticated touchscreen surface.
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(media)
    }
    fn stop_draining(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Drop for Media {
    fn drop(&mut self) {
        self.stop_draining();
    }
}

async fn perform(
    device: &mut Device,
    action: &Action,
    target: &TargetRef,
    cancellation: &CancellationToken,
    deadline: i64,
) -> Result<(), ProtocolError> {
    let mut touch: UniversalHidServiceClient<Wire> = device
        .rsd
        .connect(&mut device.adapter)
        .await
        .map_err(|_| service_error())?;
    let mut keys: IndigoHidClient<Wire> = device
        .rsd
        .connect(&mut device.adapter)
        .await
        .map_err(|_| service_error())?;
    let (_, live) = capture(device).await?;
    let record = device.last.as_ref().ok_or_else(stale)?;
    let point = validate_fence(record, &live, target)?;
    let destination = if let Action::Drag { to, .. } = action {
        Some(validate_fence(record, &live, to)?)
    } else {
        None
    };
    let display = &device.last.as_ref().ok_or_else(stale)?.displays[0];
    let (x, y) = hid_point(&point, display);
    check_protocol_boundary(cancellation, deadline)?;
    match action {
        Action::Click { .. } => touch.tap(x, y).await.map_err(|_| service_error()),
        Action::Drag { .. } | Action::Scroll { .. } => {
            let (end_x, end_y) = match (action, destination.as_ref()) {
                (Action::Drag { .. }, Some(to)) => hid_point(to, display),
                (Action::Scroll { direction, .. }, _) => match direction {
                    Direction::Down => (x, y.saturating_sub(8192)),
                    Direction::Up => (x, y.saturating_add(8192).min(32767)),
                    Direction::Right => (x.saturating_sub(8192), y),
                    Direction::Left => (x.saturating_add(8192).min(32767), y),
                },
                _ => return Err(stale()),
            };
            touch
                .drag(x, y, end_x, end_y, 20, 10)
                .await
                .map_err(|_| service_error())
        }
        Action::Press { key, .. } if key == "home" => {
            keys.send_button(0x0c, 0x40, ButtonState::Down)
                .await
                .map_err(|_| service_error())?;
            keys.send_button(0x0c, 0x40, ButtonState::Up)
                .await
                .map_err(|_| service_error())
        }
        Action::Press { key, .. } => {
            let code = match key.as_str() {
                "return" => 0x28,
                "backspace" => 0x2a,
                _ => 0x29,
            };
            keyboard(device, &[code]).await
        }
        Action::Paste { text } | Action::TypeText { text, .. } => {
            let mut paste: PasteboardServiceClient<Wire> = device
                .rsd
                .connect(&mut device.adapter)
                .await
                .map_err(|_| service_error())?;
            paste
                .set_text(text, "com.apple.UIKit.pboard.general")
                .await
                .map_err(|_| service_error())?;
            check_protocol_boundary(cancellation, deadline)?;
            keyboard(device, &[0xe3, 0x19]).await?;
            if matches!(
                action,
                Action::TypeText {
                    press_return: true,
                    ..
                }
            ) {
                check_protocol_boundary(cancellation, deadline)?;
                keyboard(device, &[0x28]).await?;
            }
            Ok(())
        }
        _ => Err(service_error()),
    }
}

fn hid_point(point: &NativePoint, display: &DisplayGeometry) -> (u16, u16) {
    (
        (point.x * 32767 / (display.width - 1).max(1)) as u16,
        (point.y * 32767 / (display.height - 1).max(1)) as u16,
    )
}

async fn keyboard(device: &mut Device, usages: &[u16]) -> Result<(), ProtocolError> {
    let mut client: UniversalHidServiceClient<Wire> = device
        .rsd
        .connect(&mut device.adapter)
        .await
        .map_err(|_| service_error())?;
    let mut service: MainKeyboardService = client
        .create_main_keyboard()
        .await
        .map_err(|_| service_error())?;
    let result = async {
        let usages = usages
            .iter()
            .map(|code| KeyboardUsage::new(*code))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| service_error())?;
        client
            .set_main_keyboard_usages(&mut service, usages)
            .await
            .map_err(|_| service_error())?;
        client
            .reset_main_keyboard(&mut service)
            .await
            .map_err(|_| service_error())
    }
    .await;
    let cleanup = client
        .remove_main_keyboard(&mut service)
        .await
        .map_err(|_| service_error());
    result.and(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_observation_preserves_deadline_and_cancellation_outcomes() {
        Runtime::new().unwrap().block_on(async {
            let cancellation = CancellationToken::default();
            let result: Result<(), _> =
                bounded(&cancellation, now_ms() + 2, std::future::pending()).await;
            assert!(matches!(result, Err(ProtocolError::ObservationExpired)));
            cancellation.cancel();
            let result: Result<(), _> =
                bounded(&cancellation, now_ms() - 1, std::future::pending()).await;
            assert!(matches!(result, Err(ProtocolError::ObservationCancelled)));
        });
    }

    fn screen() -> IphoneScreen {
        IphoneScreen {
            png: vec![],
            coordinates: CoordinateObservation {
                protocol_version: PROTOCOL_VERSION,
                snapshot_id: "iphone-test-observation".into(),
                display_geometry_hash: "a".repeat(64),
                snapshot_content_hash: "b".repeat(64),
                observed_at_ms: now_ms(),
                displays: vec![DisplayGeometry {
                    display_id: DISPLAY.into(),
                    x: 0,
                    y: 0,
                    width: 301,
                    height: 601,
                }],
            },
        }
    }

    #[test]
    fn screenshot_targets_reject_changed_pixels_geometry_age_and_foreign_snapshots() {
        let screen = screen();
        let target = screen.target(75, 450).unwrap();
        let record = screen.coordinates();
        let point = validate_fence(record, record, &target).unwrap();
        assert_eq!((point.x, point.y), (75, 450));
        assert_eq!(hid_point(&point, &record.displays[0]), (8191, 24575));
        assert!(screen.target(-1, 0).is_err());
        assert!(screen.target(301, 0).is_err());
        assert!(screen.target(0, 601).is_err());
        let edge = screen.target(300, 600).unwrap();
        let edge = validate_fence(record, record, &edge).unwrap();
        assert_eq!(hid_point(&edge, &record.displays[0]), (32767, 32767));
        let mut changed = record.clone();
        changed.snapshot_content_hash = "c".repeat(64);
        assert!(validate_fence(record, &changed, &target).is_err());
        changed = record.clone();
        changed.display_geometry_hash = "d".repeat(64);
        assert!(validate_fence(record, &changed, &target).is_err());
        changed = record.clone();
        changed.snapshot_id = "iphone-new-observation".into();
        assert!(validate_fence(&changed, record, &target).is_err());
        changed = record.clone();
        changed.observed_at_ms -= 30_001;
        assert!(validate_fence(&changed, record, &target).is_err());
        changed.observed_at_ms = now_ms() + 60_000;
        assert!(validate_fence(&changed, record, &target).is_err());
    }

    fn palette_png(palette: &[u8], note: &str) -> Vec<u8> {
        let mut bytes = vec![];
        {
            let mut encoder = png::Encoder::new(&mut bytes, 3, 1);
            encoder.set_color(png::ColorType::Indexed);
            encoder.set_depth(png::BitDepth::Eight);
            encoder.set_palette(palette);
            encoder
                .add_text_chunk("Comment".into(), note.into())
                .unwrap();
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&[0, 1, 0]).unwrap();
        }
        bytes
    }

    #[test]
    fn image_fences_hash_visible_palette_colors_but_not_png_metadata() {
        let first = palette_png(&[255, 0, 0, 0, 255, 0], "first capture");
        let same = palette_png(&[255, 0, 0, 0, 255, 0], "different metadata");
        let changed = palette_png(&[0, 0, 255, 0, 255, 0], "first capture");
        let (width, height, hash) = image_fence(&first).unwrap();
        assert_eq!((width, height), (3, 1));
        assert_eq!(hash, image_fence(&same).unwrap().2);
        assert_ne!(hash, image_fence(&changed).unwrap().2);
        assert!(image_fence(b"not a PNG").is_err());
    }

    #[test]
    fn native_service_actions_reject_unimplemented_variants_instead_of_falling_back() {
        for action in [
            Action::Click {
                button: MouseButton::Right,
                count: 1,
                allow_coordinate_fallback: true,
            },
            Action::Click {
                button: MouseButton::Left,
                count: 2,
                allow_coordinate_fallback: false,
            },
            Action::Scroll {
                direction: Direction::Down,
                amount: 2,
            },
            Action::TypeText {
                text: "replace".into(),
                clear: true,
                press_return: false,
                delay_ms: None,
            },
            Action::Application {
                operation: ApplicationOperation::Quit,
                name: "com.example.app".into(),
            },
        ] {
            assert!(validate_action(&action).is_err());
        }
    }

    #[test]
    fn connection_configuration_rejects_zero_ports_and_invalid_pairing_without_network_io() {
        assert!(IphoneConfig::on_phone(0, b"not credentials").is_err());
        assert!(IphoneConfig::on_phone(49152, b"not credentials").is_err());
    }
}
