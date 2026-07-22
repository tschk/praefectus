use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atspi::proxy::accessible::AccessibleProxyBlocking;
use atspi::proxy::action::ActionProxyBlocking;
use atspi::proxy::bus::BusProxyBlocking;
use atspi::proxy::component::ComponentProxyBlocking;
use atspi::proxy::editable_text::EditableTextProxyBlocking;
use atspi::proxy::text::TextProxyBlocking;
use atspi::zbus::Address;
use atspi::zbus::blocking::fdo::DBusProxy;
use atspi::zbus::blocking::{Connection, connection::Builder};
use atspi::zbus::proxy::CacheProperties;
use atspi::{CoordType, Interface, ObjectRefOwned, Role, State, StateSet};
use serde::{Deserialize, Serialize};
use x11rb::connection::Connection as X11Connection;
use x11rb::protocol::randr::{ConnectionExt as _, SetConfig};
use x11rb::protocol::xproto::{Atom, AtomEnum, ConnectionExt as _, MapState};
use x11rb::reexports::x11rb_protocol::parse_display::{ConnectAddress, parse_display};
use x11rb::reexports::x11rb_protocol::xauth::get_auth;
use x11rb::rust_connection::{DefaultStream, RustConnection};

use crate::semantic::{
    Actionability, SemanticBackend, SemanticElement, SemanticObservation, SemanticProvenance,
    SemanticTargetRef, opaque_element_id, semantic_fingerprint, semantic_tag,
};
use crate::{
    CancellationToken, DispatchError, DispatchReceipt, EffectKnowledge, Evidence, FailureCode,
    Observation, PROTOCOL_VERSION, ProtocolError, Rect, SurfaceDescriptor, SurfaceRef,
};

const BACKEND: &str = "praefectus-atspi2";
const MAX_APPLICATIONS: usize = 64;
const MAX_WINDOWS_PER_APPLICATION: usize = 128;
const MAX_SURFACES: usize = 512;
const MAX_ELEMENTS: usize = 512;
const MAX_DEPTH: usize = 64;
const MAX_ACTIONS: usize = 32;
const MAX_ACTION_NAME_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 1_024;
const MAX_VALUE_CHARACTERS: usize = 16 * 1_024;
const MAX_VALUE_BYTES: usize = 16 * 1_024;
const OBSERVATION_LIFETIME_MS: i64 = 30_000;
const PROVIDER_TIMEOUT_MS: u64 = 100;
const TOPOLOGY_TIMEOUT: Duration = Duration::from_millis(250);
const FOCUS_SENTINEL_TIMEOUT_MS: i64 = 1_000;
const MAX_FOCUS_ELEMENTS: usize = 2_048;
const MAX_DISPLAYS: usize = 64;
const MAX_OUTPUTS: usize = 256;

macro_rules! provider_call {
    ($cancellation:expr, $deadline_at_ms:expr, $call:expr) => {{
        check_observation_boundary($cancellation, $deadline_at_ms)?;
        match $call {
            Ok(value) => {
                check_observation_boundary($cancellation, $deadline_at_ms)?;
                Ok(value)
            }
            Err(error) => match check_observation_boundary($cancellation, $deadline_at_ms) {
                Ok(()) => Err(executor_error(error)),
                Err(boundary) => Err(boundary),
            },
        }
    }};
}

pub struct LinuxAtspiBackend {
    connection: Connection,
    generation: AtomicU64,
    latest: Mutex<Option<StoredSnapshot>>,
    topology: Option<X11TopologyWorker>,
}

struct X11TopologyWorker {
    requests: SyncSender<X11Request>,
}

struct X11ServerIdentity {
    process_id: u32,
    process_generation: String,
    executable: PathBuf,
    user_id: u32,
}

enum X11Request {
    Topology(mpsc::Sender<Result<String, ()>>),
    Desktop(mpsc::Sender<Result<X11DesktopSentinel, ()>>),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct X11Display {
    crtc: u32,
    x: i16,
    y: i16,
    width: u16,
    height: u16,
    rotation: u16,
    outputs: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct X11Topology {
    root: u32,
    width: u16,
    height: u16,
    displays: Vec<X11Display>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct X11DesktopSentinel {
    foreground_window: u32,
    foreground_process_id: u32,
    foreground_process_generation: String,
    keyboard_focus: u32,
    pointer_root: u32,
    pointer_x: i16,
    pointer_y: i16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct AccessibilityFocusSentinel {
    window: StoredObject,
    focused: StoredObject,
    process_id: u32,
    process_generation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SharedDesktopSentinel {
    x11: X11DesktopSentinel,
    accessibility: AccessibilityFocusSentinel,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSnapshot {
    protocol_version: u16,
    observation: SemanticObservation,
    targets: BTreeMap<String, StoredTarget>,
    window: StoredObject,
    window_fingerprint_hash: String,
    process_id: u32,
    process_generation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredObject {
    bus_name: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredTarget {
    object: StoredObject,
    invoke_action: Option<InvokeAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct NodeIdentity {
    backend_id: String,
    role: String,
    name: Option<String>,
    bounds: Option<Rect>,
    relevant_states: u64,
    interfaces: u32,
    actions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct SurfaceIdentity {
    backend_id: String,
    role_code: u32,
    role: String,
    name: Option<String>,
    bounds: Option<Rect>,
    states: u64,
}

#[derive(Clone)]
struct NodeSample {
    identity: NodeIdentity,
    actionability: Actionability,
    invoke_action: Option<InvokeAction>,
    value_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InvokeAction {
    index: i32,
    name: String,
}

#[derive(Clone)]
struct SurfaceWindow {
    object: StoredObject,
    process_id: u32,
    process_generation: String,
    window_id: String,
    fingerprint_hash: String,
    bounds: Option<Rect>,
}

impl StoredSnapshot {
    fn validate(&self, now_ms: i64) -> Result<(), ProtocolError> {
        self.observation.validate(now_ms).map_err(semantic_error)?;
        if self.protocol_version != PROTOCOL_VERSION
            || self.observation.provenance.backend != SemanticBackend::Accessibility
            || self.observation.provenance.backend_name != BACKEND
            || self.observation.provenance.document_id.is_some()
            || self.process_id != self.observation.provenance.process_id
            || self.process_generation != self.observation.provenance.process_generation
            || self.targets.len() != self.observation.elements.len()
        {
            return Err(ProtocolError::StaleTarget(
                "semantic observation changed".to_string(),
            ));
        }
        self.window.validate()?;
        if !is_hash(&self.window_fingerprint_hash) {
            return Err(ProtocolError::StaleTarget(
                "target window changed".to_string(),
            ));
        }
        if semantic_fingerprint(&self.window.id()?).map_err(semantic_error)?
            != self.observation.provenance.window_id
        {
            return Err(ProtocolError::StaleTarget(
                "target window changed".to_string(),
            ));
        }
        for element in &self.observation.elements {
            let target = self.targets.get(&element.element_id).ok_or_else(|| {
                ProtocolError::StaleTarget("semantic mapping changed".to_string())
            })?;
            target.validate()?;
            if opaque_element_id(&self.observation.observation_id, &target.object.id()?)
                .map_err(semantic_error)?
                != element.element_id
                || target.invoke_action.is_some() != element.actionability.invokable
            {
                return Err(ProtocolError::StaleTarget(
                    "semantic mapping changed".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl X11TopologyWorker {
    fn spawn() -> Result<Self, ProtocolError> {
        let (requests, receiver) = mpsc::sync_channel::<X11Request>(1);
        std::thread::Builder::new()
            .name("praefectus-x11-topology".to_string())
            .spawn(move || {
                let mut connection = None;
                while let Ok(request) = receiver.recv() {
                    if connection.is_none() {
                        connection = connect_x11().ok();
                    }
                    match request {
                        X11Request::Topology(response) => {
                            let result = connection.as_ref().ok_or(()).and_then(
                                |(connection, screen, server)| {
                                    server.validate(connection)?;
                                    x11_topology_hash(connection, *screen)
                                },
                            );
                            if result.is_err() {
                                connection = None;
                            }
                            let _ = response.send(result);
                        }
                        X11Request::Desktop(response) => {
                            let result = connection.as_ref().ok_or(()).and_then(
                                |(connection, screen, server)| {
                                    server.validate(connection)?;
                                    x11_desktop_sentinel(connection, *screen)
                                },
                            );
                            if result.is_err() {
                                connection = None;
                            }
                            let _ = response.send(result);
                        }
                    }
                }
            })
            .map_err(executor_error)?;
        Ok(Self { requests })
    }

    fn hash(&self) -> Result<String, ProtocolError> {
        let (response, receiver) = mpsc::channel();
        self.requests
            .try_send(X11Request::Topology(response))
            .map_err(|_| topology_unavailable())?;
        receiver
            .recv_timeout(TOPOLOGY_TIMEOUT)
            .map_err(|_| topology_unavailable())?
            .map_err(|_| topology_unavailable())
    }

    fn desktop_sentinel(&self) -> Result<X11DesktopSentinel, ProtocolError> {
        let (response, receiver) = mpsc::channel();
        self.requests
            .try_send(X11Request::Desktop(response))
            .map_err(|_| desktop_state_unavailable())?;
        receiver
            .recv_timeout(TOPOLOGY_TIMEOUT)
            .map_err(|_| desktop_state_unavailable())?
            .map_err(|_| desktop_state_unavailable())
    }
}

impl X11Topology {
    fn normalize(mut self) -> Result<Self, ()> {
        if self.width == 0
            || self.height == 0
            || self.displays.is_empty()
            || self.displays.len() > MAX_DISPLAYS
        {
            return Err(());
        }
        let mut crtcs = BTreeSet::new();
        let mut outputs = BTreeSet::new();
        for display in &mut self.displays {
            if display.width == 0
                || display.height == 0
                || display.outputs.is_empty()
                || display.outputs.len() > MAX_OUTPUTS
                || !crtcs.insert(display.crtc)
            {
                return Err(());
            }
            display.outputs.sort_unstable();
            if display
                .outputs
                .iter()
                .any(|output| !outputs.insert(*output))
            {
                return Err(());
            }
        }
        self.displays.sort_unstable();
        Ok(self)
    }
}

fn connect_x11() -> Result<(RustConnection, usize, X11ServerIdentity), ()> {
    let display = parse_display(None).map_err(|_| ())?;
    let screen = usize::from(display.screen);
    let address = display
        .connect_instruction()
        .find(|address| matches!(address, ConnectAddress::Socket(_)))
        .ok_or(())?;
    let (stream, (family, address)) = DefaultStream::connect(&address).map_err(|_| ())?;
    let (process_id, user_id) = x11_peer_identity(&stream)?;
    let process_generation = process_generation(process_id).map_err(|_| ())?;
    let executable = fs::read_link(format!("/proc/{process_id}/exe")).map_err(|_| ())?;
    if !trusted_x11_server(process_id, user_id, &executable) {
        return Err(());
    }
    let (auth_name, auth_data) = get_auth(family, &address, display.display)
        .map_err(|_| ())?
        .filter(|(name, data)| !name.is_empty() && !data.is_empty())
        .ok_or(())?;
    let connection =
        RustConnection::connect_to_stream_with_auth_info(stream, screen, auth_name, auth_data)
            .map_err(|_| ())?;
    let server = X11ServerIdentity {
        process_id,
        process_generation,
        executable,
        user_id,
    };
    server.validate(&connection)?;
    Ok((connection, screen, server))
}

impl X11ServerIdentity {
    fn validate(&self, connection: &RustConnection) -> Result<(), ()> {
        if process_generation(self.process_id).map_err(|_| ())? != self.process_generation
            || fs::read_link(format!("/proc/{}/exe", self.process_id)).map_err(|_| ())?
                != self.executable
            || !trusted_x11_server(self.process_id, self.user_id, &self.executable)
            || connection.setup().vendor != b"The X.Org Foundation"
            || connection
                .query_extension(b"XWAYLAND")
                .map_err(|_| ())?
                .reply()
                .map_err(|_| ())?
                .present
        {
            return Err(());
        }
        Ok(())
    }
}

fn x11_peer_identity(stream: &DefaultStream) -> Result<(u32, u32), ()> {
    let credentials = rustix::net::sockopt::socket_peercred(stream).map_err(|_| ())?;
    Ok((
        u32::try_from(credentials.pid.as_raw_pid()).map_err(|_| ())?,
        credentials.uid.as_raw(),
    ))
}

fn native_x11_server_executable(executable: &Path) -> bool {
    executable.file_name() == Some(OsStr::new("Xorg"))
}

fn trusted_x11_server(process_id: u32, user_id: u32, executable: &Path) -> bool {
    let current_user_id = rustix::process::geteuid().as_raw();
    let Ok(metadata) = fs::metadata(format!("/proc/{process_id}/exe")) else {
        return false;
    };
    native_x11_server_executable(executable)
        && (user_id == 0 || user_id == current_user_id)
        && metadata.is_file()
        && trusted_x11_server_file(metadata.uid(), metadata.mode())
}

fn trusted_x11_server_file(owner_id: u32, mode: u32) -> bool {
    owner_id == 0 && mode & 0o022 == 0
}

fn x11_topology_hash(connection: &RustConnection, screen: usize) -> Result<String, ()> {
    let root = connection.setup().roots.get(screen).ok_or(())?.root;
    let before_geometry = connection
        .get_geometry(root)
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    let before = connection
        .randr_get_screen_resources(root)
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    if before.crtcs.len() > MAX_DISPLAYS || before.outputs.len() > MAX_OUTPUTS {
        return Err(());
    }
    let mut displays = Vec::new();
    for crtc in &before.crtcs {
        let info = connection
            .randr_get_crtc_info(*crtc, before.config_timestamp)
            .map_err(|_| ())?
            .reply()
            .map_err(|_| ())?;
        if info.status != SetConfig::SUCCESS {
            return Err(());
        }
        if info.mode == 0 {
            if info.width != 0 || info.height != 0 || !info.outputs.is_empty() {
                return Err(());
            }
            continue;
        }
        displays.push(X11Display {
            crtc: *crtc,
            x: info.x,
            y: info.y,
            width: info.width,
            height: info.height,
            rotation: info.rotation.into(),
            outputs: info.outputs,
        });
    }
    let after = connection
        .randr_get_screen_resources(root)
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    let after_geometry = connection
        .get_geometry(root)
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    if before.timestamp != after.timestamp
        || before.config_timestamp != after.config_timestamp
        || before.crtcs != after.crtcs
        || before.outputs != after.outputs
        || before_geometry.root != after_geometry.root
        || before_geometry.width != after_geometry.width
        || before_geometry.height != after_geometry.height
    {
        return Err(());
    }
    let topology = X11Topology {
        root,
        width: after_geometry.width,
        height: after_geometry.height,
        displays,
    }
    .normalize()?;
    semantic_fingerprint(&topology).map_err(|_| ())
}

fn x11_desktop_sentinel(
    connection: &RustConnection,
    screen: usize,
) -> Result<X11DesktopSentinel, ()> {
    let screen = connection.setup().roots.get(screen).ok_or(())?;
    let active_window_atom = connection
        .intern_atom(true, b"_NET_ACTIVE_WINDOW")
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    if active_window_atom.atom == 0 {
        return Err(());
    }
    let process_id_atom = connection
        .intern_atom(true, b"_NET_WM_PID")
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    if process_id_atom.atom == 0 {
        return Err(());
    }
    let first = x11_desktop_sample(
        connection,
        screen,
        active_window_atom.atom,
        process_id_atom.atom,
    )?;
    let second = x11_desktop_sample(
        connection,
        screen,
        active_window_atom.atom,
        process_id_atom.atom,
    )?;
    (first == second).then_some(second).ok_or(())
}

fn x11_desktop_sample(
    connection: &RustConnection,
    screen: &x11rb::protocol::xproto::Screen,
    active_window_atom: Atom,
    process_id_atom: Atom,
) -> Result<X11DesktopSentinel, ()> {
    let root = screen.root;
    let active_window = connection
        .get_property(false, root, active_window_atom, AtomEnum::WINDOW, 0, 1)
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    if active_window.format != 32
        || active_window.type_ != u32::from(AtomEnum::WINDOW)
        || active_window.value_len != 1
    {
        return Err(());
    }
    let foreground_window = active_window
        .value32()
        .and_then(|mut values| values.next())
        .filter(|window| *window != 0 && *window != root)
        .ok_or(())?;
    if connection
        .get_window_attributes(foreground_window)
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?
        .map_state
        != MapState::VIEWABLE
    {
        return Err(());
    }
    let process_id = connection
        .get_property(
            false,
            foreground_window,
            process_id_atom,
            AtomEnum::CARDINAL,
            0,
            1,
        )
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    if process_id.format != 32
        || process_id.type_ != u32::from(AtomEnum::CARDINAL)
        || process_id.value_len != 1
    {
        return Err(());
    }
    let foreground_process_id = process_id
        .value32()
        .and_then(|mut values| values.next())
        .filter(|process_id| *process_id > 0)
        .ok_or(())?;
    let foreground_process_generation =
        process_generation(foreground_process_id).map_err(|_| ())?;
    let keyboard_focus = x11_keyboard_focus(connection, root, foreground_window)?;
    let pointer = connection
        .query_pointer(root)
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    if !pointer.same_screen
        || pointer.root != root
        || pointer.root_x < 0
        || pointer.root_y < 0
        || i32::from(pointer.root_x) >= i32::from(screen.width_in_pixels)
        || i32::from(pointer.root_y) >= i32::from(screen.height_in_pixels)
    {
        return Err(());
    }
    Ok(X11DesktopSentinel {
        foreground_window,
        foreground_process_id,
        foreground_process_generation,
        keyboard_focus,
        pointer_root: pointer.root,
        pointer_x: pointer.root_x,
        pointer_y: pointer.root_y,
    })
}

fn x11_keyboard_focus(
    connection: &RustConnection,
    root: u32,
    foreground_window: u32,
) -> Result<u32, ()> {
    let focus = connection
        .get_input_focus()
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?
        .focus;
    if !valid_keyboard_focus(focus, root) {
        return Err(());
    }
    let attributes = connection
        .get_window_attributes(focus)
        .map_err(|_| ())?
        .reply()
        .map_err(|_| ())?;
    if attributes.map_state != MapState::VIEWABLE {
        return Err(());
    }
    let mut current = focus;
    for _ in 0..=MAX_DEPTH {
        if current == foreground_window {
            return Ok(focus);
        }
        let tree = connection
            .query_tree(current)
            .map_err(|_| ())?
            .reply()
            .map_err(|_| ())?;
        if tree.root != root || tree.parent == 0 || tree.parent == current || tree.parent == root {
            return Err(());
        }
        current = tree.parent;
    }
    Err(())
}

fn valid_keyboard_focus(focus: u32, root: u32) -> bool {
    focus > 1 && focus != root
}

impl LinuxAtspiBackend {
    pub fn connect() -> Result<Self, ProtocolError> {
        let session = Builder::session()
            .map_err(executor_error)?
            .method_timeout(Duration::from_millis(PROVIDER_TIMEOUT_MS))
            .build()
            .map_err(executor_error)?;
        let address = BusProxyBlocking::new(&session)
            .and_then(|proxy| proxy.get_address())
            .map_err(executor_error)?;
        let address = Address::try_from(address.as_str()).map_err(executor_error)?;
        let connection = Builder::address(address)
            .map(|builder| builder.method_timeout(Duration::from_millis(PROVIDER_TIMEOUT_MS)))
            .and_then(|builder| builder.build())
            .map_err(executor_error)?;
        Ok(Self {
            connection,
            generation: AtomicU64::new(0),
            latest: Mutex::new(None),
            topology: Some(X11TopologyWorker::spawn()?),
        })
    }

    pub fn permissions(
        &self,
        display_geometry: bool,
        private_state: bool,
    ) -> BTreeMap<String, bool> {
        let session = session_type();
        let (wayland, x11) = display_protocol_permissions(session, display_geometry);
        BTreeMap::from([
            ("accessibility".to_string(), true),
            ("atspi2".to_string(), true),
            ("coordinate_capture".to_string(), false),
            ("display_geometry".to_string(), display_geometry),
            ("private_state".to_string(), private_state),
            ("screen_recording".to_string(), false),
            ("wayland".to_string(), wayland),
            ("x11".to_string(), x11),
        ])
    }

    pub fn snapshot(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<SemanticObservation, ProtocolError> {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let display_geometry_hash = self.display_geometry_hash()?;
        let window = self.active_window(cancellation, deadline_at_ms)?;
        self.snapshot_window(window, display_geometry_hash, cancellation, deadline_at_ms)
    }

    pub fn list_surfaces(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Vec<SurfaceDescriptor>, ProtocolError> {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let display_geometry_hash = self.display_geometry_hash()?;
        let windows = self.windows(cancellation, deadline_at_ms)?;
        if self.display_geometry_hash()? != display_geometry_hash {
            return Err(ProtocolError::StaleTarget(
                "display geometry changed".to_string(),
            ));
        }
        check_observation_boundary(cancellation, deadline_at_ms)?;
        windows
            .into_iter()
            .map(|window| window.descriptor(&display_geometry_hash))
            .collect()
    }

    pub fn observe_surface(
        &self,
        surface: &SurfaceRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<SemanticObservation, ProtocolError> {
        if !is_hash(&surface.id) {
            return Err(ProtocolError::InvalidRequest(
                "invalid surface reference".to_string(),
            ));
        }
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let display_geometry_hash = self.display_geometry_hash()?;
        let mut matches = Vec::new();
        for window in self.windows(cancellation, deadline_at_ms)? {
            if window.descriptor(&display_geometry_hash)?.surface == *surface {
                matches.push(window);
            }
        }
        let mut matches = matches.into_iter();
        let window = matches
            .next()
            .ok_or_else(|| ProtocolError::TargetNotFound("surface not found".to_string()))?;
        if matches.next().is_some() {
            return Err(ProtocolError::StaleTarget(
                "surface is ambiguous".to_string(),
            ));
        }
        self.snapshot_window(window, display_geometry_hash, cancellation, deadline_at_ms)
    }

    fn snapshot_window(
        &self,
        window: SurfaceWindow,
        display_geometry_hash: String,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<SemanticObservation, ProtocolError> {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        if self.display_geometry_hash()? != display_geometry_hash {
            return Err(ProtocolError::StaleTarget(
                "display geometry changed".to_string(),
            ));
        }
        self.validate_surface_window(&window, cancellation, deadline_at_ms)?;
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let observed_at_ms = now_ms();
        let observer_process_id = std::process::id();
        let observer_process_generation = process_generation(observer_process_id)?;
        let window_backend_id = window.object.id()?;
        let observation_id = semantic_fingerprint(&(
            BACKEND,
            generation,
            observed_at_ms,
            observer_process_id,
            &observer_process_generation,
            window.process_id,
            &window.process_generation,
            &window_backend_id,
            &window.fingerprint_hash,
            &display_geometry_hash,
        ))
        .map_err(semantic_error)?;
        let window_id = window.window_id.clone();
        let mut queue = VecDeque::from([(window.object.clone(), None, 0_usize)]);
        let mut seen = BTreeSet::new();
        let mut elements = Vec::new();
        let mut targets = BTreeMap::new();
        let mut truncated = false;

        while let Some((object, parent_id, depth)) = queue.pop_front() {
            check_observation_boundary(cancellation, deadline_at_ms)?;
            if elements.len() == MAX_ELEMENTS {
                truncated = true;
                break;
            }
            let backend_id = object.id()?;
            if !seen.insert(backend_id.clone()) {
                return Err(ProtocolError::Executor(
                    "ambiguous accessibility tree".to_string(),
                ));
            }
            self.validate_object_owner(
                &object,
                &window.object.bus_name,
                window.process_id,
                &window.process_generation,
                cancellation,
                deadline_at_ms,
            )?;
            let first = self.sample(&object, cancellation, deadline_at_ms, false)?;
            check_observation_boundary(cancellation, deadline_at_ms)?;
            let second = self.sample(&object, cancellation, deadline_at_ms, false)?;
            let stable = first.identity == second.identity && first.value_hash == second.value_hash;
            let element_id =
                opaque_element_id(&observation_id, &backend_id).map_err(semantic_error)?;
            let fingerprint_hash =
                semantic_fingerprint(&second.identity).map_err(semantic_error)?;
            let mut actionability = second.actionability;
            actionability.stable = stable;
            let invoke_action = second.invoke_action.clone();
            elements.push(SemanticElement {
                tag: semantic_tag(elements.len()).map_err(semantic_error)?,
                element_id: element_id.clone(),
                parent_id,
                fingerprint_hash,
                role: second.identity.role,
                name: second.identity.name,
                bounds: second.identity.bounds,
                actionability,
            });
            targets.insert(
                element_id.clone(),
                StoredTarget {
                    object: object.clone(),
                    invoke_action,
                },
            );

            let accessible = self.accessible(&object)?;
            let child_count =
                provider_call!(cancellation, deadline_at_ms, accessible.child_count())?;
            if child_count < 0 {
                return Err(ProtocolError::Executor(
                    "invalid accessibility tree".to_string(),
                ));
            }
            if depth == MAX_DEPTH {
                truncated |= child_count > 0;
                continue;
            }
            let remaining = MAX_ELEMENTS.saturating_sub(elements.len() + queue.len());
            let to_read = usize::try_from(child_count)
                .unwrap_or(usize::MAX)
                .min(remaining);
            truncated |= usize::try_from(child_count).unwrap_or(usize::MAX) > to_read;
            for index in 0..to_read {
                check_observation_boundary(cancellation, deadline_at_ms)?;
                let child = provider_call!(
                    cancellation,
                    deadline_at_ms,
                    accessible.get_child_at_index(i32::try_from(index).map_err(|_| {
                        ProtocolError::Executor("invalid accessibility tree".to_string())
                    })?)
                )?;
                if child.is_null() {
                    return Err(ProtocolError::StaleTarget(
                        "accessibility tree changed".to_string(),
                    ));
                }
                let child = StoredObject::from_ref(&child)?;
                self.validate_child_binding(
                    &child,
                    &object,
                    (
                        &window.object.bus_name,
                        window.process_id,
                        &window.process_generation,
                    ),
                    cancellation,
                    deadline_at_ms,
                )?;
                queue.push_back((child, Some(element_id.clone()), depth + 1));
            }
        }

        if self.display_geometry_hash()? != display_geometry_hash {
            return Err(ProtocolError::StaleTarget(
                "display geometry changed".to_string(),
            ));
        }
        self.validate_surface_window(&window, cancellation, deadline_at_ms)?;

        let observation = SemanticObservation {
            protocol_version: PROTOCOL_VERSION,
            observation_id,
            generation,
            provenance: SemanticProvenance {
                backend: SemanticBackend::Accessibility,
                backend_name: BACKEND.to_string(),
                process_id: window.process_id,
                process_generation: window.process_generation.clone(),
                window_id,
                document_id: None,
                display_geometry_hash,
            },
            observed_at_ms,
            expires_at_ms: observed_at_ms.saturating_add(OBSERVATION_LIFETIME_MS),
            truncated,
            elements,
        };
        observation.validate(now_ms()).map_err(semantic_error)?;
        let stored = StoredSnapshot {
            protocol_version: PROTOCOL_VERSION,
            observation: observation.clone(),
            targets,
            window: window.object,
            window_fingerprint_hash: window.fingerprint_hash,
            process_id: window.process_id,
            process_generation: window.process_generation,
        };
        stored.validate(now_ms())?;
        crate::persist_private_observation(&observation.observation_id, &stored)?;
        *self.latest.lock().map_err(|_| {
            ProtocolError::Executor("accessibility state unavailable".to_string())
        })? = Some(stored);
        Ok(observation)
    }

    fn validate_surface_window(
        &self,
        window: &SurfaceWindow,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), ProtocolError> {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let process_id = self.process_id(&window.object, cancellation, deadline_at_ms)?;
        if process_id != window.process_id
            || process_generation(process_id)? != window.process_generation
        {
            return Err(ProtocolError::StaleTarget(
                "target process changed".to_string(),
            ));
        }
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let states = self.states(&window.object, cancellation, deadline_at_ms)?;
        if !states.contains(State::Visible)
            || !states.contains(State::Showing)
            || states.contains(State::Defunct)
            || states.contains(State::Iconified)
        {
            return Err(ProtocolError::StaleTarget(
                "target window changed".to_string(),
            ));
        }
        let identity =
            self.surface_identity(&window.object, states, cancellation, deadline_at_ms)?;
        if semantic_fingerprint(&identity).map_err(semantic_error)? != window.fingerprint_hash
            || semantic_fingerprint(&identity.backend_id).map_err(semantic_error)?
                != window.window_id
            || identity.bounds != window.bounds
        {
            return Err(ProtocolError::StaleTarget(
                "target window changed".to_string(),
            ));
        }
        check_observation_boundary(cancellation, deadline_at_ms)
    }

    fn validate_object_owner(
        &self,
        object: &StoredObject,
        expected_bus_name: &str,
        expected_process_id: u32,
        expected_process_generation: &str,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), ProtocolError> {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let process_id = self.process_id(object, cancellation, deadline_at_ms)?;
        let generation = process_generation(process_id)?;
        if !owner_binding_matches(
            expected_bus_name,
            expected_process_id,
            expected_process_generation,
            object,
            process_id,
            &generation,
        ) {
            return Err(ProtocolError::StaleTarget(
                "accessibility object owner changed".to_string(),
            ));
        }
        check_observation_boundary(cancellation, deadline_at_ms)
    }

    fn validate_child_binding(
        &self,
        child: &StoredObject,
        parent: &StoredObject,
        expected_owner: (&str, u32, &str),
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), ProtocolError> {
        if child == parent {
            return Err(ProtocolError::StaleTarget(
                "accessibility tree changed".to_string(),
            ));
        }
        self.validate_object_owner(
            child,
            expected_owner.0,
            expected_owner.1,
            expected_owner.2,
            cancellation,
            deadline_at_ms,
        )?;
        let live_parent = provider_call!(
            cancellation,
            deadline_at_ms,
            self.accessible(child)?.parent()
        )?;
        if live_parent.is_null() || StoredObject::from_ref(&live_parent)? != *parent {
            return Err(ProtocolError::StaleTarget(
                "accessibility tree changed".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_live_descendant(
        &self,
        object: &StoredObject,
        root: &StoredObject,
        process_id: u32,
        process_generation: &str,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), ProtocolError> {
        let mut current = object.clone();
        let mut seen = BTreeSet::new();
        for _ in 0..=MAX_DEPTH {
            self.validate_object_owner(
                &current,
                &root.bus_name,
                process_id,
                process_generation,
                cancellation,
                deadline_at_ms,
            )?;
            if !seen.insert(current.id()?) {
                return Err(ProtocolError::StaleTarget(
                    "accessibility ancestry is ambiguous".to_string(),
                ));
            }
            if current == *root {
                return Ok(());
            }
            let parent = provider_call!(
                cancellation,
                deadline_at_ms,
                self.accessible(&current)?.parent()
            )?;
            if parent.is_null() {
                return Err(ProtocolError::StaleTarget(
                    "accessibility target left its surface".to_string(),
                ));
            }
            current = StoredObject::from_ref(&parent)?;
        }
        Err(ProtocolError::StaleTarget(
            "accessibility ancestry limit exceeded".to_string(),
        ))
    }

    pub fn display_geometry_hash(&self) -> Result<String, ProtocolError> {
        self.topology
            .as_ref()
            .ok_or_else(topology_unavailable)?
            .hash()
    }

    pub fn shared_desktop_context_hash(&self) -> Result<String, ProtocolError> {
        let topology = self
            .topology
            .as_ref()
            .ok_or_else(desktop_state_unavailable)?;
        let x11 = topology.desktop_sentinel()?;
        let cancellation = CancellationToken::default();
        let deadline_at_ms = now_ms().saturating_add(FOCUS_SENTINEL_TIMEOUT_MS);
        let accessibility =
            self.accessibility_focus_sentinel(&x11, &cancellation, deadline_at_ms)?;
        if self.accessibility_focus_sentinel(&x11, &cancellation, deadline_at_ms)? != accessibility
        {
            return Err(desktop_state_unavailable());
        }
        if topology.desktop_sentinel()? != x11 {
            return Err(desktop_state_unavailable());
        }
        let sentinel = SharedDesktopSentinel { x11, accessibility };
        semantic_fingerprint(&sentinel).map_err(semantic_error)
    }

    fn accessibility_focus_sentinel(
        &self,
        x11: &X11DesktopSentinel,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<AccessibilityFocusSentinel, ProtocolError> {
        if process_generation(x11.foreground_process_id)? != x11.foreground_process_generation {
            return Err(desktop_state_unavailable());
        }
        let root = AccessibleProxyBlocking::builder(&self.connection)
            .cache_properties(CacheProperties::No)
            .destination("org.a11y.atspi.Registry")
            .and_then(|builder| builder.path("/org/a11y/atspi/accessible/root"))
            .and_then(|builder| builder.build())
            .map_err(executor_error)?;
        let applications = provider_call!(cancellation, deadline_at_ms, root.get_children())?;
        if applications.len() > MAX_APPLICATIONS {
            return Err(desktop_state_unavailable());
        }
        let mut active = Vec::new();
        for application in applications {
            check_observation_boundary(cancellation, deadline_at_ms)?;
            if application.is_null() {
                continue;
            }
            let application = StoredObject::from_ref(&application)?;
            if self.process_id(&application, cancellation, deadline_at_ms)?
                != x11.foreground_process_id
            {
                continue;
            }
            let accessible = self.accessible(&application)?;
            let child_count =
                provider_call!(cancellation, deadline_at_ms, accessible.child_count())?;
            if child_count < 0
                || usize::try_from(child_count).unwrap_or(usize::MAX) > MAX_WINDOWS_PER_APPLICATION
            {
                return Err(desktop_state_unavailable());
            }
            for index in 0..child_count {
                let window = provider_call!(
                    cancellation,
                    deadline_at_ms,
                    accessible.get_child_at_index(index)
                )?;
                if window.is_null() {
                    continue;
                }
                let window = StoredObject::from_ref(&window)?;
                self.validate_child_binding(
                    &window,
                    &application,
                    (
                        &application.bus_name,
                        x11.foreground_process_id,
                        &x11.foreground_process_generation,
                    ),
                    cancellation,
                    deadline_at_ms,
                )?;
                let role = provider_call!(
                    cancellation,
                    deadline_at_ms,
                    self.accessible(&window)?.get_role()
                )?;
                let states = self.states(&window, cancellation, deadline_at_ms)?;
                if active_window_state(states) {
                    if !matches!(role, Role::Dialog | Role::Frame | Role::Window) {
                        return Err(desktop_state_unavailable());
                    }
                    active.push(window);
                    if active.len() > 1 {
                        return Err(desktop_state_unavailable());
                    }
                }
            }
        }
        let window = active.pop().ok_or_else(desktop_state_unavailable)?;
        let focused = self.focused_descendant(
            &window,
            x11.foreground_process_id,
            &x11.foreground_process_generation,
            cancellation,
            deadline_at_ms,
        )?;
        let process_id = self.process_id(&focused, cancellation, deadline_at_ms)?;
        let focused_process_generation = process_generation(process_id)?;
        let live_window_role = provider_call!(
            cancellation,
            deadline_at_ms,
            self.accessible(&window)?.get_role()
        )?;
        if process_generation(x11.foreground_process_id)? != x11.foreground_process_generation
            || self.process_id(&window, cancellation, deadline_at_ms)? != x11.foreground_process_id
            || process_generation(process_id)? != focused_process_generation
            || !matches!(live_window_role, Role::Dialog | Role::Frame | Role::Window)
            || !active_window_state(self.states(&window, cancellation, deadline_at_ms)?)
            || !focused_state(self.states(&focused, cancellation, deadline_at_ms)?)
        {
            return Err(desktop_state_unavailable());
        }
        Ok(AccessibilityFocusSentinel {
            window,
            focused,
            process_id,
            process_generation: focused_process_generation,
        })
    }

    fn focused_descendant(
        &self,
        window: &StoredObject,
        process_id: u32,
        process_generation: &str,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<StoredObject, ProtocolError> {
        let mut queue = VecDeque::from([(window.clone(), 0_usize)]);
        let mut seen = BTreeSet::new();
        let mut focused = Vec::new();
        while let Some((object, depth)) = queue.pop_front() {
            check_observation_boundary(cancellation, deadline_at_ms)?;
            if !seen.insert(object.id()?) || seen.len() > MAX_FOCUS_ELEMENTS {
                return Err(desktop_state_unavailable());
            }
            self.validate_object_owner(
                &object,
                &window.bus_name,
                process_id,
                process_generation,
                cancellation,
                deadline_at_ms,
            )?;
            let states = self.states(&object, cancellation, deadline_at_ms)?;
            if focused_state(states) {
                focused.push(object.clone());
                if focused.len() > 1 {
                    return Err(desktop_state_unavailable());
                }
            }
            let accessible = self.accessible(&object)?;
            let child_count =
                provider_call!(cancellation, deadline_at_ms, accessible.child_count())?;
            if child_count < 0 {
                return Err(desktop_state_unavailable());
            }
            let child_count =
                usize::try_from(child_count).map_err(|_| desktop_state_unavailable())?;
            if depth == MAX_DEPTH && child_count > 0
                || child_count > MAX_FOCUS_ELEMENTS.saturating_sub(seen.len() + queue.len())
            {
                return Err(desktop_state_unavailable());
            }
            for index in 0..child_count {
                let child = provider_call!(
                    cancellation,
                    deadline_at_ms,
                    accessible.get_child_at_index(
                        i32::try_from(index).map_err(|_| desktop_state_unavailable())?
                    )
                )?;
                if child.is_null() {
                    return Err(desktop_state_unavailable());
                }
                let child = StoredObject::from_ref(&child)?;
                self.validate_child_binding(
                    &child,
                    &object,
                    (&window.bus_name, process_id, process_generation),
                    cancellation,
                    deadline_at_ms,
                )?;
                queue.push_back((child, depth + 1));
            }
        }
        focused.pop().ok_or_else(desktop_state_unavailable)
    }

    pub fn observe_target(
        &self,
        target: &SemanticTargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Observation, ProtocolError> {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let (stored, _object, sample) =
            self.resolve_live(target, cancellation, deadline_at_ms, true)?;
        let fingerprint_hash = semantic_fingerprint(&sample.identity).map_err(semantic_error)?;
        let observation_hash = semantic_fingerprint(&(
            &target.observation_id,
            target.generation,
            &fingerprint_hash,
            now_ms(),
        ))
        .map_err(semantic_error)?;
        let state = observation_state(sample.actionability, sample.value_hash);
        Ok(Observation {
            evidence: Evidence {
                observation_hash,
                target_fingerprint_hash: Some(fingerprint_hash),
                display_geometry_hash: stored.observation.provenance.display_geometry_hash.clone(),
                observed_at_ms: now_ms(),
            },
            element: None,
            state,
        })
    }

    pub fn semantic_invoke(
        &self,
        target: &SemanticTargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        let (stored, object, sample) = self
            .resolve_live(target, cancellation, deadline_at_ms, false)
            .map_err(|error| protocol_before_effect(error, cancellation, deadline_at_ms))?;
        if !sample.actionability.visible
            || !sample.actionability.enabled
            || !sample.actionability.unambiguous
            || !sample.actionability.stable
            || !sample.actionability.invokable
        {
            return Err(no_effect(
                FailureCode::StaleTarget,
                "semantic target is not actionable",
            ));
        }
        check_dispatch_boundary(cancellation, deadline_at_ms)?;
        let proxy = self
            .action(&object)
            .map_err(|_| no_effect(FailureCode::StaleTarget, "semantic target changed"))?;
        let expected_action = sample
            .invoke_action
            .ok_or_else(|| no_effect(FailureCode::StaleTarget, "semantic action is ambiguous"))?;
        let live_actions = self
            .action_names(&proxy, cancellation, deadline_at_ms)
            .map_err(|error| protocol_before_effect(error, cancellation, deadline_at_ms))?;
        if live_actions != sample.identity.actions
            || select_invoke_action(&live_actions).as_ref() != Some(&expected_action)
        {
            return Err(no_effect(
                FailureCode::StaleTarget,
                "semantic action changed",
            ));
        }
        self.validate_live_descendant(
            &object,
            &stored.window,
            stored.process_id,
            &stored.process_generation,
            cancellation,
            deadline_at_ms,
        )
        .map_err(|error| protocol_before_effect(error, cancellation, deadline_at_ms))?;
        if self
            .action_names(&proxy, cancellation, deadline_at_ms)
            .map_err(|error| protocol_before_effect(error, cancellation, deadline_at_ms))?
            != live_actions
        {
            return Err(no_effect(
                FailureCode::StaleTarget,
                "semantic action changed",
            ));
        }
        check_dispatch_boundary(cancellation, deadline_at_ms)?;
        let dispatched = proxy
            .do_action(expected_action.index)
            .map_err(|_| unknown_after_dispatch())?;
        if !dispatched {
            return Err(unknown_after_dispatch());
        }
        check_after_dispatch(cancellation, deadline_at_ms)?;
        Ok(receipt())
    }

    pub fn semantic_set_value(
        &self,
        target: &SemanticTargetRef,
        value: &str,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        if value.len() > 16 * 1024 || value.chars().any(|character| character == '\0') {
            return Err(no_effect(FailureCode::InvalidRequest, "value is invalid"));
        }
        let (stored, object, sample) = self
            .resolve_live(target, cancellation, deadline_at_ms, true)
            .map_err(|error| protocol_before_effect(error, cancellation, deadline_at_ms))?;
        if !sample.actionability.visible
            || !sample.actionability.enabled
            || !sample.actionability.unambiguous
            || !sample.actionability.stable
            || !sample.actionability.editable
            || sample.value_hash.is_none()
        {
            return Err(no_effect(
                FailureCode::StaleTarget,
                "semantic target is not editable",
            ));
        }
        check_dispatch_boundary(cancellation, deadline_at_ms)?;
        let proxy = self
            .editable_text(&object)
            .map_err(|_| no_effect(FailureCode::StaleTarget, "semantic target changed"))?;
        self.validate_live_descendant(
            &object,
            &stored.window,
            stored.process_id,
            &stored.process_generation,
            cancellation,
            deadline_at_ms,
        )
        .map_err(|error| protocol_before_effect(error, cancellation, deadline_at_ms))?;
        check_dispatch_boundary(cancellation, deadline_at_ms)?;
        let dispatched = proxy
            .set_text_contents(value)
            .map_err(|_| unknown_after_dispatch())?;
        if !dispatched {
            return Err(unknown_after_dispatch());
        }
        check_after_dispatch(cancellation, deadline_at_ms)?;
        Ok(receipt())
    }

    fn resolve_live(
        &self,
        target: &SemanticTargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
        include_value: bool,
    ) -> Result<(StoredSnapshot, StoredObject, NodeSample), ProtocolError> {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let in_memory = self
            .latest
            .lock()
            .map_err(|_| ProtocolError::Executor("accessibility state unavailable".to_string()))?
            .clone();
        let stored = match in_memory {
            Some(stored) if stored.observation.observation_id == target.observation_id => stored,
            _ => crate::load_private_observation::<StoredSnapshot>(&target.observation_id)?,
        };
        check_observation_boundary(cancellation, deadline_at_ms)?;
        if self.display_geometry_hash()? != stored.observation.provenance.display_geometry_hash {
            return Err(ProtocolError::StaleTarget(
                "display geometry changed".to_string(),
            ));
        }
        stored.validate(now_ms())?;
        if stored.observation.observation_id != target.observation_id {
            return Err(ProtocolError::StaleTarget(
                "semantic observation changed".to_string(),
            ));
        }
        let expected = stored
            .observation
            .resolve(target, now_ms())
            .map_err(semantic_error)?;
        let mut matches = stored
            .targets
            .iter()
            .filter(|(element_id, _)| *element_id == &target.element_id);
        let stored_target = matches
            .next()
            .map(|(_, target)| target.clone())
            .ok_or_else(|| ProtocolError::StaleTarget("semantic target changed".to_string()))?;
        if matches.next().is_some() {
            return Err(ProtocolError::StaleTarget(
                "semantic target is ambiguous".to_string(),
            ));
        }
        stored_target.validate()?;
        let StoredTarget {
            object,
            invoke_action,
        } = stored_target;
        self.validate_process_and_window(&stored, cancellation, deadline_at_ms)?;
        self.validate_live_descendant(
            &object,
            &stored.window,
            stored.process_id,
            &stored.process_generation,
            cancellation,
            deadline_at_ms,
        )?;
        let first = self.sample(&object, cancellation, deadline_at_ms, include_value)?;
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let mut second = self.sample(&object, cancellation, deadline_at_ms, include_value)?;
        second.actionability.stable =
            first.identity == second.identity && first.value_hash == second.value_hash;
        let fingerprint_hash = semantic_fingerprint(&second.identity).map_err(semantic_error)?;
        if !second.actionability.stable
            || fingerprint_hash != expected.fingerprint_hash
            || second.invoke_action != invoke_action
        {
            return Err(ProtocolError::StaleTarget(
                "semantic target changed".to_string(),
            ));
        }
        Ok((stored, object, second))
    }

    fn validate_process_and_window(
        &self,
        stored: &StoredSnapshot,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), ProtocolError> {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let process_id = self.process_id(&stored.window, cancellation, deadline_at_ms)?;
        if process_id != stored.process_id
            || process_generation(process_id)? != stored.process_generation
        {
            return Err(ProtocolError::StaleTarget(
                "target process changed".to_string(),
            ));
        }
        let states = self.states(&stored.window, cancellation, deadline_at_ms)?;
        if !states.contains(State::Visible)
            || !states.contains(State::Showing)
            || states.contains(State::Defunct)
            || states.contains(State::Iconified)
        {
            return Err(ProtocolError::StaleTarget(
                "target window changed".to_string(),
            ));
        }
        let identity =
            self.surface_identity(&stored.window, states, cancellation, deadline_at_ms)?;
        if semantic_fingerprint(&identity).map_err(semantic_error)?
            != stored.window_fingerprint_hash
        {
            return Err(ProtocolError::StaleTarget(
                "target window changed".to_string(),
            ));
        }
        Ok(())
    }

    fn active_window(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<SurfaceWindow, ProtocolError> {
        let mut active = Vec::new();
        for window in self.windows(cancellation, deadline_at_ms)? {
            if self
                .states(&window.object, cancellation, deadline_at_ms)?
                .contains(State::Active)
            {
                active.push(window);
                if active.len() > 1 {
                    return Err(ProtocolError::Executor(
                        "active accessibility window is ambiguous".to_string(),
                    ));
                }
            }
        }
        active.pop().ok_or_else(|| {
            ProtocolError::TargetNotFound("active accessibility window not found".to_string())
        })
    }

    fn windows(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Vec<SurfaceWindow>, ProtocolError> {
        let root = AccessibleProxyBlocking::builder(&self.connection)
            .cache_properties(CacheProperties::No)
            .destination("org.a11y.atspi.Registry")
            .and_then(|builder| builder.path("/org/a11y/atspi/accessible/root"))
            .and_then(|builder| builder.build())
            .map_err(executor_error)?;
        let applications = provider_call!(cancellation, deadline_at_ms, root.get_children())?;
        if applications.len() > MAX_APPLICATIONS {
            return Err(ProtocolError::Executor(
                "accessibility application limit exceeded".to_string(),
            ));
        }
        let mut windows = Vec::new();
        let mut seen = BTreeSet::new();
        for application in applications {
            check_observation_boundary(cancellation, deadline_at_ms)?;
            if application.is_null() {
                continue;
            }
            let application = StoredObject::from_ref(&application)?;
            let process_id = self.process_id(&application, cancellation, deadline_at_ms)?;
            let generation = process_generation(process_id)?;
            let accessible = self.accessible(&application)?;
            let child_count =
                provider_call!(cancellation, deadline_at_ms, accessible.child_count())?;
            if child_count < 0
                || usize::try_from(child_count).unwrap_or(usize::MAX) > MAX_WINDOWS_PER_APPLICATION
            {
                return Err(ProtocolError::Executor(
                    "accessibility window limit exceeded".to_string(),
                ));
            }
            for index in 0..child_count {
                check_observation_boundary(cancellation, deadline_at_ms)?;
                let window = provider_call!(
                    cancellation,
                    deadline_at_ms,
                    accessible.get_child_at_index(index)
                )?;
                if window.is_null() {
                    continue;
                }
                let window = StoredObject::from_ref(&window)?;
                if !seen.insert(window.id()?) {
                    return Err(ProtocolError::Executor(
                        "accessibility surface is ambiguous".to_string(),
                    ));
                }
                self.validate_child_binding(
                    &window,
                    &application,
                    (&application.bus_name, process_id, &generation),
                    cancellation,
                    deadline_at_ms,
                )?;
                let role = provider_call!(
                    cancellation,
                    deadline_at_ms,
                    self.accessible(&window)?.get_role()
                )?;
                if !matches!(role, Role::Dialog | Role::Frame | Role::Window) {
                    continue;
                }
                let states = self.states(&window, cancellation, deadline_at_ms)?;
                if states.contains(State::Visible)
                    && states.contains(State::Showing)
                    && !states.contains(State::Defunct)
                    && !states.contains(State::Iconified)
                {
                    let identity =
                        self.surface_identity(&window, states, cancellation, deadline_at_ms)?;
                    let window_id =
                        semantic_fingerprint(&identity.backend_id).map_err(semantic_error)?;
                    let fingerprint_hash =
                        semantic_fingerprint(&identity).map_err(semantic_error)?;
                    windows.push(SurfaceWindow {
                        object: window,
                        process_id,
                        process_generation: generation.clone(),
                        window_id,
                        fingerprint_hash,
                        bounds: identity.bounds,
                    });
                    if windows.len() > MAX_SURFACES {
                        return Err(ProtocolError::Executor(
                            "accessibility surface limit exceeded".to_string(),
                        ));
                    }
                }
            }
            if process_generation(process_id)? != generation {
                return Err(ProtocolError::StaleTarget(
                    "target process changed".to_string(),
                ));
            }
            check_observation_boundary(cancellation, deadline_at_ms)?;
        }
        Ok(windows)
    }

    fn surface_identity(
        &self,
        object: &StoredObject,
        states: StateSet,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<SurfaceIdentity, ProtocolError> {
        let accessible = self.accessible(object)?;
        let role_code = provider_call!(cancellation, deadline_at_ms, accessible.get_role())? as u32;
        let role = bounded_text(provider_call!(
            cancellation,
            deadline_at_ms,
            accessible.get_role_name()
        )?)?;
        let name = bounded_optional_text(provider_call!(
            cancellation,
            deadline_at_ms,
            accessible.name()
        )?)?;
        let interfaces = provider_call!(cancellation, deadline_at_ms, accessible.get_interfaces())?;
        let bounds = if interfaces.contains(Interface::Component) {
            let (x, y, width, height) = provider_call!(
                cancellation,
                deadline_at_ms,
                self.component(object)?.get_extents(CoordType::Screen)
            )?;
            (width > 0 && height > 0).then_some(Rect {
                x: i64::from(x),
                y: i64::from(y),
                width: i64::from(width),
                height: i64::from(height),
            })
        } else {
            None
        };
        Ok(SurfaceIdentity {
            backend_id: object.id()?,
            role_code,
            role,
            name,
            bounds,
            states: surface_states(states),
        })
    }

    fn sample(
        &self,
        object: &StoredObject,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
        include_value: bool,
    ) -> Result<NodeSample, ProtocolError> {
        let accessible = self.accessible(object)?;
        let role = bounded_text(provider_call!(
            cancellation,
            deadline_at_ms,
            accessible.get_role_name()
        )?)?;
        let name = bounded_optional_text(provider_call!(
            cancellation,
            deadline_at_ms,
            accessible.name()
        )?)?;
        let states = provider_call!(cancellation, deadline_at_ms, accessible.get_state())?;
        let interfaces = provider_call!(cancellation, deadline_at_ms, accessible.get_interfaces())?;
        let bounds = if interfaces.contains(Interface::Component) {
            let component = self.component(object)?;
            let (x, y, width, height) = provider_call!(
                cancellation,
                deadline_at_ms,
                component.get_extents(CoordType::Screen)
            )?;
            (width > 0 && height > 0).then_some(Rect {
                x: i64::from(x),
                y: i64::from(y),
                width: i64::from(width),
                height: i64::from(height),
            })
        } else {
            None
        };
        let actions = if interfaces.contains(Interface::Action) {
            let proxy = self.action(object)?;
            self.action_names(&proxy, cancellation, deadline_at_ms)?
        } else {
            Vec::new()
        };
        let invoke_action = select_invoke_action(&actions);
        let value_hash = if include_value && interfaces.contains(Interface::Text) {
            self.value_hash(object, cancellation, deadline_at_ms)?
        } else {
            None
        };
        let visible = states.contains(State::Visible)
            && states.contains(State::Showing)
            && !states.contains(State::Defunct)
            && !states.contains(State::Iconified);
        let enabled = states.contains(State::Enabled)
            && states.contains(State::Sensitive)
            && !states.contains(State::Busy);
        let editable = interfaces.contains(Interface::EditableText)
            && states.contains(State::Editable)
            && !states.contains(State::ReadOnly);
        Ok(NodeSample {
            identity: NodeIdentity {
                backend_id: object.id()?,
                role,
                name,
                bounds,
                relevant_states: relevant_states(states),
                interfaces: interfaces.bits(),
                actions,
            },
            actionability: Actionability {
                visible,
                enabled,
                unambiguous: true,
                stable: false,
                receives_events: false,
                invokable: invoke_action.is_some(),
                editable,
            },
            invoke_action,
            value_hash,
        })
    }

    fn action_names(
        &self,
        proxy: &ActionProxyBlocking<'_>,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Vec<String>, ProtocolError> {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let count = provider_call!(cancellation, deadline_at_ms, proxy.n_actions())?;
        if count < 0 || usize::try_from(count).unwrap_or(usize::MAX) > MAX_ACTIONS {
            return Err(ProtocolError::Executor(
                "accessibility action limit exceeded".to_string(),
            ));
        }
        let mut actions = Vec::with_capacity(usize::try_from(count).unwrap_or_default());
        for index in 0..count {
            check_observation_boundary(cancellation, deadline_at_ms)?;
            actions.push(bounded_action_name(provider_call!(
                cancellation,
                deadline_at_ms,
                proxy.get_name(index)
            )?)?);
        }
        Ok(actions)
    }

    fn value_hash(
        &self,
        object: &StoredObject,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Option<String>, ProtocolError> {
        let proxy = self.text(object)?;
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let count = provider_call!(cancellation, deadline_at_ms, proxy.character_count())?;
        if count < 0 || usize::try_from(count).unwrap_or(usize::MAX) > MAX_VALUE_CHARACTERS {
            return Ok(None);
        }
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let value = provider_call!(cancellation, deadline_at_ms, proxy.get_text(0, count))?;
        if value.len() > MAX_VALUE_BYTES
            || value.chars().count() != usize::try_from(count).unwrap_or(usize::MAX)
        {
            return Ok(None);
        }
        Ok(Some(crate::hash_bytes(value.as_bytes())))
    }

    fn states(
        &self,
        object: &StoredObject,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<StateSet, ProtocolError> {
        let proxy = self.accessible(object)?;
        provider_call!(cancellation, deadline_at_ms, proxy.get_state())
    }

    fn process_id(
        &self,
        object: &StoredObject,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<u32, ProtocolError> {
        object.validate()?;
        let name = atspi::zbus::names::BusName::try_from(object.bus_name.as_str())
            .map_err(executor_error)?;
        let proxy = DBusProxy::new(&self.connection).map_err(executor_error)?;
        provider_call!(
            cancellation,
            deadline_at_ms,
            proxy.get_connection_unix_process_id(name)
        )
    }

    fn accessible<'a>(
        &'a self,
        object: &'a StoredObject,
    ) -> Result<AccessibleProxyBlocking<'a>, ProtocolError> {
        object.validate()?;
        AccessibleProxyBlocking::builder(&self.connection)
            .cache_properties(CacheProperties::No)
            .destination(object.bus_name.as_str())
            .and_then(|builder| builder.path(object.path.as_str()))
            .and_then(|builder| builder.build())
            .map_err(executor_error)
    }

    fn action<'a>(
        &'a self,
        object: &'a StoredObject,
    ) -> Result<ActionProxyBlocking<'a>, ProtocolError> {
        object.validate()?;
        ActionProxyBlocking::builder(&self.connection)
            .cache_properties(CacheProperties::No)
            .destination(object.bus_name.as_str())
            .and_then(|builder| builder.path(object.path.as_str()))
            .and_then(|builder| builder.build())
            .map_err(executor_error)
    }

    fn component<'a>(
        &'a self,
        object: &'a StoredObject,
    ) -> Result<ComponentProxyBlocking<'a>, ProtocolError> {
        object.validate()?;
        ComponentProxyBlocking::builder(&self.connection)
            .cache_properties(CacheProperties::No)
            .destination(object.bus_name.as_str())
            .and_then(|builder| builder.path(object.path.as_str()))
            .and_then(|builder| builder.build())
            .map_err(executor_error)
    }

    fn editable_text<'a>(
        &'a self,
        object: &'a StoredObject,
    ) -> Result<EditableTextProxyBlocking<'a>, ProtocolError> {
        object.validate()?;
        EditableTextProxyBlocking::builder(&self.connection)
            .cache_properties(CacheProperties::No)
            .destination(object.bus_name.as_str())
            .and_then(|builder| builder.path(object.path.as_str()))
            .and_then(|builder| builder.build())
            .map_err(executor_error)
    }

    fn text<'a>(
        &'a self,
        object: &'a StoredObject,
    ) -> Result<TextProxyBlocking<'a>, ProtocolError> {
        object.validate()?;
        TextProxyBlocking::builder(&self.connection)
            .cache_properties(CacheProperties::No)
            .destination(object.bus_name.as_str())
            .and_then(|builder| builder.path(object.path.as_str()))
            .and_then(|builder| builder.build())
            .map_err(executor_error)
    }
}

fn relevant_states(states: StateSet) -> u64 {
    [
        State::Active,
        State::Busy,
        State::Defunct,
        State::Editable,
        State::Enabled,
        State::Iconified,
        State::ReadOnly,
        State::Sensitive,
        State::Showing,
        State::Visible,
    ]
    .into_iter()
    .fold(0_u64, |bits, state| {
        if states.contains(state) {
            bits | (1_u64 << state as u32)
        } else {
            bits
        }
    })
}

fn active_window_state(states: StateSet) -> bool {
    states.contains(State::Active)
        && states.contains(State::Visible)
        && states.contains(State::Showing)
        && !states.contains(State::Defunct)
        && !states.contains(State::Iconified)
}

fn focused_state(states: StateSet) -> bool {
    states.contains(State::Focused)
        && states.contains(State::Visible)
        && states.contains(State::Showing)
        && !states.contains(State::Defunct)
}

fn surface_states(states: StateSet) -> u64 {
    [
        State::Defunct,
        State::Iconified,
        State::Showing,
        State::Visible,
    ]
    .into_iter()
    .fold(0_u64, |bits, state| {
        if states.contains(state) {
            bits | (1_u64 << state as u32)
        } else {
            bits
        }
    })
}

impl StoredObject {
    fn from_ref(object: &ObjectRefOwned) -> Result<Self, ProtocolError> {
        let stored = Self {
            bus_name: object
                .name_as_str()
                .ok_or_else(|| {
                    ProtocolError::StaleTarget("accessibility object disappeared".to_string())
                })?
                .to_string(),
            path: object.path_as_str().to_string(),
        };
        stored.validate()?;
        Ok(stored)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.bus_name.len() > 255
            || self.path.len() > 1_792
            || self
                .bus_name
                .chars()
                .chain(self.path.chars())
                .any(char::is_control)
            || atspi::zbus::names::UniqueName::try_from(self.bus_name.as_str()).is_err()
            || atspi::zbus::zvariant::ObjectPath::try_from(self.path.as_str()).is_err()
        {
            return Err(ProtocolError::StaleTarget(
                "accessibility object is invalid".to_string(),
            ));
        }
        Ok(())
    }

    fn id(&self) -> Result<String, ProtocolError> {
        self.validate()?;
        let value = format!("{}:{}", self.bus_name, self.path);
        if value.len() > 2_048 {
            return Err(ProtocolError::StaleTarget(
                "accessibility object is invalid".to_string(),
            ));
        }
        Ok(value)
    }
}

impl StoredTarget {
    fn validate(&self) -> Result<(), ProtocolError> {
        self.object.validate()?;
        if self.invoke_action.as_ref().is_some_and(|action| {
            action.index < 0
                || usize::try_from(action.index).unwrap_or(usize::MAX) >= MAX_ACTIONS
                || !["activate", "click", "press"]
                    .iter()
                    .any(|allowed| action.name.eq_ignore_ascii_case(allowed))
        }) {
            return Err(ProtocolError::StaleTarget(
                "accessibility action is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

impl SurfaceWindow {
    fn descriptor(&self, display_geometry_hash: &str) -> Result<SurfaceDescriptor, ProtocolError> {
        if !is_hash(display_geometry_hash) {
            return Err(topology_unavailable());
        }
        let id = semantic_fingerprint(&(
            BACKEND,
            &self.object,
            self.process_id,
            &self.process_generation,
            &self.window_id,
            &self.fingerprint_hash,
            display_geometry_hash,
        ))
        .map_err(semantic_error)?;
        Ok(SurfaceDescriptor {
            protocol_version: PROTOCOL_VERSION,
            surface: SurfaceRef { id },
            backend: BACKEND.to_string(),
            process_id: self.process_id,
            process_generation: self.process_generation.clone(),
            window_id: self.window_id.clone(),
            display_geometry_hash: display_geometry_hash.to_string(),
            bounds: self.bounds,
        })
    }
}

fn process_generation(process_id: u32) -> Result<String, ProtocolError> {
    let stat = fs::read_to_string(format!("/proc/{process_id}/stat"))
        .map_err(|_| ProtocolError::StaleTarget("target process disappeared".to_string()))?;
    let start_time = parse_process_start_time(&stat)
        .ok_or_else(|| ProtocolError::StaleTarget("target process changed".to_string()))?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| ProtocolError::StaleTarget("target process changed".to_string()))?;
    let boot_id = boot_id.trim();
    if !valid_boot_id(boot_id) {
        return Err(ProtocolError::StaleTarget(
            "target process changed".to_string(),
        ));
    }
    semantic_fingerprint(&(boot_id, start_time))
        .map_err(|_| ProtocolError::StaleTarget("target process changed".to_string()))
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn parse_process_start_time(stat: &str) -> Option<&str> {
    let after_name = stat.rsplit_once(')').map(|(_, fields)| fields.trim())?;
    let start_time = after_name.split_whitespace().nth(19)?;
    start_time
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then_some(start_time)
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn owner_binding_matches(
    expected_bus_name: &str,
    expected_process_id: u32,
    expected_process_generation: &str,
    object: &StoredObject,
    actual_process_id: u32,
    actual_process_generation: &str,
) -> bool {
    object.bus_name == expected_bus_name
        && actual_process_id == expected_process_id
        && actual_process_generation == expected_process_generation
}

fn bounded_text(value: String) -> Result<String, ProtocolError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ProtocolError::Executor(
            "accessibility text is invalid".to_string(),
        ));
    }
    Ok(value)
}

fn bounded_optional_text(value: String) -> Result<Option<String>, ProtocolError> {
    if value.is_empty() {
        return Ok(None);
    }
    bounded_text(value).map(Some)
}

fn bounded_action_name(value: String) -> Result<String, ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ACTION_NAME_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ProtocolError::Executor(
            "accessibility action is invalid".to_string(),
        ));
    }
    Ok(value)
}

fn select_invoke_action(actions: &[String]) -> Option<InvokeAction> {
    let mut allowed = actions.iter().enumerate().filter(|(_, name)| {
        ["activate", "click", "press"]
            .iter()
            .any(|allowed| name.eq_ignore_ascii_case(allowed))
    });
    let (index, name) = allowed.next()?;
    if allowed.next().is_some() {
        return None;
    }
    Some(InvokeAction {
        index: i32::try_from(index).ok()?,
        name: name.clone(),
    })
}

fn observation_state(
    actionability: Actionability,
    value_hash: Option<String>,
) -> serde_json::Value {
    let mut state = serde_json::Map::from_iter([(
        "actionability".to_string(),
        serde_json::json!({
            "visible": actionability.visible,
            "enabled": actionability.enabled,
            "unambiguous": actionability.unambiguous,
            "stable": actionability.stable,
            "receives_events": actionability.receives_events,
            "invokable": actionability.invokable,
            "editable": actionability.editable,
        }),
    )]);
    if let Some(value_hash) = value_hash {
        state.insert(
            "value_hash".to_string(),
            serde_json::Value::String(value_hash),
        );
    }
    serde_json::Value::Object(state)
}

fn session_type() -> &'static str {
    match std::env::var("XDG_SESSION_TYPE") {
        Ok(value) if value.eq_ignore_ascii_case("wayland") => "wayland",
        Ok(value) if value.eq_ignore_ascii_case("x11") => "x11",
        _ if std::env::var_os("WAYLAND_DISPLAY").is_some() => "wayland",
        _ if std::env::var_os("DISPLAY").is_some() => "x11",
        _ => "unknown",
    }
}

fn display_protocol_permissions(session: &str, native_x11: bool) -> (bool, bool) {
    (session == "wayland" && !native_x11, native_x11)
}

fn check_observation_boundary(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(), ProtocolError> {
    if cancellation.is_cancelled() {
        return Err(ProtocolError::ObservationCancelled);
    }
    if now_ms() >= deadline_at_ms {
        return Err(ProtocolError::ObservationExpired);
    }
    Ok(())
}

fn check_dispatch_boundary(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(), DispatchError> {
    if cancellation.is_cancelled() {
        return Err(DispatchError {
            message: "cancelled before effect".to_string(),
            effect: EffectKnowledge::CancelledBeforeEffect,
            code: FailureCode::DispatchFailed,
        });
    }
    if now_ms() >= deadline_at_ms {
        return Err(DispatchError {
            message: "expired before effect".to_string(),
            effect: EffectKnowledge::ExpiredBeforeEffect,
            code: FailureCode::DispatchFailed,
        });
    }
    Ok(())
}

fn check_after_dispatch(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(), DispatchError> {
    if cancellation.is_cancelled() || now_ms() >= deadline_at_ms {
        return Err(unknown_after_dispatch());
    }
    Ok(())
}

fn protocol_before_effect(
    error: ProtocolError,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> DispatchError {
    let _ = error;
    let effect = if cancellation.is_cancelled() {
        EffectKnowledge::CancelledBeforeEffect
    } else if now_ms() >= deadline_at_ms {
        EffectKnowledge::ExpiredBeforeEffect
    } else {
        EffectKnowledge::NoEffect
    };
    DispatchError {
        message: match effect {
            EffectKnowledge::CancelledBeforeEffect => "cancelled before effect",
            EffectKnowledge::ExpiredBeforeEffect => "expired before effect",
            _ => "semantic target changed",
        }
        .to_string(),
        effect,
        code: FailureCode::StaleTarget,
    }
}

fn no_effect(code: FailureCode, message: &str) -> DispatchError {
    DispatchError {
        message: message.to_string(),
        effect: EffectKnowledge::NoEffect,
        code,
    }
}

fn unknown_after_dispatch() -> DispatchError {
    DispatchError {
        message: "accessibility outcome is unknown".to_string(),
        effect: EffectKnowledge::Unknown,
        code: FailureCode::DispatchFailed,
    }
}

fn receipt() -> DispatchReceipt {
    DispatchReceipt {
        backend: BACKEND.to_string(),
        fallback_chain: Vec::new(),
    }
}

fn executor_error(error: impl std::fmt::Display) -> ProtocolError {
    let _ = error;
    ProtocolError::Executor("accessibility backend error".to_string())
}

fn topology_unavailable() -> ProtocolError {
    ProtocolError::Executor("display geometry is unavailable".to_string())
}

fn desktop_state_unavailable() -> ProtocolError {
    ProtocolError::Executor("desktop state is unavailable".to_string())
}

fn semantic_error(error: impl std::fmt::Display) -> ProtocolError {
    let _ = error;
    ProtocolError::StaleTarget("semantic target changed".to_string())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_stat_start_time_is_field_twenty_two() {
        let process_id = std::process::id();
        let generation = process_generation(process_id).expect("current process generation");
        assert!(is_hash(&generation));
    }

    #[test]
    fn session_detection_never_advertises_both_protocols() {
        let permissions = BTreeMap::from([
            ("wayland", session_type() == "wayland"),
            ("x11", session_type() == "x11"),
        ]);
        assert!(!(permissions["wayland"] && permissions["x11"]));
    }

    #[test]
    fn native_x11_server_requires_exact_xorg_executable() {
        assert!(native_x11_server_executable(Path::new(
            "/usr/lib/xorg/Xorg"
        )));
        assert!(!native_x11_server_executable(Path::new(
            "/usr/bin/Xwayland"
        )));
        assert!(!native_x11_server_executable(Path::new(
            "/usr/lib/xorg/Xorg.bin"
        )));
        assert!(trusted_x11_server_file(0, 0o100755));
        assert!(!trusted_x11_server_file(1_000, 0o100755));
        assert!(!trusted_x11_server_file(0, 0o100775));
        assert!(!trusted_x11_server_file(0, 0o100757));
    }

    #[test]
    fn environment_alone_never_advertises_native_x11() {
        assert_eq!(display_protocol_permissions("x11", false), (false, false));
        assert_eq!(
            display_protocol_permissions("unknown", false),
            (false, false)
        );
        assert_eq!(
            display_protocol_permissions("wayland", false),
            (true, false)
        );
        assert_eq!(display_protocol_permissions("x11", true), (false, true));
    }

    #[test]
    fn x11_topology_normalizes_display_and_output_order() {
        let topology = X11Topology {
            root: 1,
            width: 3840,
            height: 2160,
            displays: vec![
                X11Display {
                    crtc: 3,
                    x: 1920,
                    y: 0,
                    width: 1920,
                    height: 1080,
                    rotation: 1,
                    outputs: vec![9, 8],
                },
                X11Display {
                    crtc: 2,
                    x: 0,
                    y: 0,
                    width: 1920,
                    height: 1080,
                    rotation: 1,
                    outputs: vec![7],
                },
            ],
        }
        .normalize()
        .expect("valid topology");
        assert_eq!(topology.displays[0].crtc, 2);
        assert_eq!(topology.displays[1].outputs, vec![8, 9]);
    }

    #[test]
    fn x11_topology_rejects_ambiguous_outputs() {
        let topology = X11Topology {
            root: 1,
            width: 1920,
            height: 1080,
            displays: vec![
                X11Display {
                    crtc: 2,
                    x: 0,
                    y: 0,
                    width: 1920,
                    height: 1080,
                    rotation: 1,
                    outputs: vec![7],
                },
                X11Display {
                    crtc: 3,
                    x: 0,
                    y: 0,
                    width: 1920,
                    height: 1080,
                    rotation: 1,
                    outputs: vec![7],
                },
            ],
        };
        assert!(topology.normalize().is_err());
    }

    #[test]
    fn desktop_sentinel_detects_focus_and_pointer_changes() {
        let before = X11DesktopSentinel {
            foreground_window: 10,
            foreground_process_id: 42,
            foreground_process_generation: "100".to_string(),
            keyboard_focus: 12,
            pointer_root: 1,
            pointer_x: 20,
            pointer_y: 30,
        };
        let mut after = before.clone();
        after.foreground_window = 11;
        assert_ne!(before, after);
        after = before.clone();
        after.foreground_process_generation = "101".to_string();
        assert_ne!(before, after);
        after = before.clone();
        after.keyboard_focus = 13;
        assert_ne!(before, after);
        after = before.clone();
        after.pointer_x = 21;
        assert_ne!(before, after);
    }

    #[test]
    fn keyboard_focus_rejects_x11_sentinels_and_root() {
        assert!(!valid_keyboard_focus(0, 99));
        assert!(!valid_keyboard_focus(1, 99));
        assert!(!valid_keyboard_focus(99, 99));
        assert!(valid_keyboard_focus(100, 99));
    }

    #[test]
    fn accessibility_focus_sentinel_detects_descendant_and_generation_changes() {
        let before = AccessibilityFocusSentinel {
            window: StoredObject {
                bus_name: ":1.42".to_string(),
                path: "/org/a11y/atspi/accessible/1".to_string(),
            },
            focused: StoredObject {
                bus_name: ":1.42".to_string(),
                path: "/org/a11y/atspi/accessible/2".to_string(),
            },
            process_id: 42,
            process_generation: "100".to_string(),
        };
        let mut after = before.clone();
        after.focused.path = "/org/a11y/atspi/accessible/3".to_string();
        assert_ne!(before, after);
        after = before.clone();
        after.process_generation = "101".to_string();
        assert_ne!(before, after);
    }

    #[test]
    fn accessibility_focus_requires_exact_visible_states() {
        let focused = StateSet::new(State::Focused | State::Visible | State::Showing);
        assert!(focused_state(focused));
        assert!(!focused_state(StateSet::new(
            State::Focused | State::Visible
        )));
        assert!(!focused_state(StateSet::new(
            State::Focused | State::Visible | State::Showing | State::Defunct
        )));
        let active = StateSet::new(State::Active | State::Visible | State::Showing);
        assert!(active_window_state(active));
        assert!(!active_window_state(StateSet::new(
            State::Active | State::Visible | State::Showing | State::Iconified
        )));
    }

    #[test]
    fn surface_reference_is_opaque_and_topology_bound() {
        let window = SurfaceWindow {
            object: StoredObject {
                bus_name: ":1.42".to_string(),
                path: "/org/a11y/atspi/accessible/42".to_string(),
            },
            process_id: 42,
            process_generation: "100".to_string(),
            window_id: crate::hash_bytes(b"window"),
            fingerprint_hash: crate::hash_bytes(b"fingerprint"),
            bounds: Some(Rect {
                x: 0,
                y: 0,
                width: 800,
                height: 600,
            }),
        };
        let first = window
            .descriptor(&crate::hash_bytes(b"topology-1"))
            .expect("surface descriptor");
        let second = window
            .descriptor(&crate::hash_bytes(b"topology-2"))
            .expect("surface descriptor");
        assert!(is_hash(&first.surface.id));
        assert_ne!(first.surface, second.surface);
        assert!(!first.surface.id.contains(":1.42"));
    }

    #[test]
    fn malicious_cross_service_child_is_rejected() {
        let child = StoredObject {
            bus_name: ":1.99".to_string(),
            path: "/org/a11y/atspi/accessible/2".to_string(),
        };
        assert!(!owner_binding_matches(
            ":1.42", 42, "100", &child, 42, "100"
        ));
        let child = StoredObject {
            bus_name: ":1.42".to_string(),
            path: "/org/a11y/atspi/accessible/2".to_string(),
        };
        assert!(!owner_binding_matches(
            ":1.42", 42, "100", &child, 99, "100"
        ));
    }

    #[test]
    fn stale_object_owner_generation_is_rejected() {
        let child = StoredObject {
            bus_name: ":1.42".to_string(),
            path: "/org/a11y/atspi/accessible/2".to_string(),
        };
        assert!(owner_binding_matches(":1.42", 42, "100", &child, 42, "100"));
        assert!(!owner_binding_matches(
            ":1.42", 42, "100", &child, 42, "101"
        ));
    }

    #[test]
    fn invoke_selection_requires_one_exact_allowed_action() {
        assert_eq!(
            select_invoke_action(&["show-menu".to_string(), "press".to_string()]),
            Some(InvokeAction {
                index: 1,
                name: "press".to_string(),
            })
        );
        assert_eq!(
            select_invoke_action(&["click".to_string(), "activate".to_string()]),
            None
        );
        assert_eq!(select_invoke_action(&["delete".to_string()]), None);
    }

    #[test]
    fn proc_stat_parser_uses_start_time_after_the_last_parenthesis() {
        let stat =
            "42 (name with ) parenthesis) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456 20";
        assert_eq!(parse_process_start_time(stat), Some("123456"));
        assert!(valid_boot_id("01234567-89ab-cdef-0123-456789abcdef"));
        assert!(!valid_boot_id("01234567-89ab-cdef-0123-456789abcdeg"));
    }

    #[test]
    fn value_state_contains_hash_and_never_plaintext() {
        let value_hash = crate::hash_bytes(b"private value");
        let state = observation_state(
            Actionability {
                visible: true,
                enabled: true,
                unambiguous: true,
                stable: true,
                receives_events: true,
                invokable: false,
                editable: true,
            },
            Some(value_hash.clone()),
        );
        assert_eq!(
            state.get("value_hash").and_then(serde_json::Value::as_str),
            Some(value_hash.as_str())
        );
        assert_eq!(value_hash.len(), 64);
        assert!(
            value_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(!state.to_string().contains("private value"));
    }

    #[test]
    fn observation_boundaries_keep_protocol_classification() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert!(matches!(
            check_observation_boundary(&cancellation, i64::MAX),
            Err(ProtocolError::ObservationCancelled)
        ));
        assert!(matches!(
            check_observation_boundary(&CancellationToken::default(), now_ms()),
            Err(ProtocolError::ObservationExpired)
        ));
    }
}
