use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use fs2::FileExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod cdp;
#[cfg(target_os = "linux")]
mod linux_atspi;
#[cfg(target_os = "linux")]
mod linux_input;
pub mod semantic;
#[cfg(target_os = "windows")]
mod windows_acl;
#[cfg(target_os = "windows")]
mod windows_uia;

pub const PROTOCOL_VERSION: u16 = 2;
const MAX_COORDINATE_OBSERVATION_AGE_MS: i64 = 30_000;
const MAX_VERIFICATION_JSON_BYTES: usize = 64 * 1024;
const MAX_VERIFICATION_JSON_DEPTH: usize = 32;
const MAX_VERIFICATION_JSON_NODES: usize = 4_096;
#[cfg(target_os = "macos")]
const MAX_MAC_SEMANTIC_ELEMENTS: usize = 512;
#[cfg(target_os = "macos")]
const MAX_MAC_AX_COLLECTION_ITEMS: usize = 2_048;
#[cfg(target_os = "macos")]
const MAX_MAC_AX_HIDDEN_WALK_MS: i64 = 500;
#[cfg(target_os = "macos")]
const MAX_MAC_AX_RESOLUTION_MS: i64 = 5_000;
#[cfg(target_os = "macos")]
const MAX_MAC_AX_STRING_CHARACTERS: usize = 1_024;
#[cfg(target_os = "macos")]
const MAX_MAC_AX_STRING_BYTES: usize = 4_096;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub protocol_version: u16,
    pub action_version: u16,
    pub target_version: u16,
    pub verification_version: u16,
    pub operation_id: String,
    pub subject: String,
    pub session_id: String,
    pub authority: SignedAuthority,
    pub action: Action,
    pub target: TargetRef,
    pub interaction_mode: InteractionMode,
    pub deadline_at_ms: i64,
    pub verification: VerificationPolicy,
    pub safety: SafetyClass,
}

impl std::fmt::Debug for ActionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionRequest")
            .field("protocol_version", &self.protocol_version)
            .field("action_version", &self.action_version)
            .field("target_version", &self.target_version)
            .field("verification_version", &self.verification_version)
            .field("operation_id", &self.operation_id)
            .field("subject", &"[redacted]")
            .field("session_id", &"[redacted]")
            .field("authority", &"[redacted]")
            .field("action", &self.action)
            .field("target", &self.target)
            .field("interaction_mode", &self.interaction_mode)
            .field("deadline_at_ms", &self.deadline_at_ms)
            .field("verification", &"[redacted]")
            .field("safety", &self.safety)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionMode {
    Interactive,
    BackgroundOnly,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionIsolation {
    SharedDesktop,
    HostIsolated,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryRoute {
    TargetAddressed,
    Pointer,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundSupport {
    Guarded,
    HostIsolatedOnly,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextPreservation {
    NotApplicable,
    UnchangedAtBoundaries,
    Changed,
    Unavailable,
    HostIsolated,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthority {
    pub grant: AuthorityGrant,
    pub signature: String,
}

impl std::fmt::Debug for SignedAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedAuthority")
            .field("grant", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGrant {
    pub protocol_version: u16,
    pub issuer: String,
    pub key_id: String,
    pub operation_id: String,
    pub subject: String,
    pub session_id: String,
    pub risk: SafetyClass,
    pub expires_at_ms: i64,
    pub policy_generation: String,
    pub action_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetRef {
    Coordinates {
        x: i64,
        y: i64,
        display_id: String,
        display_geometry_hash: String,
        snapshot_id: String,
        snapshot_content_hash: String,
    },
    Element {
        target: semantic::SemanticTargetRef,
    },
    None,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ElementFingerprint {
    pub backend: String,
    pub id: String,
    pub app: String,
    pub process_id: i32,
    pub window: String,
    pub role: String,
    pub label: String,
    pub bounds: Option<Rect>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rect {
    pub x: i64,
    pub y: i64,
    pub width: i64,
    pub height: i64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Invoke,
    Click {
        button: MouseButton,
        count: u32,
        allow_coordinate_fallback: bool,
    },
    TypeText {
        text: String,
        clear: bool,
        press_return: bool,
        delay_ms: Option<u64>,
    },
    Press {
        key: String,
        count: u32,
        delay_ms: Option<u64>,
    },
    Paste {
        text: String,
    },
    Hotkey {
        keys: Vec<String>,
    },
    Scroll {
        direction: Direction,
        amount: u32,
    },
    Move,
    SetValue {
        value: String,
    },
}

impl std::fmt::Debug for Action {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invoke => formatter.write_str("Invoke"),
            Self::Click {
                button,
                count,
                allow_coordinate_fallback,
            } => formatter
                .debug_struct("Click")
                .field("button", button)
                .field("count", count)
                .field("allow_coordinate_fallback", allow_coordinate_fallback)
                .finish(),
            Self::TypeText {
                clear,
                press_return,
                delay_ms,
                ..
            } => formatter
                .debug_struct("TypeText")
                .field("text", &"[redacted]")
                .field("clear", clear)
                .field("press_return", press_return)
                .field("delay_ms", delay_ms)
                .finish(),
            Self::Press {
                count, delay_ms, ..
            } => formatter
                .debug_struct("Press")
                .field("key", &"[redacted]")
                .field("count", count)
                .field("delay_ms", delay_ms)
                .finish(),
            Self::Paste { .. } => formatter
                .debug_struct("Paste")
                .field("text", &"[redacted]")
                .finish(),
            Self::Hotkey { .. } => formatter
                .debug_struct("Hotkey")
                .field("keys", &"[redacted]")
                .finish(),
            Self::Scroll { direction, amount } => formatter
                .debug_struct("Scroll")
                .field("direction", direction)
                .field("amount", amount)
                .finish(),
            Self::Move => formatter.write_str("Move"),
            Self::SetValue { .. } => formatter
                .debug_struct("SetValue")
                .field("value", &"[redacted]")
                .finish(),
        }
    }
}

impl Action {
    fn name(&self) -> &'static str {
        match self {
            Self::Invoke => "invoke",
            Self::Click { .. } => "click",
            Self::TypeText { .. } => "type_text",
            Self::Press { .. } => "press",
            Self::Paste { .. } => "paste",
            Self::Hotkey { .. } => "hotkey",
            Self::Scroll { .. } => "scroll",
            Self::Move => "move",
            Self::SetValue { .. } => "set_value",
        }
    }
}

pub fn action_delivery_route(action: &Action) -> DeliveryRoute {
    match action {
        Action::Invoke | Action::SetValue { .. } => DeliveryRoute::TargetAddressed,
        Action::Scroll { .. } => DeliveryRoute::Unknown,
        _ => DeliveryRoute::Pointer,
    }
}

fn request_delivery_route(action: &Action, target: &TargetRef) -> DeliveryRoute {
    match (action, target) {
        (
            Action::Invoke | Action::SetValue { .. } | Action::Scroll { .. },
            TargetRef::Element { .. },
        ) => DeliveryRoute::TargetAddressed,
        _ => DeliveryRoute::Pointer,
    }
}

fn claim_delivery_route(action: &Action, target: &TargetRef) -> DeliveryRoute {
    if matches!(action, Action::Scroll { .. }) {
        DeliveryRoute::Unknown
    } else {
        request_delivery_route(action, target)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Up,
    Down,
    Left,
    Right,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerificationPolicy {
    None,
    SnapshotChanged,
    TargetState { expected: Value },
    TargetValueHash { sha256: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyClass {
    Reversible,
    External,
    Destructive,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionAck {
    pub protocol_version: u16,
    pub operation_id: String,
    pub sequence: u32,
    pub action_hash: String,
    pub replayed: bool,
    pub state: AckState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AckState {
    Accepted,
    Executing,
    Terminal { terminal: Box<Terminal> },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Terminal {
    Succeeded { receipt: Receipt },
    Rejected { code: FailureCode, message: String },
    Failed { code: FailureCode, message: String },
    CancelledBeforeEffect,
    ExpiredBeforeEffect,
    OutcomeUnknown { receipt: Receipt, message: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    InvalidRequest,
    Conflict,
    StaleTarget,
    TargetNotFound,
    PermissionDenied,
    Unsupported,
    DispatchFailed,
    VerificationFailed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub protocol_version: u16,
    pub action_name: String,
    pub action_hash: String,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    pub backend: String,
    pub fallback_chain: Vec<String>,
    pub delivery_route: DeliveryRoute,
    pub session_isolation: SessionIsolation,
    pub interaction_mode: InteractionMode,
    pub context_preservation: ContextPreservation,
    pub effect: Effect,
    pub before: Option<Evidence>,
    pub after: Option<Evidence>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Verified,
    ExecutedUnverified,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub observation_hash: String,
    pub target_fingerprint_hash: Option<String>,
    pub display_geometry_hash: String,
    pub observed_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteReport {
    pub acknowledgements: Vec<ActionAck>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub platform: String,
    pub backend: String,
    pub session_isolation: SessionIsolation,
    pub supported_actions: Vec<String>,
    pub action_capabilities: Vec<ActionCapability>,
    pub permissions: BTreeMap<String, bool>,
    pub display_geometry_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCapability {
    pub action: String,
    pub delivery_route: DeliveryRoute,
    pub background_support: BackgroundSupport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceRef {
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceDescriptor {
    pub protocol_version: u16,
    pub surface: SurfaceRef,
    pub backend: String,
    pub process_id: u32,
    pub process_generation: String,
    pub window_id: String,
    pub display_geometry_hash: String,
    pub bounds: Option<Rect>,
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub evidence: Evidence,
    pub element: Option<NativeElement>,
    pub state: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinateObservation {
    pub protocol_version: u16,
    pub snapshot_id: String,
    pub display_geometry_hash: String,
    pub snapshot_content_hash: String,
    pub observed_at_ms: i64,
    pub displays: Vec<DisplayGeometry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayGeometry {
    pub display_id: String,
    pub x: i64,
    pub y: i64,
    pub width: i64,
    pub height: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(target_os = "macos")]
struct ElementObservation {
    protocol_version: u16,
    target: semantic::SemanticTargetRef,
    actionability: semantic::Actionability,
    process_id: u32,
    process_generation: String,
    window_id: String,
    path: Vec<usize>,
    backend_id_hash: String,
    display_geometry_hash: String,
    element_fingerprint_hash: String,
    observed_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(target_os = "macos")]
struct ElementObservations {
    protocol_version: u16,
    observation_id: String,
    elements: Vec<ElementObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(target_os = "macos")]
struct MacSurfaceRecord {
    protocol_version: u16,
    descriptor: SurfaceDescriptor,
    cg_window_number: i64,
}

#[derive(Clone, Debug)]
pub enum ResolvedTarget {
    Point(NativePoint),
    Element(Box<NativeElement>),
    Semantic(semantic::SemanticTargetRef),
    None,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativePoint {
    pub x: i64,
    pub y: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBounds {
    pub x: i64,
    pub y: i64,
    pub width: i64,
    pub height: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeElement {
    pub backend: String,
    pub id: String,
    pub app: String,
    pub process_id: Option<i32>,
    pub window: Option<String>,
    pub role: String,
    pub label: Option<String>,
    pub title: Option<String>,
    pub bounds: Option<NativeBounds>,
    pub state: Value,
    pub enabled: Option<bool>,
}

#[derive(Clone, Debug)]
enum Target {
    Point(NativePoint),
    Element(Box<NativeElement>),
}

#[derive(Clone, Copy, Debug)]
enum ImageMode {
    Screen,
}

#[derive(Clone, Debug, Serialize)]
struct NativeSnapshot {
    snapshot_id: String,
    display_geometry_hash: String,
    content_hash: String,
    displays: Vec<DisplayGeometry>,
}

#[derive(Debug)]
struct NativeError;

impl std::fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native runtime error")
    }
}

impl std::error::Error for NativeError {}

struct NativeRuntime;

#[cfg(target_os = "macos")]
fn mac_key_code(ch: char) -> Option<u16> {
    match ch {
        'a' => Some(0x00),
        's' => Some(0x01),
        'd' => Some(0x02),
        'f' => Some(0x03),
        'h' => Some(0x04),
        'g' => Some(0x05),
        'z' => Some(0x06),
        'x' => Some(0x07),
        'c' => Some(0x08),
        'v' => Some(0x09),
        'b' => Some(0x0B),
        'q' => Some(0x0C),
        'w' => Some(0x0D),
        'e' => Some(0x0E),
        'r' => Some(0x0F),
        'y' => Some(0x10),
        't' => Some(0x11),
        '1' => Some(0x12),
        '2' => Some(0x13),
        '3' => Some(0x14),
        '4' => Some(0x15),
        '6' => Some(0x16),
        '5' => Some(0x17),
        '=' => Some(0x18),
        '9' => Some(0x19),
        '7' => Some(0x1A),
        '-' => Some(0x1B),
        '8' => Some(0x1C),
        '0' => Some(0x1D),
        ']' => Some(0x1E),
        'o' => Some(0x1F),
        'u' => Some(0x20),
        '[' => Some(0x21),
        'i' => Some(0x22),
        'p' => Some(0x23),
        'l' => Some(0x25),
        'j' => Some(0x26),
        '\'' => Some(0x27),
        'k' => Some(0x28),
        ';' => Some(0x29),
        '\\' => Some(0x2A),
        ',' => Some(0x2B),
        '/' => Some(0x2C),
        'n' => Some(0x2D),
        'm' => Some(0x2E),
        '.' => Some(0x2F),
        '\t' => Some(0x30),
        ' ' => Some(0x31),
        '`' => Some(0x32),
        '\x7F' => Some(0x33),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn mac_key_name_code(name: &str) -> Option<u16> {
    match name {
        "return" | "enter" => Some(0x24),
        "tab" => Some(0x30),
        "escape" | "esc" => Some(0x35),
        "delete" | "del" => Some(0x75),
        "backspace" => Some(0x33),
        "space" => Some(0x31),
        "up" => Some(0x7E),
        "down" => Some(0x7D),
        "left" => Some(0x7B),
        "right" => Some(0x7C),
        "home" => Some(0x73),
        "end" => Some(0x77),
        "pageup" => Some(0x74),
        "pagedown" => Some(0x79),
        "f1" => Some(0x7A),
        "f2" => Some(0x78),
        "f3" => Some(0x63),
        "f4" => Some(0x76),
        "f5" => Some(0x60),
        "f6" => Some(0x61),
        "f7" => Some(0x62),
        "f8" => Some(0x64),
        "f9" => Some(0x65),
        "f10" => Some(0x6D),
        "f11" => Some(0x67),
        "f12" => Some(0x6F),
        "insert" => Some(0x72),
        "printscreen" => Some(0x69),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
const MAC_FLAG_SHIFT: u64 = 1 << 17;
#[cfg(target_os = "macos")]
const MAC_FLAG_CONTROL: u64 = 1 << 18;
#[cfg(target_os = "macos")]
const MAC_FLAG_ALTERNATE: u64 = 1 << 19;
#[cfg(target_os = "macos")]
const MAC_FLAG_COMMAND: u64 = 1 << 20;

#[cfg(target_os = "macos")]
fn mac_post_key(code: u16, flags: u64) -> Result<(), NativeError> {
    use core_graphics::event::{CGEvent, CGEventTapLocation};
    use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
    let source =
        CGEventSource::new(CGEventSourceStateID::CombinedSessionState).map_err(|_| NativeError)?;
    let event = CGEvent::new_keyboard_event(source.clone(), code, true).map_err(|_| NativeError)?;
    event.set_flags(core_graphics::event::CGEventFlags::from_bits_truncate(
        flags,
    ));
    event.post(CGEventTapLocation::HID);
    let source_up =
        CGEventSource::new(CGEventSourceStateID::CombinedSessionState).map_err(|_| NativeError)?;
    let event_up = CGEvent::new_keyboard_event(source_up, code, false).map_err(|_| NativeError)?;
    event_up.set_flags(core_graphics::event::CGEventFlags::from_bits_truncate(
        flags,
    ));
    event_up.post(CGEventTapLocation::HID);
    Ok(())
}

impl NativeRuntime {
    fn new() -> Self {
        Self
    }

    #[cfg(not(target_os = "linux"))]
    fn permissions(&self) -> Value {
        native_permissions()
    }

    fn resolve_backend(&self) -> &'static str {
        native_backend()
    }

    fn list_screens(&self) -> Result<Value, NativeError> {
        native_screens()
    }

    fn see(
        &self,
        _app: Option<&str>,
        _mode: ImageMode,
        _path: Option<&Path>,
        _retina: bool,
    ) -> Result<NativeSnapshot, NativeError> {
        let screens = self.list_screens()?;
        let display_geometry_hash = hash_value(&screens).map_err(|_| NativeError)?;
        let displays = serde_json::from_value(screens).map_err(|_| NativeError)?;
        let content_hash = native_screen_content_hash()?;
        Ok(NativeSnapshot {
            snapshot_id: native_snapshot_id(&display_geometry_hash),
            display_geometry_hash,
            content_hash,
            displays,
        })
    }

    fn click(&self, target: Target, button: &str) -> Result<(), DispatchError> {
        match target {
            Target::Point(point) => native_click(&point, button).map_err(ambiguous_dispatch),
            Target::Element(_) => Err(unsupported("click requires a pointer target")),
        }
    }

    fn move_cursor(&self, target: Target) -> Result<(), NativeError> {
        match target {
            Target::Point(point) => native_move(&point),
            Target::Element(_) => Err(NativeError),
        }
    }

    fn screen_content_hash(&self) -> Result<String, NativeError> {
        native_screen_content_hash()
    }

    fn target_content_hash(&self, point: &NativePoint) -> Result<String, NativeError> {
        native_target_content_hash(point)
    }

    fn type_text(
        &self,
        _text: &str,
        _clear: bool,
        _press_return: bool,
        _delay_ms: Option<u64>,
        _app: Option<&str>,
    ) -> Result<(), NativeError> {
        #[cfg(target_os = "linux")]
        {
            return linux_input::native_type_text(_text, _clear, _press_return, _delay_ms);
        }
        #[cfg(windows)]
        {
            use windows::Win32::UI::Input::KeyboardAndMouse::*;

            let make_keybd = |vk: VIRTUAL_KEY, flags: KEYBD_EVENT_FLAGS| -> INPUT {
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: vk,
                            wScan: 0,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            };

            if _clear {
                let ctrl_a = [
                    make_keybd(VK_CONTROL, KEYBD_EVENT_FLAGS::default()),
                    make_keybd(VIRTUAL_KEY(0x41), KEYBD_EVENT_FLAGS::default()),
                    make_keybd(VIRTUAL_KEY(0x41), KEYEVENTF_KEYUP),
                    make_keybd(VK_CONTROL, KEYEVENTF_KEYUP),
                ];
                let _ = unsafe { SendInput(&ctrl_a, std::mem::size_of::<INPUT>() as i32) };
            }

            for code_unit in _text.encode_utf16() {
                let down = INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: code_unit,
                            dwFlags: KEYEVENTF_UNICODE,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                };
                let up = INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: code_unit,
                            dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                };
                let _ = unsafe { SendInput(&[down, up], std::mem::size_of::<INPUT>() as i32) };
                if let Some(delay) = _delay_ms {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
            }

            if _press_return {
                let enter = [
                    make_keybd(VK_RETURN, KEYBD_EVENT_FLAGS::default()),
                    make_keybd(VK_RETURN, KEYEVENTF_KEYUP),
                ];
                let _ = unsafe { SendInput(&enter, std::mem::size_of::<INPUT>() as i32) };
            }
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            if !native_permissions()
                .get("accessibility")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return Err(NativeError);
            }
            if _clear {
                let _ = mac_post_key(0x00, MAC_FLAG_COMMAND);
                std::thread::sleep(std::time::Duration::from_millis(50));
                let _ = mac_post_key(0x33, 0);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            for ch in _text.chars() {
                if let Some(code) = mac_key_code(ch.to_ascii_lowercase()) {
                    let needs_shift =
                        ch.is_ascii_uppercase() || "~!@#$%^&*()_+{}|:\"<>?".contains(ch);
                    let flags = if needs_shift { MAC_FLAG_SHIFT } else { 0 };
                    let _ = mac_post_key(code, flags);
                }
                if let Some(delay) = _delay_ms {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(12));
                }
            }
            if _press_return {
                let _ = mac_post_key(0x24, 0);
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        Err(NativeError)
    }

    fn press(&self, _key: &str, _count: u32, _delay_ms: Option<u64>) -> Result<(), NativeError> {
        #[cfg(target_os = "linux")]
        {
            return linux_input::native_press(_key, _count, _delay_ms);
        }
        #[cfg(windows)]
        {
            use windows::Win32::UI::Input::KeyboardAndMouse::*;

            let vk = match _key {
                "return" | "enter" => VK_RETURN,
                "tab" => VK_TAB,
                "escape" | "esc" => VK_ESCAPE,
                "backspace" => VK_BACK,
                "delete" | "del" => VK_DELETE,
                "space" => VK_SPACE,
                "up" => VK_UP,
                "down" => VK_DOWN,
                "left" => VK_LEFT,
                "right" => VK_RIGHT,
                "home" => VK_HOME,
                "end" => VK_END,
                "pageup" => VK_PRIOR,
                "pagedown" => VK_NEXT,
                "f1" => VK_F1,
                "f2" => VK_F2,
                "f3" => VK_F3,
                "f4" => VK_F4,
                "f5" => VK_F5,
                "f6" => VK_F6,
                "f7" => VK_F7,
                "f8" => VK_F8,
                "f9" => VK_F9,
                "f10" => VK_F10,
                "f11" => VK_F11,
                "f12" => VK_F12,
                k if k.len() == 1 => {
                    let ch = k.chars().next().unwrap().to_ascii_uppercase();
                    if ch.is_ascii_uppercase() || ch.is_ascii_digit() {
                        VIRTUAL_KEY(ch as u16)
                    } else {
                        return Err(NativeError);
                    }
                }
                _ => return Err(NativeError),
            };

            for i in 0.._count {
                if i > 0 {
                    if let Some(delay) = _delay_ms {
                        std::thread::sleep(std::time::Duration::from_millis(delay));
                    }
                }
                let down = INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: vk,
                            wScan: 0,
                            dwFlags: KEYBD_EVENT_FLAGS::default(),
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                };
                let up = INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: vk,
                            wScan: 0,
                            dwFlags: KEYEVENTF_KEYUP,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                };
                let _ = unsafe { SendInput(&[down, up], std::mem::size_of::<INPUT>() as i32) };
            }
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            if !native_permissions()
                .get("accessibility")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return Err(NativeError);
            }
            let code = mac_key_name_code(_key)
                .or_else(|| {
                    _key.chars()
                        .next()
                        .and_then(|ch| mac_key_code(ch.to_ascii_lowercase()))
                })
                .ok_or(NativeError)?;
            for i in 0.._count {
                if i > 0
                    && let Some(delay) = _delay_ms
                {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
                let _ = mac_post_key(code, 0);
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        Err(NativeError)
    }

    fn paste(&self, _text: &str) -> Result<(), NativeError> {
        #[cfg(target_os = "linux")]
        {
            return linux_input::native_paste(_text);
        }
        #[cfg(windows)]
        {
            use windows::Win32::System::DataExchange::*;
            use windows::Win32::System::Memory::*;
            use windows::Win32::UI::Input::KeyboardAndMouse::*;

            let wide: Vec<u16> = _text.encode_utf16().chain(std::iter::once(0)).collect();
            let byte_size = wide.len() * std::mem::size_of::<u16>();

            unsafe { OpenClipboard(None) }.map_err(|_| NativeError)?;
            struct ClipboardGuard;
            impl Drop for ClipboardGuard {
                fn drop(&mut self) {
                    unsafe {
                        let _ = CloseClipboard();
                    }
                }
            }
            let _guard = ClipboardGuard;
            unsafe { EmptyClipboard() }.map_err(|_| NativeError)?;

            let hglobal =
                unsafe { GlobalAlloc(GMEM_MOVEABLE, byte_size) }.map_err(|_| NativeError)?;
            let ptr = unsafe { GlobalLock(hglobal) };
            if ptr.is_null() {
                return Err(NativeError);
            }
            unsafe {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr as *mut u16, wide.len());
                let _ = GlobalUnlock(hglobal);
            }
            if unsafe { SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(hglobal.0))) }
                .is_err()
            {
                unsafe {
                    let _ = GlobalFree(hglobal);
                }
                return Err(NativeError);
            }
            drop(_guard);

            let make_keybd = |vk: VIRTUAL_KEY, flags: KEYBD_EVENT_FLAGS| -> INPUT {
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: vk,
                            wScan: 0,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            };
            let ctrl_v = [
                make_keybd(VK_CONTROL, KEYBD_EVENT_FLAGS::default()),
                make_keybd(VIRTUAL_KEY(0x56), KEYBD_EVENT_FLAGS::default()),
                make_keybd(VIRTUAL_KEY(0x56), KEYEVENTF_KEYUP),
                make_keybd(VK_CONTROL, KEYEVENTF_KEYUP),
            ];
            let _ = unsafe { SendInput(&ctrl_v, std::mem::size_of::<INPUT>() as i32) };
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            if !native_permissions()
                .get("accessibility")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return Err(NativeError);
            }
            use std::process::Command;
            let status = Command::new("/usr/bin/pbcopy")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(ref mut stdin) = child.stdin {
                        let _ = stdin.write_all(_text.as_bytes());
                    }
                    child.wait()
                })
                .map_err(|_| NativeError)?;
            if !status.success() {
                return Err(NativeError);
            }
            let _ = mac_post_key(0x09, MAC_FLAG_COMMAND);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        Err(NativeError)
    }

    fn hotkey(&self, _keys: &[&str]) -> Result<(), NativeError> {
        #[cfg(target_os = "linux")]
        {
            return linux_input::native_hotkey(_keys);
        }
        #[cfg(windows)]
        {
            use windows::Win32::UI::Input::KeyboardAndMouse::*;

            if _keys.len() < 2 {
                return Err(NativeError);
            }
            let action_key = _keys.last().ok_or(NativeError)?;
            let modifiers = &_keys[.._keys.len() - 1];

            let action_vk = match *action_key {
                "return" | "enter" => VK_RETURN,
                "tab" => VK_TAB,
                "escape" | "esc" => VK_ESCAPE,
                "backspace" => VK_BACK,
                "delete" | "del" => VK_DELETE,
                "space" => VK_SPACE,
                "up" => VK_UP,
                "down" => VK_DOWN,
                "left" => VK_LEFT,
                "right" => VK_RIGHT,
                k if k.len() == 1 => {
                    let ch = k.chars().next().unwrap().to_ascii_uppercase();
                    if ch.is_ascii_uppercase() || ch.is_ascii_digit() {
                        VIRTUAL_KEY(ch as u16)
                    } else {
                        return Err(NativeError);
                    }
                }
                _ => return Err(NativeError),
            };
            let modifier_vks: Vec<VIRTUAL_KEY> = modifiers
                .iter()
                .map(|m| match *m {
                    "ctrl" => Ok(VK_CONTROL),
                    "alt" => Ok(VK_MENU),
                    "shift" => Ok(VK_SHIFT),
                    "win" => Ok(VK_LWIN),
                    _ => Err(NativeError),
                })
                .collect::<Result<_, _>>()?;

            let make_keybd = |vk: VIRTUAL_KEY, flags: KEYBD_EVENT_FLAGS| -> INPUT {
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: vk,
                            wScan: 0,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            };

            for vk in &modifier_vks {
                let _ = unsafe {
                    SendInput(
                        &[make_keybd(*vk, KEYBD_EVENT_FLAGS::default())],
                        std::mem::size_of::<INPUT>() as i32,
                    )
                };
            }
            let down = make_keybd(action_vk, KEYBD_EVENT_FLAGS::default());
            let up = make_keybd(action_vk, KEYEVENTF_KEYUP);
            let _ = unsafe { SendInput(&[down, up], std::mem::size_of::<INPUT>() as i32) };
            for vk in modifier_vks.iter().rev() {
                let _ = unsafe {
                    SendInput(
                        &[make_keybd(*vk, KEYEVENTF_KEYUP)],
                        std::mem::size_of::<INPUT>() as i32,
                    )
                };
            }
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            if !native_permissions()
                .get("accessibility")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                return Err(NativeError);
            }
            let code = _keys
                .last()
                .and_then(|k| {
                    mac_key_name_code(k).or_else(|| {
                        k.chars()
                            .next()
                            .and_then(|ch| mac_key_code(ch.to_ascii_lowercase()))
                    })
                })
                .ok_or(NativeError)?;
            let mut flags: u64 = 0;
            for &mod_key in &_keys[.._keys.len().saturating_sub(1)] {
                match mod_key {
                    "cmd" | "command" | "super" => flags |= MAC_FLAG_COMMAND,
                    "ctrl" | "control" => flags |= MAC_FLAG_CONTROL,
                    "alt" | "option" | "opt" => flags |= MAC_FLAG_ALTERNATE,
                    "shift" => flags |= MAC_FLAG_SHIFT,
                    _ => return Err(NativeError),
                }
            }
            let _ = mac_post_key(code, flags);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        Err(NativeError)
    }

    fn scroll(&self, _direction: Direction, _amount: u32) -> Result<(), NativeError> {
        #[cfg(target_os = "linux")]
        {
            return linux_input::native_scroll(_direction, _amount);
        }
        #[cfg(windows)]
        {
            use windows::Win32::UI::Input::KeyboardAndMouse::*;

            let (flags, delta) = match _direction {
                Direction::Up => (MOUSEEVENTF_WHEEL, 120u32),
                Direction::Down => (MOUSEEVENTF_WHEEL, (-120i32) as u32),
                Direction::Left => (MOUSEEVENTF_HWHEEL, (-120i32) as u32),
                Direction::Right => (MOUSEEVENTF_HWHEEL, 120u32),
            };
            for _ in 0.._amount {
                let input = INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dx: 0,
                            dy: 0,
                            mouseData: delta,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                };
                let _ = unsafe { SendInput(&[input], std::mem::size_of::<INPUT>() as i32) };
            }
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            use core_graphics::event::CGEventTapLocation;
            use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
            unsafe extern "C" {
                fn CGEventCreateScrollWheelEvent(
                    source: *const std::ffi::c_void,
                    units: u32,
                    wheel_count: u32,
                    wheel1: i32,
                    wheel2: i32,
                ) -> *mut std::ffi::c_void;
            }
            const K_CGSCROLL_EVENT_UNIT_LINE: u32 = 1;
            for _ in 0.._amount {
                let (w1, w2) = match _direction {
                    Direction::Up => (1i32, 0i32),
                    Direction::Down => (-1i32, 0i32),
                    Direction::Left => (0i32, -1i32),
                    Direction::Right => (0i32, 1i32),
                };
                let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
                    .map_err(|_| NativeError)?;
                let source_ptr: *mut core_graphics::sys::CGEventSource =
                    unsafe { std::mem::transmute_copy(&source) };
                let raw = unsafe {
                    CGEventCreateScrollWheelEvent(
                        source_ptr.cast(),
                        K_CGSCROLL_EVENT_UNIT_LINE,
                        2,
                        w1,
                        w2,
                    )
                };
                if raw.is_null() {
                    return Err(NativeError);
                }
                let event: core_graphics::event::CGEvent = unsafe { std::mem::transmute(raw) };
                event.post(CGEventTapLocation::HID);
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        Err(NativeError)
    }

    fn set_value(
        &self,
        target: Target,
        value: &str,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), DispatchError> {
        match target {
            Target::Element(element) => {
                native_element_set_value(&element, value, cancellation, deadline_at_ms)
            }
            Target::Point(_) => Err(unsupported("set_value requires an element target")),
        }
    }
}

fn native_backend() -> &'static str {
    #[cfg(windows)]
    {
        windows_uia::backend()
    }
    #[cfg(not(windows))]
    {
        match std::env::consts::OS {
            "macos" => "praefectus-macos-ax",
            "linux" => "praefectus-linux",
            _ => "praefectus-unavailable",
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn native_permissions() -> Value {
    native_platform_permissions()
}

#[cfg(target_os = "macos")]
fn native_platform_permissions() -> Value {
    serde_json::json!({
        "accessibility": unsafe { accessibility_sys::AXIsProcessTrusted() },
        "screen_recording": core_graphics::access::ScreenCaptureAccess.preflight(),
        "coordinate_capture": false,
        "private_state": private_storage_available(),
    })
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn native_platform_permissions() -> Value {
    serde_json::json!({"accessibility": false, "screen_recording": false, "coordinate_capture": false, "private_state": private_storage_available()})
}

#[cfg(windows)]
fn native_platform_permissions() -> Value {
    serde_json::json!({
        "accessibility": windows_uia::available(),
        "screen_recording": false,
        "coordinate_capture": false,
        "private_state": private_storage_available(),
    })
}

#[cfg(not(any(unix, windows)))]
fn native_platform_permissions() -> Value {
    serde_json::json!({"accessibility": false, "screen_recording": false, "coordinate_capture": false, "private_state": false})
}

fn native_screens() -> Result<Value, NativeError> {
    #[cfg(target_os = "macos")]
    {
        use core_graphics::display::CGDisplay;

        let displays = CGDisplay::active_displays().map_err(|_| NativeError)?;
        Ok(Value::Array(
            displays
                .into_iter()
                .map(|id| {
                    let bounds = CGDisplay::new(id).bounds();
                    serde_json::json!({
                        "display_id": id.to_string(),
                        "x": bounds.origin.x as i64,
                        "y": bounds.origin.y as i64,
                        "width": bounds.size.width as i64,
                        "height": bounds.size.height as i64,
                    })
                })
                .collect(),
        ))
    }
    #[cfg(windows)]
    {
        windows_uia::screens()
    }
    #[cfg(target_os = "linux")]
    {
        return linux_input::native_screens();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    Ok(Value::Array(Vec::new()))
}

fn native_screen_content_hash() -> Result<String, NativeError> {
    #[cfg(target_os = "macos")]
    {
        use core_graphics::display::CGDisplay;

        if !native_permissions()
            .get("coordinate_capture")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(NativeError);
        }
        let mut hasher = Sha256::new();
        for id in CGDisplay::active_displays().map_err(|_| NativeError)? {
            let display = CGDisplay::new(id);
            let image = display.image().ok_or(NativeError)?;
            let data = image.data();
            hasher.update(id.to_be_bytes());
            hasher.update(image.width().to_be_bytes());
            hasher.update(image.height().to_be_bytes());
            hasher.update(data.as_ref());
        }
        Ok(hex::encode(hasher.finalize()))
    }
    #[cfg(target_os = "linux")]
    {
        return linux_input::native_screen_content_hash();
    }
    #[cfg(windows)]
    {
        use windows::Win32::Graphics::Gdi::*;
        use windows::Win32::UI::WindowsAndMessaging::*;

        let cx = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) };
        let cy = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) };
        let ox = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
        let oy = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
        if cx <= 0 || cy <= 0 {
            return Err(NativeError);
        }
        let screen_dc = unsafe { GetDC(None) };
        if screen_dc.0.is_null() {
            return Err(NativeError);
        }
        let mem_dc = unsafe { CreateCompatibleDC(Some(screen_dc)) };
        if mem_dc.0.is_null() {
            unsafe {
                let _ = ReleaseDC(None, screen_dc);
            }
            return Err(NativeError);
        }
        let bitmap = unsafe { CreateCompatibleBitmap(screen_dc, cx, cy) };
        if bitmap.0.is_null() {
            unsafe {
                let _ = DeleteDC(mem_dc);
                let _ = ReleaseDC(None, screen_dc);
            }
            return Err(NativeError);
        }
        let old_bmp = unsafe { SelectObject(mem_dc, bitmap) };
        let blt_ok =
            unsafe { BitBlt(mem_dc, 0, 0, cx, cy, Some(screen_dc), ox, oy, SRCCOPY) }.as_bool();
        unsafe {
            let _ = SelectObject(mem_dc, old_bmp);
        }
        if !blt_ok {
            unsafe {
                let _ = DeleteObject(HGDIOBJ(bitmap.0));
                let _ = DeleteDC(mem_dc);
                let _ = ReleaseDC(None, screen_dc);
            }
            return Err(NativeError);
        }
        let mut bmi: BITMAPINFO = unsafe { std::mem::zeroed() };
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = cx;
        bmi.bmiHeader.biHeight = -cy;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = 0;
        let buf_len = (cx as usize) * (cy as usize) * 4;
        let mut pixels = vec![0u8; buf_len];
        let n = unsafe {
            GetDIBits(
                mem_dc,
                bitmap,
                0,
                cy as u32,
                Some(pixels.as_mut_ptr().cast()),
                &mut bmi,
                DIB_RGB_COLORS,
            )
        };
        unsafe {
            let _ = DeleteObject(HGDIOBJ(bitmap.0));
            let _ = DeleteDC(mem_dc);
            let _ = ReleaseDC(None, screen_dc);
        }
        if n <= 0 {
            return Err(NativeError);
        }
        let used = (n as usize) * (cx as usize) * 4;
        let mut hasher = Sha256::new();
        hasher.update((ox as i64).to_be_bytes());
        hasher.update((oy as i64).to_be_bytes());
        hasher.update((cx as i64).to_be_bytes());
        hasher.update((cy as i64).to_be_bytes());
        hasher.update(&pixels[..used]);
        return Ok(hex::encode(hasher.finalize()));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    Err(NativeError)
}

#[cfg(any(target_os = "macos", test))]
fn target_capture_bounds(display: &NativeBounds, point: &NativePoint) -> Option<NativeBounds> {
    let right = display.x.checked_add(display.width)?;
    let bottom = display.y.checked_add(display.height)?;
    if display.width <= 0
        || display.height <= 0
        || point.x < display.x
        || point.y < display.y
        || point.x >= right
        || point.y >= bottom
    {
        return None;
    }
    let x = point.x.saturating_sub(32).max(display.x);
    let y = point.y.saturating_sub(32).max(display.y);
    Some(NativeBounds {
        x,
        y,
        width: right.saturating_sub(x).min(64),
        height: bottom.saturating_sub(y).min(64),
    })
}

fn native_target_content_hash(point: &NativePoint) -> Result<String, NativeError> {
    #[cfg(target_os = "macos")]
    {
        use core_graphics::display::CGDisplay;
        use core_graphics::geometry::{CGPoint, CGRect, CGSize};

        if !native_permissions()
            .get("coordinate_capture")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(NativeError);
        }
        for id in CGDisplay::active_displays().map_err(|_| NativeError)? {
            let display = CGDisplay::new(id);
            let bounds = display.bounds();
            let display_bounds = NativeBounds {
                x: bounds.origin.x as i64,
                y: bounds.origin.y as i64,
                width: bounds.size.width as i64,
                height: bounds.size.height as i64,
            };
            let Some(region) = target_capture_bounds(&display_bounds, point) else {
                continue;
            };
            let local = CGRect::new(
                &CGPoint::new(
                    (region.x - display_bounds.x) as f64,
                    (region.y - display_bounds.y) as f64,
                ),
                &CGSize::new(region.width as f64, region.height as f64),
            );
            let image = display.image_for_rect(local).ok_or(NativeError)?;
            let mut hasher = Sha256::new();
            hasher.update(id.to_be_bytes());
            hasher.update(region.x.to_be_bytes());
            hasher.update(region.y.to_be_bytes());
            hasher.update(image.width().to_be_bytes());
            hasher.update(image.height().to_be_bytes());
            hasher.update(image.data().as_ref());
            return Ok(hex::encode(hasher.finalize()));
        }
        Err(NativeError)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = point;
        return Err(NativeError);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = point;
        Err(NativeError)
    }
}

fn native_click(point: &NativePoint, button: &str) -> Result<(), NativeError> {
    #[cfg(target_os = "macos")]
    {
        use core_graphics::event::{CGEvent, CGEventTapLocation, CGEventType, CGMouseButton};
        use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
        use core_graphics::geometry::CGPoint;

        if !native_permissions()
            .get("accessibility")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(NativeError);
        }
        let (down, up, mouse_button) = match button {
            "left" => (
                CGEventType::LeftMouseDown,
                CGEventType::LeftMouseUp,
                CGMouseButton::Left,
            ),
            "right" => (
                CGEventType::RightMouseDown,
                CGEventType::RightMouseUp,
                CGMouseButton::Right,
            ),
            "middle" => (
                CGEventType::OtherMouseDown,
                CGEventType::OtherMouseUp,
                CGMouseButton::Center,
            ),
            _ => return Err(NativeError),
        };
        let position = CGPoint::new(point.x as f64, point.y as f64);
        let down_source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| NativeError)?;
        let down_event = CGEvent::new_mouse_event(down_source, down, position, mouse_button)
            .map_err(|_| NativeError)?;
        let up_source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| NativeError)?;
        let up_event = CGEvent::new_mouse_event(up_source, up, position, mouse_button)
            .map_err(|_| NativeError)?;
        down_event.post(CGEventTapLocation::HID);
        up_event.post(CGEventTapLocation::HID);
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows::Win32::UI::Input::KeyboardAndMouse::*;
        use windows::Win32::UI::WindowsAndMessaging::SetCursorPos;

        if !unsafe { SetCursorPos(point.x as i32, point.y as i32) }.as_bool() {
            return Err(NativeError);
        }
        let (down_flags, up_flags) = match button {
            "left" => (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
            "right" => (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
            "middle" => (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
            _ => return Err(NativeError),
        };
        let down = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: down_flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let up = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: up_flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        if unsafe { SendInput(&[down, up], std::mem::size_of::<INPUT>() as i32) } != 2 {
            return Err(NativeError);
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let native_button = match button {
            "left" => MouseButton::Left,
            "right" => MouseButton::Right,
            "middle" => MouseButton::Middle,
            _ => return Err(NativeError),
        };
        return linux_input::native_click(point, native_button);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (point, button);
        Err(NativeError)
    }
}

fn native_move(point: &NativePoint) -> Result<(), NativeError> {
    #[cfg(target_os = "macos")]
    {
        use core_graphics::event::{CGEvent, CGEventTapLocation, CGEventType, CGMouseButton};
        use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
        use core_graphics::geometry::CGPoint;

        if !native_permissions()
            .get("accessibility")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(NativeError);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| NativeError)?;
        let event = CGEvent::new_mouse_event(
            source,
            CGEventType::MouseMoved,
            CGPoint::new(point.x as f64, point.y as f64),
            CGMouseButton::Left,
        )
        .map_err(|_| NativeError)?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::SetCursorPos;

        if !unsafe { SetCursorPos(point.x as i32, point.y as i32) }.as_bool() {
            return Err(NativeError);
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        return linux_input::native_move(point);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = point;
        Err(NativeError)
    }
}

#[cfg(target_os = "macos")]
struct AxElement(accessibility_sys::AXUIElementRef);

#[cfg(target_os = "macos")]
fn mac_bounded_string_array(
    values: core_foundation::array::CFArray,
    maximum_items: usize,
    maximum_characters: usize,
    maximum_bytes: usize,
) -> Result<Vec<String>, NativeError> {
    use core_foundation::array::CFArrayGetValueAtIndex;
    use core_foundation::base::{CFGetTypeID, TCFType};
    use core_foundation::string::CFString;

    let length = usize::try_from(values.len()).map_err(|_| NativeError)?;
    if length > maximum_items {
        return Err(NativeError);
    }
    let mut strings = Vec::with_capacity(length);
    for index in 0..length {
        let raw = unsafe {
            CFArrayGetValueAtIndex(
                values.as_concrete_TypeRef(),
                isize::try_from(index).map_err(|_| NativeError)?,
            )
        };
        if raw.is_null() || unsafe { CFGetTypeID(raw.cast()) } != CFString::type_id() {
            return Err(NativeError);
        }
        let value = unsafe { CFString::wrap_under_get_rule(raw.cast()) };
        let characters = usize::try_from(value.char_len()).map_err(|_| NativeError)?;
        if characters > maximum_characters {
            return Err(NativeError);
        }
        let value = value.to_string();
        strings.push(
            (value.len() <= maximum_bytes)
                .then_some(value)
                .ok_or(NativeError)?,
        );
    }
    Ok(strings)
}

#[cfg(target_os = "macos")]
impl AxElement {
    fn created(raw: accessibility_sys::AXUIElementRef) -> Result<Self, NativeError> {
        if raw.is_null() {
            return Err(NativeError);
        }
        if unsafe { accessibility_sys::AXUIElementSetMessagingTimeout(raw, 0.1) }
            != accessibility_sys::kAXErrorSuccess
        {
            use core_foundation::base::CFRelease;

            unsafe { CFRelease(raw.cast()) };
            return Err(NativeError);
        }
        Ok(Self(raw))
    }

    fn prepare(&self) -> Result<(), NativeError> {
        (unsafe { accessibility_sys::AXUIElementSetMessagingTimeout(self.0, 0.1) }
            == accessibility_sys::kAXErrorSuccess)
            .then_some(())
            .ok_or(NativeError)
    }

    fn retained(&self) -> Result<Self, NativeError> {
        use core_foundation::base::CFRetain;

        unsafe { CFRetain(self.0.cast()) };
        Self::created(self.0)
    }

    fn identity_hash(&self) -> usize {
        use core_foundation::base::CFHash;

        unsafe { CFHash(self.0.cast()) }
    }

    fn identity_eq(&self, other: &Self) -> bool {
        use core_foundation::base::CFEqual;

        unsafe { CFEqual(self.0.cast(), other.0.cast()) != 0 }
    }

    fn optional_attribute(
        &self,
        name: &str,
    ) -> Result<Option<core_foundation::base::CFType>, NativeError> {
        use accessibility_sys::{
            AXUIElementCopyAttributeValue,
            kAXErrorAttributeUnsupported as K_AX_ERROR_ATTRIBUTE_UNSUPPORTED,
            kAXErrorNoValue as K_AX_ERROR_NO_VALUE, kAXErrorSuccess as K_AX_ERROR_SUCCESS,
        };
        use core_foundation::base::{CFType, TCFType};
        use core_foundation::string::CFString;
        use std::ptr;

        self.prepare()?;
        let key = CFString::new(name);
        let mut raw: core_foundation::base::CFTypeRef = ptr::null();
        match unsafe { AXUIElementCopyAttributeValue(self.0, key.as_concrete_TypeRef(), &mut raw) }
        {
            K_AX_ERROR_SUCCESS if !raw.is_null() => {
                Ok(Some(unsafe { CFType::wrap_under_create_rule(raw) }))
            }
            K_AX_ERROR_ATTRIBUTE_UNSUPPORTED | K_AX_ERROR_NO_VALUE if raw.is_null() => Ok(None),
            _ => Err(NativeError),
        }
    }

    fn attribute(&self, name: &str) -> Result<core_foundation::base::CFType, NativeError> {
        self.optional_attribute(name)?.ok_or(NativeError)
    }

    fn string(&self, name: &str) -> Option<String> {
        use core_foundation::string::CFString;

        let value = self.attribute(name).ok()?.downcast::<CFString>()?;
        let characters = usize::try_from(value.char_len()).ok()?;
        if characters > MAX_MAC_AX_STRING_CHARACTERS {
            return None;
        }
        let value = value.to_string();
        (value.len() <= MAX_MAC_AX_STRING_BYTES).then_some(value)
    }

    fn value_string(&self) -> Option<String> {
        use core_foundation::string::CFString;

        let value = self.attribute("AXValue").ok()?.downcast::<CFString>()?;
        let characters = usize::try_from(value.char_len()).ok()?;
        if characters > 16 * 1_024 {
            return None;
        }
        let value = value.to_string();
        (value.len() <= 16 * 1_024).then_some(value)
    }

    fn boolean(&self, name: &str) -> Option<bool> {
        self.optional_boolean(name).ok().flatten()
    }

    fn optional_boolean(&self, name: &str) -> Result<Option<bool>, NativeError> {
        use core_foundation::boolean::CFBoolean;

        self.optional_attribute(name)?
            .map(|value| {
                value
                    .downcast::<CFBoolean>()
                    .map(bool::from)
                    .ok_or(NativeError)
            })
            .transpose()
    }

    fn element(&self, name: &str) -> Result<Self, NativeError> {
        self.optional_element(name)?.ok_or(NativeError)
    }

    fn optional_element(&self, name: &str) -> Result<Option<Self>, NativeError> {
        use accessibility_sys::AXUIElementGetTypeID;
        use core_foundation::base::{CFGetTypeID, CFRetain, TCFType};

        let Some(value) = self.optional_attribute(name)? else {
            return Ok(None);
        };
        let raw = value.as_CFTypeRef();
        if unsafe { CFGetTypeID(raw) } != unsafe { AXUIElementGetTypeID() } {
            return Err(NativeError);
        }
        unsafe { CFRetain(raw) };
        Self::created(raw.cast_mut().cast()).map(Some)
    }

    fn elements(&self, name: &str, maximum: usize) -> Result<Vec<Self>, NativeError> {
        use accessibility_sys::AXUIElementGetTypeID;
        use core_foundation::array::CFArray;
        use core_foundation::base::{CFGetTypeID, CFRetain};

        let values = self.attribute(name)?;
        let values = values.downcast::<CFArray>().ok_or(NativeError)?;
        let length = usize::try_from(values.len()).map_err(|_| NativeError)?;
        if length > maximum || length > MAX_MAC_AX_COLLECTION_ITEMS {
            return Err(NativeError);
        }
        let mut elements = Vec::new();
        for raw in values.get_all_values() {
            if unsafe { CFGetTypeID(raw.cast()) } != unsafe { AXUIElementGetTypeID() } {
                continue;
            }
            unsafe { CFRetain(raw.cast()) };
            elements.push(Self::created(raw.cast_mut().cast())?);
        }
        Ok(elements)
    }

    fn actions(&self) -> Result<Vec<String>, NativeError> {
        use accessibility_sys::{AXUIElementCopyActionNames, kAXErrorSuccess};
        use core_foundation::array::{CFArray, CFArrayRef};
        use core_foundation::base::TCFType;
        use std::ptr;

        self.prepare()?;
        let mut raw: CFArrayRef = ptr::null();
        if unsafe { AXUIElementCopyActionNames(self.0, &mut raw) } != kAXErrorSuccess
            || raw.is_null()
        {
            return Err(NativeError);
        }
        let actions: CFArray = unsafe { CFArray::wrap_under_create_rule(raw) };
        mac_bounded_string_array(actions, 128, 128, 512)
    }

    fn has_attribute(&self, name: &str) -> Result<bool, NativeError> {
        use accessibility_sys::{AXUIElementCopyAttributeNames, kAXErrorSuccess};
        use core_foundation::array::{CFArray, CFArrayRef};
        use core_foundation::base::TCFType;
        use std::ptr;

        self.prepare()?;
        let mut raw: CFArrayRef = ptr::null();
        if unsafe { AXUIElementCopyAttributeNames(self.0, &mut raw) } != kAXErrorSuccess
            || raw.is_null()
        {
            return Err(NativeError);
        }
        let attributes: CFArray = unsafe { CFArray::wrap_under_create_rule(raw) };
        Ok(mac_bounded_string_array(attributes, 512, 128, 512)?
            .iter()
            .any(|attribute| attribute == name))
    }

    fn is_settable(&self, name: &str) -> bool {
        use accessibility_sys::{AXUIElementIsAttributeSettable, kAXErrorSuccess};
        use core_foundation::base::TCFType;
        use core_foundation::string::CFString;

        if self.prepare().is_err() {
            return false;
        }
        let name = CFString::new(name);
        let mut settable = 0_u8;
        (unsafe {
            AXUIElementIsAttributeSettable(self.0, name.as_concrete_TypeRef(), &mut settable)
                == kAXErrorSuccess
        }) && settable != 0
    }
}

#[cfg(target_os = "macos")]
fn mac_native_boundary(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(), NativeError> {
    if cancellation.is_cancelled() || now_ms() >= deadline_at_ms {
        return Err(NativeError);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn mac_observation_error(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
    fallback: ProtocolError,
) -> ProtocolError {
    if cancellation.is_cancelled() {
        ProtocolError::ObservationCancelled
    } else if now_ms() >= deadline_at_ms {
        ProtocolError::ObservationExpired
    } else {
        fallback
    }
}

#[cfg(target_os = "macos")]
fn mac_ax_hidden(
    element: &AxElement,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<bool, NativeError> {
    let mut candidate = element.retained()?;
    for _ in 0..64 {
        mac_native_boundary(cancellation, deadline_at_ms)?;
        if candidate.optional_boolean("AXHidden")? == Some(true) {
            return Ok(true);
        }
        mac_native_boundary(cancellation, deadline_at_ms)?;
        let Some(parent) = candidate.optional_element("AXParent")? else {
            return Ok(false);
        };
        candidate = parent;
    }
    Err(NativeError)
}

#[cfg(target_os = "macos")]
impl Drop for AxElement {
    fn drop(&mut self) {
        use core_foundation::base::CFRelease;

        unsafe { CFRelease(self.0.cast()) };
    }
}

#[cfg(target_os = "macos")]
fn mac_ax_element_at(point: &NativePoint) -> Result<AxElement, NativeError> {
    use accessibility_sys::{
        AXUIElementCopyElementAtPosition, AXUIElementCreateSystemWide, kAXErrorSuccess,
    };
    use std::ptr;

    let system = AxElement::created(unsafe { AXUIElementCreateSystemWide() })?;
    let mut raw = ptr::null_mut();
    let status = unsafe {
        AXUIElementCopyElementAtPosition(system.0, point.x as f32, point.y as f32, &mut raw)
    };
    if status != kAXErrorSuccess || raw.is_null() {
        return Err(NativeError);
    }
    AxElement::created(raw)
}

#[cfg(target_os = "macos")]
fn mac_ax_bounds(element: &AxElement) -> Result<NativeBounds, NativeError> {
    use accessibility_sys::{
        AXValueGetType, AXValueGetTypeID, AXValueGetValue, kAXValueTypeCGPoint, kAXValueTypeCGSize,
    };
    use core_foundation::base::{CFGetTypeID, TCFType};
    use core_graphics::geometry::{CGPoint, CGSize};

    let position = element.attribute("AXPosition")?;
    let size = element.attribute("AXSize")?;
    let mut point = CGPoint::new(0.0, 0.0);
    let mut dimensions = CGSize::new(0.0, 0.0);
    let point_ref = position.as_CFTypeRef().cast_mut().cast();
    let size_ref = size.as_CFTypeRef().cast_mut().cast();
    if unsafe { CFGetTypeID(position.as_CFTypeRef()) } != unsafe { AXValueGetTypeID() }
        || unsafe { CFGetTypeID(size.as_CFTypeRef()) } != unsafe { AXValueGetTypeID() }
        || unsafe { AXValueGetType(point_ref) } != kAXValueTypeCGPoint
        || unsafe { AXValueGetType(size_ref) } != kAXValueTypeCGSize
        || !unsafe {
            AXValueGetValue(
                point_ref,
                kAXValueTypeCGPoint,
                (&mut point as *mut CGPoint).cast(),
            )
        }
        || !unsafe {
            AXValueGetValue(
                size_ref,
                kAXValueTypeCGSize,
                (&mut dimensions as *mut CGSize).cast(),
            )
        }
    {
        return Err(NativeError);
    }
    Ok(NativeBounds {
        x: point.x as i64,
        y: point.y as i64,
        width: dimensions.width as i64,
        height: dimensions.height as i64,
    })
}

#[cfg(target_os = "macos")]
fn mac_native_element(
    element: &AxElement,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<NativeElement, NativeError> {
    use accessibility_sys::{AXUIElementCreateApplication, AXUIElementGetPid, kAXErrorSuccess};

    mac_native_boundary(cancellation, deadline_at_ms)?;
    let mut process_id = 0;
    element.prepare()?;
    if unsafe { AXUIElementGetPid(element.0, &mut process_id) } != kAXErrorSuccess
        || process_id <= 0
    {
        return Err(NativeError);
    }
    mac_native_boundary(cancellation, deadline_at_ms)?;
    let bounds = mac_ax_bounds(element)?;
    mac_native_boundary(cancellation, deadline_at_ms)?;
    let role = element.string("AXRole").ok_or(NativeError)?;
    let title = element.string("AXTitle");
    let label = element
        .string("AXDescription")
        .filter(|value| !value.is_empty())
        .or_else(|| title.clone());
    let enabled = element.boolean("AXEnabled");
    let focused = element.boolean("AXFocused");
    mac_native_boundary(cancellation, deadline_at_ms)?;
    let window = element
        .element("AXWindow")
        .or_else(|_| element.element("AXTopLevelUIElement"))?;
    let minimized = window.boolean("AXMinimized").unwrap_or(false);
    let window_identity = mac_window_identity(&window, process_id)?;
    mac_native_boundary(cancellation, deadline_at_ms)?;
    let identifier = element
        .string("AXIdentifier")
        .filter(|value| !value.is_empty())
        .map(Ok)
        .unwrap_or_else(|| {
            hash_serializable(&(process_id, &window_identity, &role, &label, &title, &bounds))
                .map_err(|_| NativeError)
        })?;
    let app = AxElement::created(unsafe { AXUIElementCreateApplication(process_id) })?
        .string("AXTitle")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("pid-{process_id}"));
    mac_native_boundary(cancellation, deadline_at_ms)?;
    let value_hash = element
        .value_string()
        .map(|value| hash_bytes(value.as_bytes()));
    let hidden_deadline_at_ms =
        deadline_at_ms.min(now_ms().saturating_add(MAX_MAC_AX_HIDDEN_WALK_MS));
    let visible = !mac_ax_hidden(element, cancellation, hidden_deadline_at_ms)?
        && !minimized
        && native_screens()?.as_array().is_some_and(|screens| {
            screens.iter().any(|screen| {
                let screen_x = screen.get("x").and_then(Value::as_i64);
                let screen_y = screen.get("y").and_then(Value::as_i64);
                let screen_width = screen.get("width").and_then(Value::as_i64);
                let screen_height = screen.get("height").and_then(Value::as_i64);
                matches!(
                    (screen_x, screen_y, screen_width, screen_height),
                    (Some(x), Some(y), Some(width), Some(height))
                        if bounds.width > 0
                            && bounds.height > 0
                            && bounds.x < x.saturating_add(width)
                            && bounds.y < y.saturating_add(height)
                            && bounds.x.saturating_add(bounds.width) > x
                            && bounds.y.saturating_add(bounds.height) > y
                )
            })
        });
    Ok(NativeElement {
        backend: "praefectus-macos-ax".to_string(),
        id: identifier,
        app,
        process_id: Some(process_id),
        window: Some(window_identity),
        role: role.clone(),
        label,
        title,
        bounds: Some(bounds),
        state: serde_json::json!({
            "visible": visible,
            "hidden": !visible,
            "enabled": enabled,
            "focused": focused,
            "role": role,
            "value_hash": value_hash,
        }),
        enabled,
    })
}

#[cfg(target_os = "macos")]
fn mac_ax_element_matching_hash(
    point: &NativePoint,
    expected_hash: &str,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(AxElement, NativeElement), NativeError> {
    let mut element = mac_ax_element_at(point)?;
    for _ in 0..64 {
        mac_native_boundary(cancellation, deadline_at_ms)?;
        if let Ok(candidate) = mac_native_element(&element, cancellation, deadline_at_ms) {
            let fingerprint = ElementFingerprint::from(&candidate);
            if element_fingerprint_hash(&fingerprint).ok().as_deref() == Some(expected_hash) {
                return Ok((element, candidate));
            }
        }
        element = element.element("AXParent")?;
    }
    Err(NativeError)
}

#[cfg(target_os = "macos")]
fn mac_element_receives_events(
    expected: &AxElement,
    point: &NativePoint,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<bool, ProtocolError> {
    if cancellation.is_cancelled() {
        return Err(ProtocolError::ObservationCancelled);
    }
    if now_ms() >= deadline_at_ms {
        return Err(ProtocolError::ObservationExpired);
    }
    let Ok(mut candidate) = mac_ax_element_at(point) else {
        return Ok(false);
    };
    for _ in 0..64 {
        if cancellation.is_cancelled() {
            return Err(ProtocolError::ObservationCancelled);
        }
        if now_ms() >= deadline_at_ms {
            return Err(ProtocolError::ObservationExpired);
        }
        if candidate.identity_eq(expected) {
            return Ok(true);
        }
        let Ok(parent) = candidate.element("AXParent") else {
            return Ok(false);
        };
        candidate = parent;
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
fn mac_actionability_allows(action: &Action, actionability: &semantic::Actionability) -> bool {
    let base = actionability.visible
        && actionability.enabled
        && actionability.unambiguous
        && actionability.stable;
    match action {
        Action::Invoke => base && actionability.invokable,
        Action::SetValue { .. } => base && actionability.editable,
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn mac_live_actionability(
    element: &AxElement,
    expected: &NativeElement,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<semantic::Actionability, ProtocolError> {
    let stale = || ProtocolError::StaleTarget("semantic target changed".to_string());
    let first = mac_native_element(element, cancellation, deadline_at_ms)
        .map_err(|_| mac_observation_error(cancellation, deadline_at_ms, stale()))?;
    validate_matching_live_element(&first, expected)
        .map_err(|_| mac_observation_error(cancellation, deadline_at_ms, stale()))?;
    let second = mac_native_element(element, cancellation, deadline_at_ms)
        .map_err(|_| mac_observation_error(cancellation, deadline_at_ms, stale()))?;
    validate_matching_live_element(&second, &first)
        .map_err(|_| mac_observation_error(cancellation, deadline_at_ms, stale()))?;
    let bounds = second.bounds.as_ref().ok_or_else(stale)?;
    let point = NativePoint {
        x: bounds.x.saturating_add(bounds.width / 2),
        y: bounds.y.saturating_add(bounds.height / 2),
    };
    let visible = second.state.get("visible").and_then(Value::as_bool) == Some(true)
        && second.state.get("hidden").and_then(Value::as_bool) != Some(true);
    let invokable = element
        .actions()
        .is_ok_and(|actions| actions.iter().any(|action| action == "AXPress"));
    let editable = element.is_settable("AXValue");
    let receives_events = visible
        && invokable
        && mac_element_receives_events(element, &point, cancellation, deadline_at_ms)?;
    check_protocol_boundary(cancellation, deadline_at_ms)?;
    Ok(semantic::Actionability {
        visible,
        enabled: second.enabled == Some(true),
        unambiguous: true,
        stable: true,
        receives_events,
        invokable,
        editable,
    })
}

#[cfg(target_os = "macos")]
fn mac_actionability_matches_observation(
    action: &Action,
    observed: &semantic::Actionability,
    live: &semantic::Actionability,
) -> bool {
    observed == live && mac_actionability_allows(action, live)
}

#[cfg(target_os = "macos")]
fn mac_window_identity(window: &AxElement, process_id: i32) -> Result<String, NativeError> {
    let title = window
        .string("AXTitle")
        .filter(|value| !value.is_empty())
        .unwrap_or_default();
    let identifier = window
        .string("AXIdentifier")
        .filter(|value| !value.is_empty())
        .or_else(|| {
            use core_foundation::number::CFNumber;

            window
                .attribute("AXWindowNumber")
                .ok()?
                .downcast::<CFNumber>()?
                .to_i64()
                .map(|value| value.to_string())
        })
        .map(Ok)
        .unwrap_or_else(|| {
            hash_serializable(&(process_id, &title, mac_ax_bounds(window)?))
                .map_err(|_| NativeError)
        })?;
    hash_serializable(&(mac_process_generation(process_id)?, identifier, title))
        .map_err(|_| NativeError)
}

#[cfg(target_os = "macos")]
fn mac_process_generation(process_id: i32) -> Result<String, NativeError> {
    let mut information = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let written = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut information as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if written != size || information.pbi_start_tvsec == 0 {
        return Err(NativeError);
    }
    Ok(format!(
        "{}-{}",
        information.pbi_start_tvsec, information.pbi_start_tvusec
    ))
}

#[cfg(target_os = "macos")]
fn mac_observation_window(
    observation: &ElementObservation,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
    resolution_deadline_at_ms: i64,
) -> Result<AxElement, ProtocolError> {
    check_protocol_boundary(cancellation, deadline_at_ms)?;
    if now_ms() >= resolution_deadline_at_ms {
        return Err(ProtocolError::StaleTarget(
            "semantic target resolution timed out".to_string(),
        ));
    }
    let process_id = i32::try_from(observation.process_id)
        .map_err(|_| ProtocolError::StaleTarget("focused process changed".to_string()))?;
    if !matches!(
        mac_process_generation(process_id),
        Ok(generation) if generation == observation.process_generation
    ) {
        return Err(ProtocolError::StaleTarget(
            "focused process changed".to_string(),
        ));
    }
    let application =
        AxElement::created(unsafe { accessibility_sys::AXUIElementCreateApplication(process_id) })
            .map_err(|_| ProtocolError::StaleTarget("focused process changed".to_string()))?;
    let windows = application.elements("AXWindows", 256).map_err(|_| {
        mac_observation_error(
            cancellation,
            deadline_at_ms,
            ProtocolError::StaleTarget("focused window changed".to_string()),
        )
    })?;
    let mut matches = Vec::new();
    for window in windows {
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        if now_ms() >= resolution_deadline_at_ms {
            return Err(ProtocolError::StaleTarget(
                "semantic target resolution timed out".to_string(),
            ));
        }
        if mac_window_identity(&window, process_id)
            .is_ok_and(|identity| identity == observation.window_id)
        {
            matches.push(window);
        }
    }
    let mut matches = matches.into_iter();
    let window = matches
        .next()
        .ok_or_else(|| ProtocolError::StaleTarget("focused window changed".to_string()))?;
    if matches.next().is_some() {
        return Err(ProtocolError::StaleTarget(
            "focused window is ambiguous".to_string(),
        ));
    }
    Ok(window)
}

#[cfg(target_os = "macos")]
fn mac_element_at_path(
    mut element: AxElement,
    path: &[usize],
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
    resolution_deadline_at_ms: i64,
) -> Result<AxElement, ProtocolError> {
    if path.len() > 256
        || path
            .iter()
            .any(|index| *index >= MAX_MAC_AX_COLLECTION_ITEMS)
    {
        return Err(ProtocolError::StaleTarget(
            "semantic target path is invalid".to_string(),
        ));
    }
    for index in path {
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        if now_ms() >= resolution_deadline_at_ms {
            return Err(ProtocolError::StaleTarget(
                "semantic target resolution timed out".to_string(),
            ));
        }
        element = element
            .elements("AXChildren", MAX_MAC_AX_COLLECTION_ITEMS)
            .map_err(|_| ProtocolError::StaleTarget("semantic target path changed".to_string()))?
            .into_iter()
            .nth(*index)
            .ok_or_else(|| {
                ProtocolError::StaleTarget("semantic target path changed".to_string())
            })?;
        check_protocol_boundary(cancellation, deadline_at_ms)?;
    }
    Ok(element)
}

#[cfg(target_os = "macos")]
fn mac_resolve_observed_element_inner(
    observation: &ElementObservation,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(AxElement, NativeElement), ProtocolError> {
    use std::collections::VecDeque;

    if cancellation.is_cancelled() {
        return Err(ProtocolError::ObservationCancelled);
    }
    if now_ms() >= deadline_at_ms {
        return Err(ProtocolError::ObservationExpired);
    }
    let resolution_deadline_at_ms =
        deadline_at_ms.min(now_ms().saturating_add(MAX_MAC_AX_RESOLUTION_MS));
    let window = mac_observation_window(
        observation,
        cancellation,
        deadline_at_ms,
        resolution_deadline_at_ms,
    )?;
    let target = mac_element_at_path(
        window
            .retained()
            .map_err(|_| ProtocolError::StaleTarget("semantic target path changed".to_string()))?,
        &observation.path,
        cancellation,
        deadline_at_ms,
        resolution_deadline_at_ms,
    )?;
    let target_native = mac_native_element(&target, cancellation, resolution_deadline_at_ms)
        .map_err(|_| {
            mac_observation_error(
                cancellation,
                deadline_at_ms,
                ProtocolError::StaleTarget("semantic target changed".to_string()),
            )
        })?;
    let target_fingerprint = ElementFingerprint::from(&target_native);
    if hash_bytes(target_native.id.as_bytes()) != observation.backend_id_hash
        || element_fingerprint_hash(&target_fingerprint)? != observation.element_fingerprint_hash
    {
        return Err(ProtocolError::StaleTarget(
            "semantic target changed".to_string(),
        ));
    }

    let mut queue = VecDeque::from([window]);
    let mut seen = BTreeMap::<usize, Vec<AxElement>>::new();
    let mut matches = 0usize;
    let mut matched_target = false;
    let mut visited = 0usize;
    while let Some(element) = queue.pop_front() {
        if cancellation.is_cancelled() {
            return Err(ProtocolError::ObservationCancelled);
        }
        if now_ms() >= deadline_at_ms {
            return Err(ProtocolError::ObservationExpired);
        }
        if now_ms() >= resolution_deadline_at_ms {
            return Err(ProtocolError::StaleTarget(
                "semantic target resolution timed out".to_string(),
            ));
        }
        visited = visited.saturating_add(1);
        if visited > MAX_MAC_AX_COLLECTION_ITEMS {
            return Err(ProtocolError::StaleTarget(
                "semantic target tree is ambiguous".to_string(),
            ));
        }
        let identity_hash = element.identity_hash();
        if seen
            .get(&identity_hash)
            .is_some_and(|values| values.iter().any(|value| value.identity_eq(&element)))
        {
            continue;
        }
        seen.entry(identity_hash).or_default().push(
            element.retained().map_err(|_| {
                ProtocolError::StaleTarget("semantic target tree changed".to_string())
            })?,
        );
        if let Ok(candidate) = mac_native_element(&element, cancellation, resolution_deadline_at_ms)
        {
            let fingerprint = ElementFingerprint::from(&candidate);
            if hash_bytes(candidate.id.as_bytes()) == observation.backend_id_hash
                && element_fingerprint_hash(&fingerprint)? == observation.element_fingerprint_hash
            {
                matches = matches.saturating_add(1);
                matched_target |= element.identity_eq(&target);
            }
        }
        match element.has_attribute("AXChildren") {
            Ok(false) => {}
            Ok(true) => queue.extend(
                element
                    .elements(
                        "AXChildren",
                        MAX_MAC_AX_COLLECTION_ITEMS.saturating_sub(visited),
                    )
                    .map_err(|_| {
                        ProtocolError::StaleTarget("semantic target tree changed".to_string())
                    })?,
            ),
            Err(_) => {
                return Err(ProtocolError::StaleTarget(
                    "semantic target tree changed".to_string(),
                ));
            }
        }
    }
    if now_ms() >= resolution_deadline_at_ms {
        return Err(ProtocolError::StaleTarget(
            "semantic target resolution timed out".to_string(),
        ));
    }
    if matches != 1 || !matched_target {
        return Err(ProtocolError::StaleTarget(
            "semantic target is ambiguous".to_string(),
        ));
    }
    Ok((target, target_native))
}

#[cfg(target_os = "macos")]
fn mac_resolve_observed_element(
    observation: &ElementObservation,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(AxElement, NativeElement), ProtocolError> {
    check_protocol_boundary(cancellation, deadline_at_ms)?;
    let result = mac_resolve_observed_element_inner(observation, cancellation, deadline_at_ms);
    check_protocol_boundary(cancellation, deadline_at_ms)?;
    result
}

#[cfg(target_os = "macos")]
fn mac_frontmost_window(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<AxElement, NativeError> {
    mac_surface_windows(cancellation, deadline_at_ms)
        .map_err(|_| NativeError)?
        .into_iter()
        .next()
        .map(|(_, _, window)| window)
        .ok_or(NativeError)
}

#[cfg(target_os = "macos")]
fn mac_shared_desktop_context_hash(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<String, NativeError> {
    use accessibility_sys::{AXUIElementCreateApplication, AXUIElementGetPid, kAXErrorSuccess};
    use core_graphics::event::CGEvent;
    use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};

    mac_native_boundary(cancellation, deadline_at_ms)?;
    let window = mac_frontmost_window(cancellation, deadline_at_ms)?;
    let mut process_id = 0;
    window.prepare()?;
    if unsafe { AXUIElementGetPid(window.0, &mut process_id) } != kAXErrorSuccess || process_id <= 0
    {
        return Err(NativeError);
    }
    mac_native_boundary(cancellation, deadline_at_ms)?;
    let process_generation = mac_process_generation(process_id)?;
    let window_id = mac_window_identity(&window, process_id)?;
    let application = AxElement::created(unsafe { AXUIElementCreateApplication(process_id) })?;
    let focused = application.element("AXFocusedUIElement")?;
    let mut candidate = focused;
    let mut ancestry = Vec::new();
    let mut belongs_to_window = false;
    for _ in 0..64 {
        mac_native_boundary(cancellation, deadline_at_ms)?;
        ancestry.push((
            candidate.identity_hash(),
            candidate.string("AXRole").ok_or(NativeError)?,
            candidate.string("AXSubrole").unwrap_or_default(),
            hash_bytes(
                candidate
                    .string("AXIdentifier")
                    .unwrap_or_default()
                    .as_bytes(),
            ),
        ));
        if candidate.identity_eq(&window) {
            belongs_to_window = true;
            break;
        }
        candidate = candidate.element("AXParent")?;
    }
    if !belongs_to_window {
        return Err(NativeError);
    }
    let focused_identity = hash_serializable(&ancestry).map_err(|_| NativeError)?;
    let source =
        CGEventSource::new(CGEventSourceStateID::CombinedSessionState).map_err(|_| NativeError)?;
    let cursor = CGEvent::new(source).map_err(|_| NativeError)?.location();
    hash_serializable(&(
        process_id,
        process_generation,
        window_id,
        focused_identity,
        cursor.x.to_bits(),
        cursor.y.to_bits(),
    ))
    .map_err(|_| NativeError)
}

#[cfg(target_os = "macos")]
fn mac_surface_windows(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<Vec<(i32, i64, AxElement)>, ProtocolError> {
    use accessibility_sys::{
        AXUIElementCreateApplication, AXUIElementSetMessagingTimeout, kAXErrorSuccess,
    };
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::{CFDictionary, CFDictionaryGetValue};
    use core_foundation::number::CFNumber;
    use core_graphics::geometry::CGRect;
    use core_graphics::window::{
        kCGNullWindowID, kCGWindowBounds, kCGWindowLayer, kCGWindowListExcludeDesktopElements,
        kCGWindowListOptionOnScreenOnly, kCGWindowNumber, kCGWindowOwnerPID,
    };

    let windows = core_graphics::window::copy_window_info(
        kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
        kCGNullWindowID,
    )
    .ok_or_else(|| ProtocolError::Executor("desktop backend error".to_string()))?;
    let mut surfaces = Vec::new();
    for raw in windows
        .get_all_values()
        .into_iter()
        .take(MAX_MAC_SEMANTIC_ELEMENTS)
    {
        if cancellation.is_cancelled() {
            return Err(ProtocolError::ObservationCancelled);
        }
        if now_ms() >= deadline_at_ms {
            return Err(ProtocolError::ObservationExpired);
        }
        let number = |key| {
            let value = unsafe { CFDictionaryGetValue(raw.cast(), key) };
            if value.is_null() {
                return None;
            }
            unsafe { CFType::wrap_under_get_rule(value.cast()) }
                .downcast::<CFNumber>()?
                .to_i64()
        };
        if number(unsafe { kCGWindowLayer }.cast()) != Some(0) {
            continue;
        }
        let Some(process_id) = number(unsafe { kCGWindowOwnerPID }.cast())
            .and_then(|value| i32::try_from(value).ok())
            .filter(|value| *value > 0 && u32::try_from(*value).ok() != Some(std::process::id()))
        else {
            continue;
        };
        let Some(window_number) = number(unsafe { kCGWindowNumber }.cast()) else {
            continue;
        };
        let bounds_value = unsafe { CFDictionaryGetValue(raw.cast(), kCGWindowBounds.cast()) };
        if bounds_value.is_null() {
            continue;
        }
        let Some(bounds_dictionary) =
            unsafe { CFType::wrap_under_get_rule(bounds_value.cast()) }.downcast::<CFDictionary>()
        else {
            continue;
        };
        let Some(cg_bounds) = CGRect::from_dict_representation(&bounds_dictionary) else {
            continue;
        };
        let cg_bounds = NativeBounds {
            x: cg_bounds.origin.x as i64,
            y: cg_bounds.origin.y as i64,
            width: cg_bounds.size.width as i64,
            height: cg_bounds.size.height as i64,
        };
        if cg_bounds.width <= 0 || cg_bounds.height <= 0 {
            continue;
        }
        let Ok(application) =
            AxElement::created(unsafe { AXUIElementCreateApplication(process_id) })
        else {
            continue;
        };
        if unsafe { AXUIElementSetMessagingTimeout(application.0, 0.1) } != kAXErrorSuccess {
            continue;
        }
        let Ok(windows) = application.elements("AXWindows", 256) else {
            check_protocol_boundary(cancellation, deadline_at_ms)?;
            continue;
        };
        let mut matches = Vec::new();
        for window in windows {
            check_protocol_boundary(cancellation, deadline_at_ms)?;
            if mac_ax_bounds(&window).is_ok_and(|bounds| bounds == cg_bounds) {
                matches.push(window);
            }
        }
        let mut matches = matches.into_iter();
        let Some(window) = matches.next() else {
            continue;
        };
        if matches.next().is_some() {
            continue;
        }
        surfaces.push((process_id, window_number, window));
    }
    Ok(surfaces)
}

#[cfg(target_os = "macos")]
fn mac_list_surfaces(
    display_geometry_hash: &str,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<Vec<SurfaceDescriptor>, ProtocolError> {
    let mut descriptors = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (process_id, cg_window_number, window) in mac_surface_windows(cancellation, deadline_at_ms)?
    {
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        let Ok(process_generation) = mac_process_generation(process_id) else {
            check_protocol_boundary(cancellation, deadline_at_ms)?;
            continue;
        };
        let Ok(window_id) = mac_window_identity(&window, process_id) else {
            check_protocol_boundary(cancellation, deadline_at_ms)?;
            continue;
        };
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        let Ok(bounds) = mac_ax_bounds(&window) else {
            check_protocol_boundary(cancellation, deadline_at_ms)?;
            continue;
        };
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        if bounds.width <= 0 || bounds.height <= 0 {
            continue;
        }
        let id = hash_serializable(&(
            "macos-ax-surface",
            process_id,
            &process_generation,
            cg_window_number,
            &window_id,
            display_geometry_hash,
        ))?;
        if !seen.insert(id.clone()) {
            continue;
        }
        let descriptor = SurfaceDescriptor {
            protocol_version: PROTOCOL_VERSION,
            surface: SurfaceRef { id: id.clone() },
            backend: "praefectus-macos-ax".to_string(),
            process_id: u32::try_from(process_id)
                .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?,
            process_generation,
            window_id,
            display_geometry_hash: display_geometry_hash.to_string(),
            bounds: Some(Rect {
                x: bounds.x,
                y: bounds.y,
                width: bounds.width,
                height: bounds.height,
            }),
        };
        let persisted = persist_private_observation(
            &id,
            &MacSurfaceRecord {
                protocol_version: PROTOCOL_VERSION,
                descriptor: descriptor.clone(),
                cg_window_number,
            },
        );
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        persisted?;
        descriptors.push(descriptor);
    }
    check_protocol_boundary(cancellation, deadline_at_ms)?;
    Ok(descriptors)
}

#[cfg(target_os = "macos")]
fn mac_surface_window(
    surface: &SurfaceRef,
    display_geometry_hash: &str,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<AxElement, ProtocolError> {
    if !semantic_hash(&surface.id) {
        return Err(ProtocolError::InvalidRequest(
            "invalid surface reference".to_string(),
        ));
    }
    let record: MacSurfaceRecord = load_private_observation(&surface.id)?;
    if record.protocol_version != PROTOCOL_VERSION
        || record.descriptor.protocol_version != PROTOCOL_VERSION
        || record.descriptor.surface != *surface
        || record.descriptor.backend != "praefectus-macos-ax"
        || record.descriptor.display_geometry_hash != display_geometry_hash
    {
        return Err(ProtocolError::StaleTarget(
            "surface provenance does not match".to_string(),
        ));
    }
    let process_id = i32::try_from(record.descriptor.process_id)
        .map_err(|_| ProtocolError::StaleTarget("surface process changed".to_string()))?;
    if mac_process_generation(process_id).ok().as_deref()
        != Some(record.descriptor.process_generation.as_str())
    {
        return Err(ProtocolError::StaleTarget(
            "surface process changed".to_string(),
        ));
    }
    let expected_id = hash_serializable(&(
        "macos-ax-surface",
        process_id,
        &record.descriptor.process_generation,
        record.cg_window_number,
        &record.descriptor.window_id,
        display_geometry_hash,
    ))?;
    if expected_id != surface.id {
        return Err(ProtocolError::StaleTarget(
            "surface provenance does not match".to_string(),
        ));
    }
    let mut matches = mac_surface_windows(cancellation, deadline_at_ms)?
        .into_iter()
        .filter(|(candidate_pid, candidate_number, window)| {
            *candidate_pid == process_id
                && *candidate_number == record.cg_window_number
                && mac_window_identity(window, process_id).ok().as_deref()
                    == Some(record.descriptor.window_id.as_str())
        })
        .map(|(_, _, window)| window);
    let window = matches
        .next()
        .ok_or_else(|| ProtocolError::StaleTarget("surface changed".to_string()))?;
    if matches.next().is_some() {
        return Err(ProtocolError::StaleTarget(
            "surface is ambiguous".to_string(),
        ));
    }
    Ok(window)
}

#[cfg(target_os = "macos")]
fn mac_semantic_snapshot(
    display_geometry_hash: &str,
    selected_window: Option<AxElement>,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(semantic::SemanticObservation, Vec<ElementObservation>), ProtocolError> {
    use accessibility_sys::{
        AXUIElementCreateSystemWide, AXUIElementGetPid, AXUIElementSetMessagingTimeout,
        kAXErrorSuccess,
    };
    use std::collections::VecDeque;

    if cancellation.is_cancelled() {
        return Err(ProtocolError::ObservationCancelled);
    }
    if now_ms() >= deadline_at_ms {
        return Err(ProtocolError::ObservationExpired);
    }
    let system = AxElement::created(unsafe { AXUIElementCreateSystemWide() })
        .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?;
    let window = if let Some(window) = selected_window {
        window
    } else {
        match mac_frontmost_window(cancellation, deadline_at_ms) {
            Ok(window) => window,
            Err(_) => {
                check_protocol_boundary(cancellation, deadline_at_ms)?;
                system
                    .element("AXFocusedApplication")
                    .and_then(|application| application.element("AXFocusedWindow"))
                    .or_else(|_| {
                        mac_native_boundary(cancellation, deadline_at_ms)?;
                        system.element("AXFocusedUIElement").and_then(|element| {
                            element
                                .element("AXWindow")
                                .or_else(|_| element.element("AXTopLevelUIElement"))
                        })
                    })
                    .map_err(|_| {
                        mac_observation_error(
                            cancellation,
                            deadline_at_ms,
                            ProtocolError::TargetNotFound("focused window not found".to_string()),
                        )
                    })?
            }
        }
    };
    let mut process_id = 0;
    window
        .prepare()
        .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?;
    if unsafe { AXUIElementGetPid(window.0, &mut process_id) } != kAXErrorSuccess || process_id <= 0
    {
        return Err(ProtocolError::TargetNotFound(
            "focused process not found".to_string(),
        ));
    }
    let application =
        AxElement::created(unsafe { accessibility_sys::AXUIElementCreateApplication(process_id) })
            .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?;
    if unsafe { AXUIElementSetMessagingTimeout(application.0, 0.1) } != kAXErrorSuccess {
        return Err(ProtocolError::Executor("desktop backend error".to_string()));
    }
    let process_generation = mac_process_generation(process_id)
        .map_err(|_| ProtocolError::StaleTarget("focused process changed".to_string()))?;
    let window_id = mac_window_identity(&window, process_id)
        .map_err(|_| ProtocolError::StaleTarget("focused window changed".to_string()))?;
    let generation = next_semantic_generation();
    let observed_at_ms = now_ms();
    let observation_id = hash_serializable(&(
        "macos-ax",
        process_id,
        &process_generation,
        &window_id,
        generation,
        observed_at_ms,
        display_geometry_hash,
    ))?;
    let provenance = semantic::SemanticProvenance {
        backend: semantic::SemanticBackend::Accessibility,
        backend_name: "praefectus-macos-ax".to_string(),
        process_id: u32::try_from(process_id)
            .map_err(|_| ProtocolError::StaleTarget("focused process changed".to_string()))?,
        process_generation,
        window_id,
        document_id: None,
        display_geometry_hash: display_geometry_hash.to_string(),
    };
    let mut queue = VecDeque::from([(window, Vec::<usize>::new(), None::<String>)]);
    let mut elements = Vec::new();
    let mut pending = Vec::new();
    let mut seen_elements = BTreeMap::<usize, Vec<AxElement>>::new();
    let mut visited = 0usize;
    let mut truncated = false;
    let traversal_deadline_at_ms = deadline_at_ms.min(now_ms().saturating_add(5_000));
    while let Some((element, path, parent_id)) = queue.pop_front() {
        if cancellation.is_cancelled() {
            return Err(ProtocolError::ObservationCancelled);
        }
        if now_ms() >= deadline_at_ms {
            return Err(ProtocolError::ObservationExpired);
        }
        if now_ms() >= traversal_deadline_at_ms {
            truncated = true;
            break;
        }
        let identity_hash = element.identity_hash();
        if seen_elements
            .get(&identity_hash)
            .is_some_and(|seen| seen.iter().any(|seen| seen.identity_eq(&element)))
        {
            continue;
        }
        seen_elements.entry(identity_hash).or_default().push(
            element
                .retained()
                .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?,
        );
        visited += 1;
        if visited > MAX_MAC_SEMANTIC_ELEMENTS.saturating_mul(4) {
            truncated = true;
            break;
        }
        let children = match element.has_attribute("AXChildren") {
            Ok(false) => Vec::new(),
            Ok(true) => match element.elements(
                "AXChildren",
                MAX_MAC_AX_COLLECTION_ITEMS.saturating_sub(visited),
            ) {
                Ok(children) => children,
                Err(_) => {
                    truncated = true;
                    Vec::new()
                }
            },
            Err(_) => {
                truncated = true;
                Vec::new()
            }
        };
        let mut child_parent = parent_id.clone();
        if elements.len() < MAX_MAC_SEMANTIC_ELEMENTS {
            if let Ok(first) = mac_native_element(&element, cancellation, traversal_deadline_at_ms)
            {
                let fingerprint = ElementFingerprint::from(&first);
                if let Some(bounds) = fingerprint
                    .bounds
                    .filter(|bounds| bounds.width > 0 && bounds.height > 0)
                {
                    let point = NativePoint {
                        x: bounds.x.saturating_add(bounds.width / 2),
                        y: bounds.y.saturating_add(bounds.height / 2),
                    };
                    let backend_id = hash_serializable(&(&path, &first.id))?;
                    let backend_id_hash = hash_bytes(first.id.as_bytes());
                    let element_id = semantic::opaque_element_id(&observation_id, &backend_id)
                        .map_err(semantic_protocol_error)?;
                    let fingerprint_hash = element_fingerprint_hash(&fingerprint)?;
                    let second =
                        mac_native_element(&element, cancellation, traversal_deadline_at_ms).ok();
                    let stable = second.as_ref().is_some_and(|second| {
                        ElementFingerprint::from(second) == fingerprint
                            && validate_matching_live_element(second, &first).is_ok()
                    });
                    let visible = first.state.get("visible").and_then(Value::as_bool) == Some(true)
                        && first.state.get("hidden").and_then(Value::as_bool) != Some(true);
                    let invokable = element
                        .actions()
                        .is_ok_and(|actions| actions.iter().any(|action| action == "AXPress"));
                    let editable = element.is_settable("AXValue");
                    let receives_events = visible
                        && stable
                        && invokable
                        && mac_element_receives_events(
                            &element,
                            &point,
                            cancellation,
                            deadline_at_ms,
                        )?;
                    let name =
                        bounded_semantic_name(first.label.as_deref().or(first.title.as_deref()));
                    let tag =
                        semantic::semantic_tag(elements.len()).map_err(semantic_protocol_error)?;
                    let actionability = semantic::Actionability {
                        visible,
                        enabled: first.enabled == Some(true),
                        unambiguous: true,
                        stable,
                        receives_events,
                        invokable,
                        editable,
                    };
                    elements.push(semantic::SemanticElement {
                        tag,
                        element_id: element_id.clone(),
                        parent_id: parent_id.clone(),
                        fingerprint_hash: fingerprint_hash.clone(),
                        role: bounded_semantic_role(&first.role),
                        name,
                        bounds: Some(bounds),
                        actionability,
                    });
                    pending.push((
                        element_id.clone(),
                        fingerprint_hash,
                        point,
                        path.clone(),
                        backend_id_hash,
                    ));
                    child_parent = Some(element_id);
                }
            }
        } else {
            truncated = true;
        }
        for (index, child) in children.into_iter().enumerate() {
            let mut child_path = path.clone();
            child_path.push(index);
            queue.push_back((child, child_path, child_parent.clone()));
        }
    }
    check_protocol_boundary(cancellation, deadline_at_ms)?;
    let mut overlap_counts = BTreeMap::new();
    for (_, fingerprint_hash, point, _, _) in &pending {
        *overlap_counts
            .entry((fingerprint_hash.as_str(), point.x, point.y))
            .or_insert(0_usize) += 1;
    }
    for (index, (_, fingerprint_hash, point, _, _)) in pending.iter().enumerate() {
        if overlap_counts
            .get(&(fingerprint_hash.as_str(), point.x, point.y))
            .copied()
            .unwrap_or_default()
            > 1
        {
            elements[index].actionability.unambiguous = false;
            elements[index].actionability.receives_events = false;
        }
    }
    let observation = semantic::SemanticObservation {
        protocol_version: PROTOCOL_VERSION,
        observation_id,
        generation,
        provenance,
        observed_at_ms,
        expires_at_ms: observed_at_ms.saturating_add(MAX_COORDINATE_OBSERVATION_AGE_MS),
        truncated,
        elements,
    };
    observation
        .validate(now_ms())
        .map_err(semantic_protocol_error)?;
    let mut records = Vec::with_capacity(pending.len());
    for (index, (element_id, element_fingerprint_hash, _, path, backend_id_hash)) in
        pending.into_iter().enumerate()
    {
        let target = observation
            .target(&observation.elements[index].tag)
            .map_err(semantic_protocol_error)?;
        if target.element_id != element_id {
            return Err(ProtocolError::StaleTarget(
                "semantic observation changed".to_string(),
            ));
        }
        records.push(ElementObservation {
            protocol_version: PROTOCOL_VERSION,
            target,
            actionability: observation.elements[index].actionability,
            process_id: observation.provenance.process_id,
            process_generation: observation.provenance.process_generation.clone(),
            window_id: observation.provenance.window_id.clone(),
            path,
            backend_id_hash,
            display_geometry_hash: display_geometry_hash.to_string(),
            element_fingerprint_hash,
            observed_at_ms,
        });
    }
    Ok((observation, records))
}

#[cfg(target_os = "macos")]
fn bounded_semantic_name(value: Option<&str>) -> Option<String> {
    value.and_then(|value| bounded_semantic_text(value, 1_024))
}

#[cfg(target_os = "macos")]
fn bounded_semantic_role(value: &str) -> String {
    bounded_semantic_text(value, 128).unwrap_or_else(|| "unknown".to_string())
}

#[cfg(target_os = "macos")]
fn bounded_semantic_text(value: &str, maximum: usize) -> Option<String> {
    let value: String = value
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    let mut end = value.len().min(maximum);
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let value = value[..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn native_element_set_value(
    expected: &NativeElement,
    value: &str,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(), DispatchError> {
    #[cfg(target_os = "macos")]
    {
        use accessibility_sys::{AXUIElementSetAttributeValue, kAXErrorSuccess};
        use core_foundation::base::TCFType;
        use core_foundation::string::CFString;

        let attribute = CFString::new("AXValue");
        let value = CFString::new(value);
        let bounds = expected
            .bounds
            .as_ref()
            .ok_or_else(|| no_effect("semantic target has no bounds"))?;
        let point = NativePoint {
            x: bounds.x.saturating_add(bounds.width / 2),
            y: bounds.y.saturating_add(bounds.height / 2),
        };
        let expected_hash = element_fingerprint_hash(&ElementFingerprint::from(expected))
            .map_err(|_| no_effect("semantic target is unavailable"))?;
        let resolution_deadline_at_ms =
            deadline_at_ms.min(now_ms().saturating_add(MAX_MAC_AX_RESOLUTION_MS));
        let (element, current) = mac_ax_element_matching_hash(
            &point,
            &expected_hash,
            cancellation,
            resolution_deadline_at_ms,
        )
        .map_err(|_| {
            if cancellation.is_cancelled() {
                interrupted(EffectKnowledge::CancelledBeforeEffect)
            } else if now_ms() >= deadline_at_ms {
                interrupted(EffectKnowledge::ExpiredBeforeEffect)
            } else {
                no_effect("semantic target is unavailable")
            }
        })?;
        validate_matching_live_element(&current, expected)
            .map_err(|_| no_effect("semantic target changed"))?;
        if !element.is_settable("AXValue") {
            return Err(no_effect("semantic value is not settable"));
        }
        element
            .prepare()
            .map_err(|_| no_effect("semantic target is unavailable"))?;
        if cancellation.is_cancelled() {
            return Err(interrupted(EffectKnowledge::CancelledBeforeEffect));
        }
        if now_ms() >= deadline_at_ms {
            return Err(interrupted(EffectKnowledge::ExpiredBeforeEffect));
        }
        if unsafe {
            AXUIElementSetAttributeValue(
                element.0,
                attribute.as_concrete_TypeRef(),
                value.as_CFTypeRef(),
            )
        } == kAXErrorSuccess
        {
            Ok(())
        } else {
            Err(ambiguous(
                "accessibility action failed after dispatch began",
            ))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (expected, value, cancellation, deadline_at_ms);
        Err(unsupported("accessibility actions are unavailable"))
    }
}

#[derive(Clone, Debug)]
pub struct DispatchReceipt {
    pub backend: String,
    pub fallback_chain: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectKnowledge {
    NoEffect,
    Unknown,
    CancelledBeforeEffect,
    ExpiredBeforeEffect,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct DispatchError {
    pub message: String,
    pub effect: EffectKnowledge,
    pub code: FailureCode,
}

pub trait Executor: Send + Sync {
    fn capabilities(&self) -> Result<Capabilities, ProtocolError>;
    fn session_isolation(&self) -> SessionIsolation {
        SessionIsolation::SharedDesktop
    }
    fn shared_desktop_context_hash(&self) -> Result<String, ProtocolError> {
        Err(ProtocolError::Executor(
            "shared desktop context is unavailable".to_string(),
        ))
    }
    fn shared_desktop_context_hash_with_boundary(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<String, ProtocolError> {
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        let result = self.shared_desktop_context_hash();
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        result
    }
    fn observe(&self, target: &TargetRef) -> Result<Observation, ProtocolError>;
    fn observe_with_boundary(
        &self,
        target: &TargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Observation, ProtocolError> {
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        let result = self.observe(target);
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        result
    }
    fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, ProtocolError>;
    fn resolve_with_boundary(
        &self,
        target: &TargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<ResolvedTarget, ProtocolError> {
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        let result = self.resolve(target);
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        result
    }
    fn dispatch(
        &self,
        action: &Action,
        target: &ResolvedTarget,
        verification: &VerificationPolicy,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError>;
}

pub trait AuthorityVerifier: Send + Sync {
    fn verify(
        &self,
        request: &ActionRequest,
        action_hash: &str,
    ) -> Result<VerifiedAuthority, ProtocolError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedAuthority {
    pub expires_at_ms: i64,
}

pub struct Ed25519AuthorityVerifier {
    issuers: BTreeMap<(String, String), (String, VerifyingKey)>,
}

impl Ed25519AuthorityVerifier {
    pub fn new(
        keys: impl IntoIterator<Item = (String, String, String, VerifyingKey)>,
    ) -> Result<Self, ProtocolError> {
        let mut issuers = BTreeMap::new();
        for (issuer, key_id, policy_generation, key) in keys {
            if !valid_identifier(&issuer)
                || !valid_identifier(&key_id)
                || !valid_identifier(&policy_generation)
                || issuers
                    .insert((issuer, key_id), (policy_generation, key))
                    .is_some()
            {
                return Err(ProtocolError::InvalidRequest(
                    "invalid authority keyring".to_string(),
                ));
            }
        }
        Ok(Self { issuers })
    }
}

impl AuthorityVerifier for Ed25519AuthorityVerifier {
    fn verify(
        &self,
        request: &ActionRequest,
        action_hash: &str,
    ) -> Result<VerifiedAuthority, ProtocolError> {
        let grant = &request.authority.grant;
        if grant.protocol_version != PROTOCOL_VERSION
            || grant.operation_id != request.operation_id
            || grant.subject != request.subject
            || grant.session_id != request.session_id
            || grant.risk != request.safety
            || grant.action_hash != action_hash
            || grant.expires_at_ms <= 0
            || !valid_identifier(&grant.issuer)
            || !valid_identifier(&grant.key_id)
            || !valid_identifier(&grant.policy_generation)
            || !is_hash(&grant.action_hash)
        {
            return Err(ProtocolError::AuthorityDenied);
        }
        let Some((policy_generation, key)) = self
            .issuers
            .get(&(grant.issuer.clone(), grant.key_id.clone()))
        else {
            return Err(ProtocolError::AuthorityDenied);
        };
        if policy_generation != &grant.policy_generation {
            return Err(ProtocolError::AuthorityDenied);
        }
        let signature = hex::decode(&request.authority.signature)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .map(|bytes| Signature::from_bytes(&bytes))
            .ok_or(ProtocolError::AuthorityDenied)?;
        key.verify_strict(&canonical_authority_bytes(grant)?, &signature)
            .map_err(|_| ProtocolError::AuthorityDenied)?;
        Ok(VerifiedAuthority {
            expires_at_ms: grant.expires_at_ms,
        })
    }
}

pub struct DenyAuthority;

impl AuthorityVerifier for DenyAuthority {
    fn verify(
        &self,
        _request: &ActionRequest,
        _action_hash: &str,
    ) -> Result<VerifiedAuthority, ProtocolError> {
        Err(ProtocolError::AuthorityDenied)
    }
}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

fn check_protocol_boundary(
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

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("operation conflict")]
    Conflict,
    #[error("authority denied")]
    AuthorityDenied,
    #[error("stale target: {0}")]
    StaleTarget(String),
    #[error("target not found: {0}")]
    TargetNotFound(String),
    #[error("observation cancelled")]
    ObservationCancelled,
    #[error("observation expired")]
    ObservationExpired,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("executor error: {0}")]
    Executor(String),
}

pub struct Engine<E> {
    executor: E,
    ledger: OperationLedger,
    authority: Arc<dyn AuthorityVerifier>,
}

impl<E: Executor> Engine<E> {
    pub fn new(
        executor: E,
        ledger_path: impl Into<PathBuf>,
        authority: impl AuthorityVerifier + 'static,
    ) -> Self {
        Self {
            executor,
            ledger: OperationLedger::new(ledger_path.into()),
            authority: Arc::new(authority),
        }
    }

    pub fn execute(
        &self,
        request: &ActionRequest,
        cancellation: &CancellationToken,
    ) -> Result<ExecuteReport, ProtocolError> {
        validate_request(request)?;
        let action_hash = normalized_action_hash(request)?;
        let authority = self.authority.verify(request, &action_hash)?;
        let effect_deadline_at_ms = request.deadline_at_ms.min(authority.expires_at_ms);
        let session_isolation = self.executor.session_isolation();
        let _operation_guard = self.ledger.execution_lock()?;
        self.ledger.repair_tail()?;
        match self
            .ledger
            .claim(request, &action_hash, session_isolation)?
        {
            ClaimResult::Replay(mut acknowledgement) => {
                acknowledgement.replayed = true;
                return Ok(ExecuteReport {
                    acknowledgements: vec![*acknowledgement],
                });
            }
            ClaimResult::RecoveredUnknown {
                action_name,
                delivery_route,
                session_isolation,
                interaction_mode,
            } => {
                let mut receipt = empty_receipt(
                    request,
                    &action_hash,
                    Effect::Unknown,
                    session_isolation.unwrap_or(SessionIsolation::Unknown),
                );
                receipt.action_name = action_name.unwrap_or_else(|| "unknown".to_string());
                receipt.delivery_route = delivery_route.unwrap_or(DeliveryRoute::Unknown);
                receipt.interaction_mode = interaction_mode.unwrap_or(InteractionMode::Unknown);
                let terminal = Terminal::OutcomeUnknown {
                    receipt,
                    message: "a durable claim existed without a terminal receipt".to_string(),
                };
                let acknowledgement = terminal_ack(request, &action_hash, terminal, false);
                self.ledger.finish(&acknowledgement)?;
                return Ok(ExecuteReport {
                    acknowledgements: vec![acknowledgement],
                });
            }
            ClaimResult::New => {}
        }

        let accepted = ack(request, &action_hash, 0, AckState::Accepted, false);
        let _ = self.ledger.trajectory(&accepted);
        if cancellation.is_cancelled() {
            return self.finish_early(request, &action_hash, Terminal::CancelledBeforeEffect);
        }
        if now_ms() >= effect_deadline_at_ms {
            return self.finish_early(request, &action_hash, Terminal::ExpiredBeforeEffect);
        }
        if session_isolation == SessionIsolation::Unknown {
            return self.finish_early(
                request,
                &action_hash,
                Terminal::Rejected {
                    code: FailureCode::Unsupported,
                    message: "runtime session isolation is unknown".to_string(),
                },
            );
        }
        let capabilities = self.executor.capabilities();
        if cancellation.is_cancelled() {
            return self.finish_early(request, &action_hash, Terminal::CancelledBeforeEffect);
        }
        if now_ms() >= effect_deadline_at_ms {
            return self.finish_early(request, &action_hash, Terminal::ExpiredBeforeEffect);
        }
        let capabilities = match capabilities {
            Ok(capabilities) => capabilities,
            Err(error) => {
                return self.finish_early(request, &action_hash, protocol_failure(error));
            }
        };
        let action_capability = strict_action_capability(&capabilities, &request.action);
        let Some(action_capability) = action_capability else {
            return self.finish_early(
                request,
                &action_hash,
                Terminal::Rejected {
                    code: FailureCode::Unsupported,
                    message: "runtime action capability facts are missing or inconsistent"
                        .to_string(),
                },
            );
        };
        let delivery_route = action_capability.delivery_route;
        if request.interaction_mode == InteractionMode::BackgroundOnly
            && !background_capability_is_authorized(action_capability, session_isolation)
        {
            return self.finish_early(
                request,
                &action_hash,
                Terminal::Rejected {
                    code: FailureCode::Unsupported,
                    message: "background action is unavailable for this delivery route and session isolation"
                        .to_string(),
                },
            );
        }

        let before = match self.executor.observe_with_boundary(
            &request.target,
            cancellation,
            effect_deadline_at_ms,
        ) {
            Ok(observation) => observation,
            Err(error) => {
                let terminal = protocol_failure(error);
                return self.finish_early(request, &action_hash, terminal);
            }
        };
        let resolved = match self.executor.resolve_with_boundary(
            &request.target,
            cancellation,
            effect_deadline_at_ms,
        ) {
            Ok(target) => target,
            Err(error) => {
                let terminal = protocol_failure(error);
                return self.finish_early(request, &action_hash, terminal);
            }
        };
        let executing = ack(request, &action_hash, 1, AckState::Executing, false);
        let _ = self.ledger.trajectory(&executing);
        if cancellation.is_cancelled() {
            return self.finish_early(request, &action_hash, Terminal::CancelledBeforeEffect);
        }
        if now_ms() >= effect_deadline_at_ms {
            return self.finish_early(request, &action_hash, Terminal::ExpiredBeforeEffect);
        }

        let context_before = if request.interaction_mode == InteractionMode::BackgroundOnly
            && session_isolation == SessionIsolation::SharedDesktop
        {
            match self
                .executor
                .shared_desktop_context_hash_with_boundary(cancellation, effect_deadline_at_ms)
            {
                Ok(context) => Some(context),
                Err(ProtocolError::ObservationCancelled) => {
                    return self.finish_early(
                        request,
                        &action_hash,
                        Terminal::CancelledBeforeEffect,
                    );
                }
                Err(ProtocolError::ObservationExpired) => {
                    return self.finish_early(request, &action_hash, Terminal::ExpiredBeforeEffect);
                }
                Err(_) => {
                    return self.finish_early(
                        request,
                        &action_hash,
                        Terminal::Rejected {
                            code: FailureCode::Unsupported,
                            message: "shared desktop context cannot be guarded".to_string(),
                        },
                    );
                }
            }
        } else {
            None
        };

        let started_at_ms = now_ms();
        let dispatched = self.executor.dispatch(
            &request.action,
            &resolved,
            &request.verification,
            cancellation,
            effect_deadline_at_ms,
        );
        let (terminal, effect_may_have_occurred) = match dispatched {
            Ok(dispatch) if cancellation.is_cancelled() || now_ms() >= effect_deadline_at_ms => {
                let mut receipt =
                    empty_receipt(request, &action_hash, Effect::Unknown, session_isolation);
                receipt.started_at_ms = started_at_ms;
                receipt.finished_at_ms = now_ms();
                receipt.before = Some(before.evidence);
                receipt.backend = dispatch.backend;
                receipt.fallback_chain = dispatch.fallback_chain;
                receipt.context_preservation = self.context_preservation(
                    request.interaction_mode,
                    session_isolation,
                    context_before.as_deref(),
                    cancellation,
                    effect_deadline_at_ms,
                );
                (
                    Terminal::OutcomeUnknown {
                        receipt,
                        message: "action completed at the cancellation or deadline boundary"
                            .to_string(),
                    },
                    true,
                )
            }
            Ok(dispatch) => {
                let context_preservation = self.context_preservation(
                    request.interaction_mode,
                    session_isolation,
                    context_before.as_deref(),
                    cancellation,
                    effect_deadline_at_ms,
                );
                let after = self.executor.observe_with_boundary(
                    &request.target,
                    cancellation,
                    effect_deadline_at_ms,
                );
                let expected_target_fingerprint_hash = match &request.target {
                    TargetRef::Element { target } => Some(target.fingerprint_hash.clone()),
                    _ => None,
                };
                let (mut effect, mut warnings) = verify(
                    &request.verification,
                    &before,
                    after.as_ref().ok(),
                    expected_target_fingerprint_hash.as_deref(),
                );
                let post_dispatch_boundary_unknown = cancellation.is_cancelled()
                    || now_ms() >= effect_deadline_at_ms
                    || matches!(
                        &after,
                        Err(ProtocolError::ObservationCancelled | ProtocolError::ObservationExpired)
                    );
                if post_dispatch_boundary_unknown {
                    effect = Effect::Unknown;
                    warnings.push(
                        "action completed at the cancellation or deadline boundary".to_string(),
                    );
                }
                if matches!(
                    context_preservation,
                    ContextPreservation::Changed | ContextPreservation::Unavailable
                ) {
                    effect = Effect::Unknown;
                    warnings.push("shared desktop context preservation is unknown".to_string());
                }
                let receipt = Receipt {
                    protocol_version: PROTOCOL_VERSION,
                    action_name: request.action.name().to_string(),
                    action_hash: action_hash.clone(),
                    started_at_ms,
                    finished_at_ms: now_ms(),
                    backend: dispatch.backend,
                    fallback_chain: dispatch.fallback_chain,
                    delivery_route,
                    session_isolation,
                    interaction_mode: request.interaction_mode,
                    context_preservation,
                    effect,
                    before: Some(before.evidence),
                    after: after.ok().map(|value| value.evidence),
                    warnings,
                };
                if !matches!(receipt.effect, Effect::Unknown)
                    && (matches!(request.verification, VerificationPolicy::None)
                        || matches!(receipt.effect, Effect::Verified))
                {
                    (Terminal::Succeeded { receipt }, true)
                } else {
                    let message = if post_dispatch_boundary_unknown {
                        "action completed at the cancellation or deadline boundary".to_string()
                    } else if matches!(
                        receipt.context_preservation,
                        ContextPreservation::Changed | ContextPreservation::Unavailable
                    ) {
                        "action result or shared desktop context preservation could not be proven"
                            .to_string()
                    } else {
                        "action dispatched but requested verification failed".to_string()
                    };
                    (Terminal::OutcomeUnknown { receipt, message }, true)
                }
            }
            Err(error) if error.effect == EffectKnowledge::Unknown => {
                let mut receipt =
                    empty_receipt(request, &action_hash, Effect::Unknown, session_isolation);
                receipt.started_at_ms = started_at_ms;
                receipt.finished_at_ms = now_ms();
                receipt.before = Some(before.evidence);
                receipt.context_preservation = self.context_preservation(
                    request.interaction_mode,
                    session_isolation,
                    context_before.as_deref(),
                    cancellation,
                    effect_deadline_at_ms,
                );
                (
                    Terminal::OutcomeUnknown {
                        receipt,
                        message: dispatch_message(&error),
                    },
                    true,
                )
            }
            Err(error) if error.effect == EffectKnowledge::CancelledBeforeEffect => {
                (Terminal::CancelledBeforeEffect, false)
            }
            Err(error) if error.effect == EffectKnowledge::ExpiredBeforeEffect => {
                (Terminal::ExpiredBeforeEffect, false)
            }
            Err(_) if cancellation.is_cancelled() => (Terminal::CancelledBeforeEffect, false),
            Err(_) if now_ms() >= effect_deadline_at_ms => (Terminal::ExpiredBeforeEffect, false),
            Err(error) => (
                Terminal::Rejected {
                    code: error.code,
                    message: dispatch_message(&error),
                },
                false,
            ),
        };
        let mut terminal_ack = terminal_ack(request, &action_hash, terminal, false);
        if effect_may_have_occurred {
            terminal_ack = self.ledger.finish_after_effect(terminal_ack);
        } else {
            self.ledger.finish(&terminal_ack)?;
        }
        Ok(ExecuteReport {
            acknowledgements: vec![accepted, executing, terminal_ack],
        })
    }

    fn finish_early(
        &self,
        request: &ActionRequest,
        action_hash: &str,
        terminal: Terminal,
    ) -> Result<ExecuteReport, ProtocolError> {
        let accepted = ack(request, action_hash, 0, AckState::Accepted, false);
        let terminal_ack = terminal_ack(request, action_hash, terminal, false);
        self.ledger.finish(&terminal_ack)?;
        Ok(ExecuteReport {
            acknowledgements: vec![accepted, terminal_ack],
        })
    }

    pub fn status(&self, operation_id: &str) -> Result<Option<ActionAck>, ProtocolError> {
        if !valid_identifier(operation_id) {
            return Err(ProtocolError::InvalidRequest(
                "invalid operation_id".to_string(),
            ));
        }
        self.ledger.status(operation_id)
    }

    pub fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
        self.executor.capabilities()
    }

    fn context_preservation(
        &self,
        interaction_mode: InteractionMode,
        session_isolation: SessionIsolation,
        before: Option<&str>,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> ContextPreservation {
        if interaction_mode != InteractionMode::BackgroundOnly {
            return ContextPreservation::NotApplicable;
        }
        if session_isolation == SessionIsolation::HostIsolated {
            return ContextPreservation::HostIsolated;
        }
        let Some(before) = before else {
            return ContextPreservation::Unavailable;
        };
        match self
            .executor
            .shared_desktop_context_hash_with_boundary(cancellation, deadline_at_ms)
        {
            Ok(after) if after == before => ContextPreservation::UnchangedAtBoundaries,
            Ok(_) => ContextPreservation::Changed,
            Err(_) => ContextPreservation::Unavailable,
        }
    }
}

fn strict_action_capability<'a>(
    capabilities: &'a Capabilities,
    action: &Action,
) -> Option<&'a ActionCapability> {
    let mut supported = std::collections::BTreeSet::new();
    if capabilities
        .supported_actions
        .iter()
        .any(|name| !supported.insert(name.as_str()))
    {
        return None;
    }
    let mut facts = BTreeMap::new();
    for capability in &capabilities.action_capabilities {
        let route_is_valid = match capability.action.as_str() {
            "invoke" | "set_value" => capability.delivery_route == DeliveryRoute::TargetAddressed,
            "click" | "type_text" | "press" | "paste" | "hotkey" | "move" => {
                capability.delivery_route == DeliveryRoute::Pointer
            }
            "scroll" => matches!(
                capability.delivery_route,
                DeliveryRoute::Pointer | DeliveryRoute::TargetAddressed
            ),
            _ => false,
        };
        if !route_is_valid
            || facts
                .insert(capability.action.as_str(), capability)
                .is_some()
        {
            return None;
        }
    }
    if supported.len() != facts.len() || supported.iter().any(|name| !facts.contains_key(*name)) {
        return None;
    }
    supported
        .contains(action.name())
        .then(|| facts.get(action.name()).copied())
        .flatten()
}

fn background_capability_is_authorized(
    capability: &ActionCapability,
    session_isolation: SessionIsolation,
) -> bool {
    match session_isolation {
        SessionIsolation::SharedDesktop => {
            capability.delivery_route == DeliveryRoute::TargetAddressed
                && capability.background_support == BackgroundSupport::Guarded
        }
        SessionIsolation::HostIsolated => matches!(
            capability.background_support,
            BackgroundSupport::Guarded | BackgroundSupport::HostIsolatedOnly
        ),
        SessionIsolation::Unknown => false,
    }
}

pub struct NativeExecutor {
    runtime: NativeRuntime,
    session_isolation: SessionIsolation,
    #[cfg(target_os = "linux")]
    linux_atspi: std::sync::Mutex<Option<linux_atspi::LinuxAtspiBackend>>,
}

impl Default for NativeExecutor {
    fn default() -> Self {
        Self {
            runtime: NativeRuntime::new(),
            session_isolation: SessionIsolation::SharedDesktop,
            #[cfg(target_os = "linux")]
            linux_atspi: std::sync::Mutex::new(None),
        }
    }
}

impl NativeExecutor {
    pub fn with_session_isolation(session_isolation: SessionIsolation) -> Self {
        Self {
            session_isolation,
            ..Self::default()
        }
    }

    pub fn list_surfaces(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Vec<SurfaceDescriptor>, ProtocolError> {
        if cancellation.is_cancelled() {
            return Err(ProtocolError::ObservationCancelled);
        }
        if now_ms() >= deadline_at_ms {
            return Err(ProtocolError::ObservationExpired);
        }
        #[cfg(target_os = "macos")]
        {
            let capabilities = self.capabilities()?;
            if !capabilities
                .permissions
                .get("accessibility")
                .copied()
                .unwrap_or(false)
            {
                return Err(ProtocolError::Executor("desktop backend error".to_string()));
            }
            return mac_list_surfaces(
                &capabilities.display_geometry_hash,
                cancellation,
                deadline_at_ms,
            );
        }
        #[cfg(target_os = "linux")]
        {
            let mut backend = self
                .linux_atspi
                .lock()
                .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?;
            if backend.is_none() {
                *backend = Some(linux_atspi::LinuxAtspiBackend::connect()?);
            }
            return backend
                .as_ref()
                .ok_or_else(|| ProtocolError::Executor("desktop backend error".to_string()))?
                .list_surfaces(cancellation, deadline_at_ms);
        }
        #[cfg(target_os = "windows")]
        {
            return windows_uia::list_surfaces(cancellation, deadline_at_ms);
        }
        #[allow(unreachable_code)]
        Err(ProtocolError::Executor(
            "surface enumeration is unavailable".to_string(),
        ))
    }

    pub fn observe_surface(
        &self,
        surface: &SurfaceRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<semantic::SemanticObservation, ProtocolError> {
        if !semantic_hash(&surface.id) {
            return Err(ProtocolError::InvalidRequest(
                "invalid surface reference".to_string(),
            ));
        }
        if cancellation.is_cancelled() {
            return Err(ProtocolError::ObservationCancelled);
        }
        if now_ms() >= deadline_at_ms {
            return Err(ProtocolError::ObservationExpired);
        }
        #[cfg(target_os = "macos")]
        {
            let capabilities = self.capabilities()?;
            let window = mac_surface_window(
                surface,
                &capabilities.display_geometry_hash,
                cancellation,
                deadline_at_ms,
            )?;
            let (observation, records) = mac_semantic_snapshot(
                &capabilities.display_geometry_hash,
                Some(window),
                cancellation,
                deadline_at_ms,
            )?;
            persist_element_observations(&observation.observation_id, &records)?;
            return Ok(observation);
        }
        #[cfg(target_os = "linux")]
        {
            let mut backend = self
                .linux_atspi
                .lock()
                .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?;
            if backend.is_none() {
                *backend = Some(linux_atspi::LinuxAtspiBackend::connect()?);
            }
            return backend
                .as_ref()
                .ok_or_else(|| ProtocolError::Executor("desktop backend error".to_string()))?
                .observe_surface(surface, cancellation, deadline_at_ms);
        }
        #[cfg(target_os = "windows")]
        {
            return windows_uia::snapshot_surface(surface, cancellation, deadline_at_ms);
        }
        #[allow(unreachable_code)]
        Err(ProtocolError::Executor(
            "surface observation is unavailable".to_string(),
        ))
    }

    fn dispatch_semantic(
        &self,
        action: &Action,
        target: &semantic::SemanticTargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        #[cfg(target_os = "macos")]
        {
            use accessibility_sys::{
                AXUIElementPerformAction, AXUIElementSetAttributeValue, kAXErrorSuccess,
            };
            use core_foundation::base::TCFType;
            use core_foundation::string::CFString;

            Self::check_before_effect(cancellation, deadline_at_ms)?;
            let (element, native, actionability) = self
                .resolve_recorded_element(target, cancellation, deadline_at_ms)
                .map_err(|error| match error {
                    ProtocolError::ObservationCancelled => {
                        interrupted(EffectKnowledge::CancelledBeforeEffect)
                    }
                    ProtocolError::ObservationExpired => {
                        interrupted(EffectKnowledge::ExpiredBeforeEffect)
                    }
                    _ => no_effect("semantic target changed"),
                })?;
            if !mac_actionability_allows(action, &actionability) {
                return Err(no_effect("semantic target is not actionable"));
            }
            let live_actionability =
                mac_live_actionability(&element, &native, cancellation, deadline_at_ms).map_err(
                    |error| match error {
                        ProtocolError::ObservationCancelled => {
                            interrupted(EffectKnowledge::CancelledBeforeEffect)
                        }
                        ProtocolError::ObservationExpired => {
                            interrupted(EffectKnowledge::ExpiredBeforeEffect)
                        }
                        _ => no_effect("semantic target actionability changed"),
                    },
                )?;
            if !mac_actionability_matches_observation(action, &actionability, &live_actionability) {
                return Err(no_effect("semantic target actionability changed"));
            }
            match action {
                Action::Invoke => {
                    Self::check_before_effect(cancellation, deadline_at_ms)?;
                    element
                        .prepare()
                        .map_err(|_| no_effect("semantic target is unavailable"))?;
                    if !element
                        .actions()
                        .is_ok_and(|actions| actions.iter().any(|action| action == "AXPress"))
                    {
                        return Err(no_effect("semantic target is not invokable"));
                    }
                    Self::check_before_effect(cancellation, deadline_at_ms)?;
                    let action = CFString::new("AXPress");
                    if unsafe { AXUIElementPerformAction(element.0, action.as_concrete_TypeRef()) }
                        != kAXErrorSuccess
                    {
                        return Err(ambiguous("accessibility action outcome is unknown"));
                    }
                }
                Action::SetValue { value } => {
                    Self::check_before_effect(cancellation, deadline_at_ms)?;
                    element
                        .prepare()
                        .map_err(|_| no_effect("semantic target is unavailable"))?;
                    if !element.is_settable("AXValue") {
                        return Err(no_effect("semantic target is not editable"));
                    }
                    Self::check_before_effect(cancellation, deadline_at_ms)?;
                    let attribute = CFString::new("AXValue");
                    let value = CFString::new(value);
                    if unsafe {
                        AXUIElementSetAttributeValue(
                            element.0,
                            attribute.as_concrete_TypeRef(),
                            value.as_CFTypeRef(),
                        )
                    } != kAXErrorSuccess
                    {
                        return Err(ambiguous("accessibility action outcome is unknown"));
                    }
                }
                _ => return Err(unsupported("semantic action is unavailable")),
            }
            Self::check_after_effect(cancellation, deadline_at_ms)?;
            return Ok(DispatchReceipt {
                backend: "praefectus-macos-ax".to_string(),
                fallback_chain: Vec::new(),
            });
        }
        #[cfg(target_os = "linux")]
        {
            let mut backend = self
                .linux_atspi
                .lock()
                .map_err(|_| unsupported("accessibility backend is unavailable"))?;
            if backend.is_none() {
                *backend = Some(
                    linux_atspi::LinuxAtspiBackend::connect()
                        .map_err(|_| unsupported("accessibility backend is unavailable"))?,
                );
            }
            let backend = backend
                .as_ref()
                .ok_or_else(|| unsupported("accessibility backend is unavailable"))?;
            return match action {
                Action::Invoke => backend.semantic_invoke(target, cancellation, deadline_at_ms),
                Action::SetValue { value } => {
                    backend.semantic_set_value(target, value, cancellation, deadline_at_ms)
                }
                _ => Err(unsupported("semantic action is unavailable")),
            };
        }
        #[cfg(target_os = "windows")]
        {
            return match action {
                Action::Invoke => windows_uia::invoke(target, cancellation, deadline_at_ms),
                Action::SetValue { value } => {
                    windows_uia::set_value(target, value, cancellation, deadline_at_ms)
                }
                Action::Scroll {
                    direction,
                    amount: 1,
                } => windows_uia::scroll(target, *direction, cancellation, deadline_at_ms),
                _ => Err(unsupported("semantic action is unavailable")),
            };
        }
        #[allow(unreachable_code)]
        {
            let _ = (action, target, cancellation, deadline_at_ms);
            Err(unsupported("semantic action is unavailable"))
        }
    }

    pub fn observe_semantic(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<semantic::SemanticObservation, ProtocolError> {
        if cancellation.is_cancelled() {
            return Err(ProtocolError::ObservationCancelled);
        }
        if now_ms() >= deadline_at_ms {
            return Err(ProtocolError::ObservationExpired);
        }
        #[cfg(target_os = "macos")]
        {
            let capabilities = self.capabilities()?;
            if !capabilities
                .permissions
                .get("accessibility")
                .copied()
                .unwrap_or(false)
            {
                return Err(ProtocolError::Executor("desktop backend error".to_string()));
            }
            let (observation, records) = mac_semantic_snapshot(
                &capabilities.display_geometry_hash,
                None,
                cancellation,
                deadline_at_ms,
            )?;
            persist_element_observations(&observation.observation_id, &records)?;
            return Ok(observation);
        }
        #[cfg(target_os = "linux")]
        {
            let mut backend = self
                .linux_atspi
                .lock()
                .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?;
            if backend.is_none() {
                *backend = Some(linux_atspi::LinuxAtspiBackend::connect()?);
            }
            return backend
                .as_ref()
                .ok_or_else(|| ProtocolError::Executor("desktop backend error".to_string()))?
                .snapshot(cancellation, deadline_at_ms);
        }
        #[cfg(target_os = "windows")]
        {
            return windows_uia::snapshot(cancellation, deadline_at_ms);
        }
        #[allow(unreachable_code)]
        Err(ProtocolError::Executor(
            "semantic observation is unavailable".to_string(),
        ))
    }

    #[cfg(target_os = "macos")]
    fn resolve_recorded_element(
        &self,
        target: &semantic::SemanticTargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(AxElement, NativeElement, semantic::Actionability), ProtocolError> {
        let observation = load_element_observation(&target.observation_id, &target.element_id)?;
        let capabilities = self.capabilities()?;
        if observation.protocol_version != PROTOCOL_VERSION
            || observation.target != *target
            || observation.display_geometry_hash != capabilities.display_geometry_hash
            || observation.observed_at_ms > now_ms()
            || now_ms().saturating_sub(observation.observed_at_ms)
                > MAX_COORDINATE_OBSERVATION_AGE_MS
        {
            return Err(ProtocolError::StaleTarget(
                "semantic observation provenance does not match".to_string(),
            ));
        }
        let (element, native) =
            mac_resolve_observed_element(&observation, cancellation, deadline_at_ms)?;
        validate_live_element(&native)?;
        let fingerprint = ElementFingerprint::from(&native);
        if element_fingerprint_hash(&fingerprint)? != observation.element_fingerprint_hash
            || observation.element_fingerprint_hash != target.fingerprint_hash
        {
            return Err(ProtocolError::StaleTarget(
                "live semantic target changed".to_string(),
            ));
        }
        Ok((element, native, observation.actionability))
    }

    pub fn observe_coordinates(&self) -> Result<CoordinateObservation, ProtocolError> {
        let snapshot = self
            .runtime
            .see(None, ImageMode::Screen, None, false)
            .map_err(|error| ProtocolError::Executor(redact_message(&error.to_string())))?;
        let display_geometry_hash = snapshot.display_geometry_hash.clone();
        let observation = CoordinateObservation {
            protocol_version: PROTOCOL_VERSION,
            snapshot_id: snapshot.snapshot_id.clone(),
            display_geometry_hash,
            snapshot_content_hash: snapshot.content_hash,
            observed_at_ms: now_ms(),
            displays: snapshot.displays,
        };
        persist_coordinate_observation(&observation)?;
        Ok(observation)
    }

    fn check_before_effect(
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), DispatchError> {
        if cancellation.is_cancelled() {
            return Err(interrupted(EffectKnowledge::CancelledBeforeEffect));
        }
        if now_ms() >= deadline_at_ms {
            return Err(interrupted(EffectKnowledge::ExpiredBeforeEffect));
        }
        Ok(())
    }

    fn check_after_effect(
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), DispatchError> {
        if cancellation.is_cancelled() || now_ms() >= deadline_at_ms {
            return Err(ambiguous(
                "action completed at the cancellation or deadline boundary",
            ));
        }
        Ok(())
    }

    fn dispatch_type_text(
        &self,
        text: &str,
        clear: bool,
        press_return: bool,
        delay_ms: Option<u64>,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), DispatchError> {
        if text.is_empty() || text.len() > 16 * 1024 || delay_ms.is_some_and(|delay| delay > 1_000)
        {
            return Err(no_effect("type action parameters are invalid"));
        }
        let mut effect_started = false;
        if clear {
            self.runtime
                .type_text("", true, false, None, None)
                .map_err(ambiguous_dispatch)?;
            effect_started = true;
        }
        let chunk_size = if delay_ms.is_some() { 1 } else { 64 };
        let mut chunk = String::new();
        for character in text.chars() {
            if cancellation.is_cancelled() || now_ms() >= deadline_at_ms {
                return Err(if effect_started {
                    ambiguous("type action interrupted after partial dispatch")
                } else if cancellation.is_cancelled() {
                    interrupted(EffectKnowledge::CancelledBeforeEffect)
                } else {
                    interrupted(EffectKnowledge::ExpiredBeforeEffect)
                });
            }
            chunk.push(character);
            if chunk.chars().count() == chunk_size {
                self.runtime
                    .type_text(&chunk, false, false, delay_ms, None)
                    .map_err(ambiguous_dispatch)?;
                effect_started = true;
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            self.runtime
                .type_text(&chunk, false, false, delay_ms, None)
                .map_err(ambiguous_dispatch)?;
            effect_started = true;
        }
        if cancellation.is_cancelled() || now_ms() >= deadline_at_ms {
            return Err(if effect_started {
                ambiguous("type action interrupted after partial dispatch")
            } else if cancellation.is_cancelled() {
                interrupted(EffectKnowledge::CancelledBeforeEffect)
            } else {
                interrupted(EffectKnowledge::ExpiredBeforeEffect)
            });
        }
        if press_return {
            self.runtime
                .type_text("", false, true, None, None)
                .map_err(ambiguous_dispatch)?;
        }
        Ok(())
    }
}

impl Executor for NativeExecutor {
    fn session_isolation(&self) -> SessionIsolation {
        self.session_isolation
    }

    fn shared_desktop_context_hash(&self) -> Result<String, ProtocolError> {
        self.shared_desktop_context_hash_with_boundary(&CancellationToken::default(), i64::MAX)
    }

    fn shared_desktop_context_hash_with_boundary(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<String, ProtocolError> {
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        if self.session_isolation != SessionIsolation::SharedDesktop {
            return Err(ProtocolError::Executor(
                "shared desktop context is unavailable".to_string(),
            ));
        }
        #[cfg(target_os = "macos")]
        {
            let result =
                mac_shared_desktop_context_hash(cancellation, deadline_at_ms).map_err(|_| {
                    mac_observation_error(
                        cancellation,
                        deadline_at_ms,
                        ProtocolError::Executor("desktop backend error".to_string()),
                    )
                });
            check_protocol_boundary(cancellation, deadline_at_ms)?;
            return result;
        }
        #[cfg(target_os = "linux")]
        {
            let mut backend = self
                .linux_atspi
                .lock()
                .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?;
            if backend.is_none() {
                *backend = Some(linux_atspi::LinuxAtspiBackend::connect()?);
            }
            let result = backend
                .as_ref()
                .ok_or_else(|| ProtocolError::Executor("desktop backend error".to_string()))?
                .shared_desktop_context_hash();
            check_protocol_boundary(cancellation, deadline_at_ms)?;
            return result;
        }
        #[cfg(target_os = "windows")]
        {
            return windows_uia::shared_desktop_context_hash(cancellation, deadline_at_ms);
        }
        #[allow(unreachable_code)]
        Err(ProtocolError::Executor(
            "shared desktop context is unavailable".to_string(),
        ))
    }

    fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
        #[cfg(target_os = "linux")]
        {
            let mut backend = self
                .linux_atspi
                .lock()
                .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?;
            if backend.is_none() {
                *backend = linux_atspi::LinuxAtspiBackend::connect().ok();
            }
            let display_geometry_hash = backend
                .as_ref()
                .and_then(|backend| backend.display_geometry_hash().ok());
            let permissions = backend
                .as_ref()
                .map(|backend| {
                    backend
                        .permissions(display_geometry_hash.is_some(), private_storage_available())
                })
                .unwrap_or_else(|| {
                    BTreeMap::from([
                        ("accessibility".to_string(), false),
                        ("atspi2".to_string(), false),
                        ("coordinate_capture".to_string(), false),
                        ("display_geometry".to_string(), false),
                        ("private_state".to_string(), false),
                        ("screen_recording".to_string(), false),
                    ])
                });
            let has_accessibility = permissions.get("accessibility").copied().unwrap_or(false);
            let has_display_geometry = permissions
                .get("display_geometry")
                .copied()
                .unwrap_or(false);
            let has_private_state = permissions.get("private_state").copied().unwrap_or(false);
            let mut supported_actions = Vec::new();
            let mut action_capabilities = Vec::new();
            if has_accessibility && has_display_geometry && has_private_state {
                for action in ["invoke", "set_value"] {
                    supported_actions.push(action.to_string());
                    action_capabilities.push(ActionCapability {
                        action: action.to_string(),
                        delivery_route: DeliveryRoute::TargetAddressed,
                        background_support: BackgroundSupport::Guarded,
                    });
                }
            }
            let session = linux_input::session_type();
            if session == "x11" || session == "wayland" {
                for action in ["click", "type_text", "press", "paste", "hotkey", "move"] {
                    supported_actions.push(action.to_string());
                    action_capabilities.push(ActionCapability {
                        action: action.to_string(),
                        delivery_route: DeliveryRoute::Pointer,
                        background_support: BackgroundSupport::Unavailable,
                    });
                }
                supported_actions.push("scroll".to_string());
                action_capabilities.push(ActionCapability {
                    action: "scroll".to_string(),
                    delivery_route: DeliveryRoute::Pointer,
                    background_support: BackgroundSupport::Unavailable,
                });
            }
            Ok(Capabilities {
                platform: "linux".to_string(),
                backend: "praefectus-linux".to_string(),
                session_isolation: self.session_isolation,
                action_capabilities,
                supported_actions,
                permissions,
                display_geometry_hash: display_geometry_hash.unwrap_or_else(|| "0".repeat(64)),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let permission_value = self.runtime.permissions();
            let permissions: BTreeMap<String, bool> = permission_value
                .as_object()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|(key, value)| {
                            value.as_bool().map(|value| (key.clone(), value))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let screens = self
                .runtime
                .list_screens()
                .map_err(|error| ProtocolError::Executor(redact_message(&error.to_string())))?;
            let accessibility = permissions.get("accessibility").copied().unwrap_or(false);
            let private_state = permissions.get("private_state").copied().unwrap_or(false);
            let mut supported_actions = Vec::new();
            if accessibility && private_state {
                supported_actions.extend([
                    "invoke",
                    "set_value",
                    "click",
                    "type_text",
                    "press",
                    "paste",
                    "hotkey",
                    "move",
                    "scroll",
                ]);
            }
            let action_capabilities = supported_actions
                .iter()
                .map(|action| ActionCapability {
                    action: (*action).to_string(),
                    delivery_route: match *action {
                        "invoke" | "set_value" => DeliveryRoute::TargetAddressed,
                        "scroll" => DeliveryRoute::TargetAddressed,
                        _ => DeliveryRoute::Pointer,
                    },
                    background_support: match *action {
                        "invoke" | "set_value" | "scroll" => BackgroundSupport::Guarded,
                        _ => BackgroundSupport::Unavailable,
                    },
                })
                .collect();
            Ok(Capabilities {
                platform: std::env::consts::OS.to_string(),
                backend: self.runtime.resolve_backend().to_string(),
                session_isolation: self.session_isolation,
                supported_actions: supported_actions.into_iter().map(str::to_string).collect(),
                action_capabilities,
                permissions,
                display_geometry_hash: hash_value(&screens)?,
            })
        }
    }

    fn observe(&self, target: &TargetRef) -> Result<Observation, ProtocolError> {
        self.observe_with_boundary(target, &CancellationToken::default(), i64::MAX)
    }

    fn observe_with_boundary(
        &self,
        target: &TargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Observation, ProtocolError> {
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        #[cfg(target_os = "linux")]
        if let TargetRef::Element { target } = target {
            let mut backend = self
                .linux_atspi
                .lock()
                .map_err(|_| ProtocolError::Executor("desktop backend error".to_string()))?;
            if backend.is_none() {
                *backend = Some(linux_atspi::LinuxAtspiBackend::connect()?);
            }
            return backend
                .as_ref()
                .ok_or_else(|| ProtocolError::Executor("desktop backend error".to_string()))?
                .observe_target(target, cancellation, deadline_at_ms);
        }
        #[cfg(target_os = "windows")]
        if let TargetRef::Element { target } = target {
            let (element, value_hash) =
                windows_uia::observe_target(target, cancellation, deadline_at_ms)?;
            let capabilities = self.capabilities()?;
            return semantic_target_observation(
                target,
                &element,
                value_hash.as_deref(),
                &capabilities,
            );
        }
        let capabilities = self.capabilities()?;
        #[cfg(target_os = "macos")]
        let element = match target {
            TargetRef::Element { target } => Some(
                self.resolve_recorded_element(target, cancellation, deadline_at_ms)?
                    .1,
            ),
            _ => None,
        };
        #[cfg(not(target_os = "macos"))]
        let element: Option<NativeElement> = None;
        let state = match element.as_ref() {
            Some(node) => node.state.clone(),
            None => match target {
                TargetRef::Coordinates { x, y, .. } => serde_json::json!({
                    "target_content_hash": self
                        .runtime
                        .target_content_hash(&NativePoint { x: *x, y: *y })
                        .map_err(|error| ProtocolError::Executor(redact_message(&error.to_string())))?,
                }),
                _ => Value::Null,
            },
        };
        let target_fingerprint_hash = element
            .as_ref()
            .map(ElementFingerprint::from)
            .map(|fingerprint| element_fingerprint_hash(&fingerprint))
            .transpose()?;
        let observation_hash = hash_serializable(&(
            &capabilities.display_geometry_hash,
            &target_fingerprint_hash,
            &state,
        ))?;
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        Ok(Observation {
            evidence: Evidence {
                observation_hash,
                target_fingerprint_hash,
                display_geometry_hash: capabilities.display_geometry_hash,
                observed_at_ms: now_ms(),
            },
            element,
            state,
        })
    }

    fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, ProtocolError> {
        self.resolve_with_boundary(target, &CancellationToken::default(), i64::MAX)
    }

    fn resolve_with_boundary(
        &self,
        target: &TargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<ResolvedTarget, ProtocolError> {
        check_protocol_boundary(cancellation, deadline_at_ms)?;
        match target {
            TargetRef::Coordinates {
                x,
                y,
                display_id,
                display_geometry_hash,
                snapshot_id,
                snapshot_content_hash,
            } => {
                let observation = load_coordinate_observation(snapshot_id)?;
                if observation.protocol_version != PROTOCOL_VERSION
                    || observation.snapshot_id != *snapshot_id
                    || observation.display_geometry_hash != *display_geometry_hash
                    || observation.snapshot_content_hash != *snapshot_content_hash
                    || observation.observed_at_ms > now_ms()
                    || now_ms().saturating_sub(observation.observed_at_ms)
                        > MAX_COORDINATE_OBSERVATION_AGE_MS
                {
                    return Err(ProtocolError::StaleTarget(
                        "coordinate observation provenance does not match".to_string(),
                    ));
                }
                let screens = self
                    .runtime
                    .list_screens()
                    .map_err(|error| ProtocolError::Executor(redact_message(&error.to_string())))?;
                let current = hash_value(&screens)?;
                if &current != display_geometry_hash {
                    return Err(ProtocolError::StaleTarget(
                        "display geometry changed".to_string(),
                    ));
                }
                let current_content_hash = self
                    .runtime
                    .screen_content_hash()
                    .map_err(|error| ProtocolError::Executor(redact_message(&error.to_string())))?;
                if &current_content_hash != snapshot_content_hash {
                    return Err(ProtocolError::StaleTarget(
                        "screen observation changed".to_string(),
                    ));
                }
                let on_display = screens.as_array().is_some_and(|values| {
                    values.iter().any(|screen| {
                        let id_matches = ["id", "name", "display_id"]
                            .iter()
                            .filter_map(|key| screen.get(key).and_then(Value::as_str))
                            .any(|id| id == display_id);
                        let bounds = (
                            screen.get("x").and_then(Value::as_i64),
                            screen.get("y").and_then(Value::as_i64),
                            screen.get("width").and_then(Value::as_i64),
                            screen.get("height").and_then(Value::as_i64),
                        );
                        id_matches
                            && matches!(bounds, (Some(left), Some(top), Some(width), Some(height))
                        if width > 0 && height > 0 && *x >= left && *y >= top
                            && *x < left.saturating_add(width) && *y < top.saturating_add(height))
                    })
                });
                if !on_display {
                    return Err(ProtocolError::StaleTarget(
                        "coordinate is outside its named display".to_string(),
                    ));
                }
                Ok(ResolvedTarget::Point(NativePoint { x: *x, y: *y }))
            }
            TargetRef::Element { target } => {
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                {
                    Ok(ResolvedTarget::Semantic(target.clone()))
                }
                #[cfg(target_os = "macos")]
                {
                    self.resolve_recorded_element(target, cancellation, deadline_at_ms)?;
                    Ok(ResolvedTarget::Semantic(target.clone()))
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
                Err(ProtocolError::Executor(
                    "semantic execution is unavailable".to_string(),
                ))
            }
            TargetRef::None => Ok(ResolvedTarget::None),
        }
    }

    fn dispatch(
        &self,
        action: &Action,
        target: &ResolvedTarget,
        verification: &VerificationPolicy,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        Self::check_before_effect(cancellation, deadline_at_ms)?;
        validate_action(action).map_err(|_| no_effect("action parameters are invalid"))?;
        if matches!(action, Action::SetValue { .. })
            && !matches!(verification, VerificationPolicy::TargetValueHash { .. })
        {
            return Err(no_effect(
                "set_value requires target value hash verification",
            ));
        }
        if let ResolvedTarget::Semantic(target) = target {
            return self.dispatch_semantic(action, target, cancellation, deadline_at_ms);
        }
        match target {
            ResolvedTarget::Point(_) => {
                return Err(unsupported(
                    "coordinate effects require artifact-bound observation provenance",
                ));
            }
            ResolvedTarget::None => return Err(no_effect("action requires a fenced target")),
            ResolvedTarget::Element(element) => validate_live_element(element)
                .map_err(|_| no_effect("semantic target is unavailable"))?,
            ResolvedTarget::Semantic(_) => unreachable!("semantic target handled above"),
        }
        if matches!(
            (action, target),
            (
                Action::Click { count, .. },
                ResolvedTarget::Element(_)
            ) if *count > 1
        ) {
            return Err(unsupported("repeated semantic clicks are unavailable"));
        }
        let capabilities = self
            .capabilities()
            .map_err(|_| unsupported("runtime capabilities are unavailable"))?;
        if !capabilities
            .supported_actions
            .iter()
            .any(|supported| supported == action.name())
        {
            return Err(unsupported(
                "action is unavailable with current permissions or backend",
            ));
        }
        let native_target = || match target {
            ResolvedTarget::Point(point) => Ok(Target::Point(point.clone())),
            ResolvedTarget::Element(element) => Ok(Target::Element(element.clone())),
            ResolvedTarget::Semantic(_) => Err(no_effect("semantic target was not routed")),
            ResolvedTarget::None => Err(no_effect("action requires a target")),
        };
        if let Action::TypeText {
            text,
            clear,
            press_return,
            delay_ms,
        } = action
        {
            self.dispatch_type_text(
                text,
                *clear,
                *press_return,
                *delay_ms,
                cancellation,
                deadline_at_ms,
            )?;
            Self::check_after_effect(cancellation, deadline_at_ms)?;
            return Ok(DispatchReceipt {
                backend: self.runtime.resolve_backend().to_string(),
                fallback_chain: Vec::new(),
            });
        }
        let result = match action {
            Action::Invoke => unreachable!("semantic invoke handled above"),
            Action::Click { button, count, .. } => {
                if matches!(button, MouseButton::Middle) && !cfg!(target_os = "windows") {
                    return Err(unsupported("middle click is not reliable on this backend"));
                }
                if matches!(target, ResolvedTarget::Element(_))
                    && !matches!(button, MouseButton::Left)
                {
                    return Err(unsupported(
                        "semantic elements support only the accessibility press action",
                    ));
                }
                for index in 0..*count {
                    if index == 0 {
                        Self::check_before_effect(cancellation, deadline_at_ms)?;
                    } else if cancellation.is_cancelled() || now_ms() >= deadline_at_ms {
                        return Err(ambiguous("click interrupted after partial dispatch"));
                    }
                    self.runtime.click(
                        native_target()?,
                        match button {
                            MouseButton::Left => "left",
                            MouseButton::Right => "right",
                            MouseButton::Middle => "middle",
                        },
                    )?;
                }
                if matches!(verification, VerificationPolicy::None) {
                    return Err(ambiguous("native input event delivery cannot be verified"));
                }
                return Self::check_after_effect(cancellation, deadline_at_ms).map(|()| {
                    DispatchReceipt {
                        backend: self.runtime.resolve_backend().to_string(),
                        fallback_chain: Vec::new(),
                    }
                });
            }
            Action::TypeText { .. } => unreachable!("type text handled above"),
            Action::Press {
                key,
                count,
                delay_ms,
            } => {
                for index in 0..*count {
                    if index == 0 {
                        Self::check_before_effect(cancellation, deadline_at_ms)?;
                    } else if cancellation.is_cancelled() || now_ms() >= deadline_at_ms {
                        return Err(ambiguous("press interrupted after partial dispatch"));
                    }
                    self.runtime
                        .press(key, 1, None)
                        .map_err(ambiguous_dispatch)?;
                    if index + 1 < *count
                        && let Some(delay) = delay_ms
                    {
                        std::thread::sleep(std::time::Duration::from_millis(*delay));
                    }
                }
                return Self::check_after_effect(cancellation, deadline_at_ms).map(|()| {
                    DispatchReceipt {
                        backend: self.runtime.resolve_backend().to_string(),
                        fallback_chain: Vec::new(),
                    }
                });
            }
            Action::Paste { text } => self.runtime.paste(text),
            Action::Hotkey { keys } => {
                let keys = keys.iter().map(String::as_str).collect::<Vec<_>>();
                self.runtime.hotkey(&keys)
            }
            Action::Scroll { direction, amount } => {
                for index in 0..*amount {
                    if index == 0 {
                        Self::check_before_effect(cancellation, deadline_at_ms)?;
                    } else if cancellation.is_cancelled() || now_ms() >= deadline_at_ms {
                        return Err(ambiguous("scroll interrupted after partial dispatch"));
                    }
                    self.runtime
                        .scroll(
                            match direction {
                                Direction::Up => Direction::Up,
                                Direction::Down => Direction::Down,
                                Direction::Left => Direction::Left,
                                Direction::Right => Direction::Right,
                            },
                            1,
                        )
                        .map_err(ambiguous_dispatch)?;
                }
                return Self::check_after_effect(cancellation, deadline_at_ms).map(|()| {
                    DispatchReceipt {
                        backend: self.runtime.resolve_backend().to_string(),
                        fallback_chain: Vec::new(),
                    }
                });
            }
            Action::Move => {
                Self::check_before_effect(cancellation, deadline_at_ms)?;
                self.runtime
                    .move_cursor(native_target()?)
                    .map_err(ambiguous_dispatch)?;
                if matches!(verification, VerificationPolicy::None) {
                    return Err(ambiguous("native input event delivery cannot be verified"));
                }
                return Self::check_after_effect(cancellation, deadline_at_ms).map(|()| {
                    DispatchReceipt {
                        backend: self.runtime.resolve_backend().to_string(),
                        fallback_chain: Vec::new(),
                    }
                });
            }
            Action::SetValue { value } => {
                if !cfg!(target_os = "macos") {
                    return Err(unsupported("set_value is unavailable on this backend"));
                }
                if !matches!(target, ResolvedTarget::Element(element) if element.bounds.is_some()) {
                    return Err(no_effect("set_value requires an element with bounds"));
                }
                Self::check_before_effect(cancellation, deadline_at_ms)?;
                self.runtime
                    .set_value(native_target()?, value, cancellation, deadline_at_ms)?;
                return Self::check_after_effect(cancellation, deadline_at_ms).map(|()| {
                    DispatchReceipt {
                        backend: self.runtime.resolve_backend().to_string(),
                        fallback_chain: Vec::new(),
                    }
                });
            }
        };
        result.map_err(|error| DispatchError {
            message: redact_message(&error.to_string()),
            effect: EffectKnowledge::Unknown,
            code: FailureCode::DispatchFailed,
        })?;
        Self::check_after_effect(cancellation, deadline_at_ms)?;
        Ok(DispatchReceipt {
            backend: self.runtime.resolve_backend().to_string(),
            fallback_chain: Vec::new(),
        })
    }
}

impl From<&NativeElement> for ElementFingerprint {
    fn from(node: &NativeElement) -> Self {
        Self {
            backend: node.backend.clone(),
            id: node.id.clone(),
            app: node.app.clone(),
            process_id: node.process_id.unwrap_or_default(),
            window: node.window.clone().unwrap_or_default(),
            role: node.role.clone(),
            label: node
                .label
                .clone()
                .or_else(|| node.title.clone())
                .unwrap_or_default(),
            bounds: node.bounds.as_ref().map(|bounds| Rect {
                x: bounds.x,
                y: bounds.y,
                width: bounds.width,
                height: bounds.height,
            }),
        }
    }
}

fn validate_live_element(node: &NativeElement) -> Result<(), ProtocolError> {
    let visible = node.state.get("visible").and_then(Value::as_bool) == Some(true)
        && node.state.get("hidden").and_then(Value::as_bool) != Some(true);
    if node.id.is_empty()
        || node.app.is_empty()
        || node.window.as_deref().is_none_or(str::is_empty)
        || node.process_id.unwrap_or_default() <= 0
        || node.enabled != Some(true)
        || !visible
        || !node
            .bounds
            .as_ref()
            .is_some_and(|bounds| bounds.width > 0 && bounds.height > 0)
    {
        return Err(ProtocolError::StaleTarget(
            "target is missing, disabled, or hidden".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn validate_matching_live_element(
    current: &NativeElement,
    expected: &NativeElement,
) -> Result<(), NativeError> {
    validate_live_element(current).map_err(|_| NativeError)?;
    if ElementFingerprint::from(current) != ElementFingerprint::from(expected) {
        return Err(NativeError);
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LedgerRecord {
    Claim {
        operation_id: String,
        action_hash: String,
        claimed_at_ms: i64,
        #[serde(default)]
        action_name: Option<String>,
        #[serde(default)]
        delivery_route: Option<DeliveryRoute>,
        #[serde(default)]
        session_isolation: Option<SessionIsolation>,
        #[serde(default)]
        interaction_mode: Option<InteractionMode>,
    },
    Terminal {
        acknowledgement: Box<ActionAck>,
    },
}

enum ClaimResult {
    New,
    Replay(Box<ActionAck>),
    RecoveredUnknown {
        action_name: Option<String>,
        delivery_route: Option<DeliveryRoute>,
        session_isolation: Option<SessionIsolation>,
        interaction_mode: Option<InteractionMode>,
    },
}

struct OperationLedger {
    path: PathBuf,
}

impl OperationLedger {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn execution_lock(&self) -> Result<LedgerLock, ProtocolError> {
        acquire_ledger_lock(&self.path.with_extension("lock"))
    }

    fn trajectory_lock(&self) -> Result<LedgerLock, ProtocolError> {
        acquire_ledger_lock(&self.path.with_extension("trajectory.lock"))
    }

    fn repair_tail(&self) -> Result<(), ProtocolError> {
        #[cfg(windows)]
        let _path_guard = windows_acl::lock_path(&self.path)?;
        repair_jsonl_tail::<LedgerRecord>(
            &self.path,
            "ledger contains an invalid non-terminal record",
        )
    }

    fn claim(
        &self,
        request: &ActionRequest,
        action_hash: &str,
        session_isolation: SessionIsolation,
    ) -> Result<ClaimResult, ProtocolError> {
        let records = self.records()?;
        let mut claim = None;
        let mut terminal = None;
        for record in records {
            match record {
                LedgerRecord::Claim {
                    operation_id,
                    action_hash,
                    action_name,
                    delivery_route,
                    session_isolation,
                    interaction_mode,
                    ..
                } if operation_id == request.operation_id => {
                    claim = Some((
                        action_hash,
                        action_name,
                        delivery_route,
                        session_isolation,
                        interaction_mode,
                    ));
                }
                LedgerRecord::Terminal { acknowledgement }
                    if acknowledgement.operation_id == request.operation_id =>
                {
                    terminal = Some(acknowledgement)
                }
                _ => {}
            }
        }
        if let Some((
            existing_hash,
            action_name,
            delivery_route,
            session_isolation,
            interaction_mode,
        )) = claim
        {
            if existing_hash != action_hash {
                return Err(ProtocolError::Conflict);
            }
            return Ok(terminal.map(ClaimResult::Replay).unwrap_or(
                ClaimResult::RecoveredUnknown {
                    action_name,
                    delivery_route,
                    session_isolation,
                    interaction_mode,
                },
            ));
        }
        self.append(&LedgerRecord::Claim {
            operation_id: request.operation_id.clone(),
            action_hash: action_hash.to_string(),
            claimed_at_ms: now_ms(),
            action_name: Some(request.action.name().to_string()),
            delivery_route: Some(claim_delivery_route(&request.action, &request.target)),
            session_isolation: Some(session_isolation),
            interaction_mode: Some(request.interaction_mode),
        })?;
        Ok(ClaimResult::New)
    }

    fn finish(&self, acknowledgement: &ActionAck) -> Result<(), ProtocolError> {
        self.append(&LedgerRecord::Terminal {
            acknowledgement: Box::new(acknowledgement.clone()),
        })?;
        let _ = self.trajectory(acknowledgement);
        Ok(())
    }

    fn finish_after_effect(&self, acknowledgement: ActionAck) -> ActionAck {
        if self.finish(&acknowledgement).is_ok() {
            return acknowledgement;
        }
        let acknowledgement = persistence_unknown_ack(acknowledgement);
        let _ = self
            .repair_tail()
            .and_then(|()| self.finish(&acknowledgement));
        acknowledgement
    }

    fn status(&self, operation_id: &str) -> Result<Option<ActionAck>, ProtocolError> {
        let _guard = self.execution_lock()?;
        self.repair_tail()?;
        let mut claim = None;
        let mut terminal = None;
        for record in self.records()? {
            match record {
                LedgerRecord::Claim {
                    operation_id: claimed_operation_id,
                    action_hash,
                    claimed_at_ms,
                    action_name,
                    delivery_route,
                    session_isolation,
                    interaction_mode,
                } if claimed_operation_id == operation_id => {
                    claim = Some((
                        action_hash,
                        claimed_at_ms,
                        action_name,
                        delivery_route,
                        session_isolation,
                        interaction_mode,
                    ));
                }
                LedgerRecord::Terminal { acknowledgement }
                    if acknowledgement.operation_id == operation_id =>
                {
                    terminal = Some(*acknowledgement);
                }
                _ => {}
            }
        }
        if terminal.is_some() {
            return Ok(terminal);
        }
        let Some((
            action_hash,
            claimed_at_ms,
            action_name,
            delivery_route,
            session_isolation,
            interaction_mode,
        )) = claim
        else {
            return Ok(None);
        };
        let finished_at_ms = now_ms();
        let delivery_route = delivery_route.unwrap_or(DeliveryRoute::Unknown);
        let session_isolation = session_isolation.unwrap_or(SessionIsolation::Unknown);
        let interaction_mode = interaction_mode.unwrap_or(InteractionMode::Unknown);
        let acknowledgement = ActionAck {
            protocol_version: PROTOCOL_VERSION,
            operation_id: operation_id.to_string(),
            sequence: 2,
            action_hash: action_hash.clone(),
            replayed: false,
            state: AckState::Terminal {
                terminal: Box::new(Terminal::OutcomeUnknown {
                    receipt: Receipt {
                        protocol_version: PROTOCOL_VERSION,
                        action_name: action_name.unwrap_or_else(|| "unknown".to_string()),
                        action_hash,
                        started_at_ms: claimed_at_ms,
                        finished_at_ms,
                        backend: "unknown".to_string(),
                        fallback_chain: Vec::new(),
                        delivery_route,
                        session_isolation,
                        interaction_mode,
                        context_preservation: recovered_context_preservation(
                            interaction_mode,
                            session_isolation,
                        ),
                        effect: Effect::Unknown,
                        before: None,
                        after: None,
                        warnings: Vec::new(),
                    },
                    message: "a durable claim existed without a terminal receipt".to_string(),
                }),
            },
        };
        self.finish(&acknowledgement)?;
        Ok(Some(acknowledgement))
    }

    fn records(&self) -> Result<Vec<LedgerRecord>, ProtocolError> {
        #[cfg(windows)]
        let _path_guard = windows_acl::lock_path(&self.path)?;
        let file = match private_open_options().read(true).open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        restrict_file(&file)?;
        let mut lines = BufReader::new(file).lines().peekable();
        let mut records = Vec::new();
        while let Some(line) = lines.next() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str(&line) {
                Ok(record) => records.push(record),
                Err(_) if lines.peek().is_none() => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(records)
    }

    fn append(&self, record: &LedgerRecord) -> Result<(), ProtocolError> {
        require_private_storage()?;
        if let Some(parent) = self.path.parent() {
            ensure_directory(parent, false)?;
        }
        #[cfg(windows)]
        let _path_guard = windows_acl::lock_path(&self.path)?;
        let existed = self.path.exists();
        let mut file = private_open_options()
            .create(true)
            .append(true)
            .open(&self.path)?;
        restrict_file(&file)?;
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        if !existed {
            sync_parent(&self.path)?;
        }
        Ok(())
    }

    fn trajectory(&self, acknowledgement: &ActionAck) -> Result<(), ProtocolError> {
        require_private_storage()?;
        let path = self.path.with_extension("trajectory.jsonl");
        let _guard = self.trajectory_lock()?;
        if let Some(parent) = path.parent() {
            ensure_directory(parent, false)?;
        }
        #[cfg(windows)]
        let _path_guard = windows_acl::lock_path(&path)?;
        repair_jsonl_tail::<Value>(&path, "trajectory contains an invalid non-terminal record")?;
        let terminal_kind = match &acknowledgement.state {
            AckState::Accepted => "accepted",
            AckState::Executing => "executing",
            AckState::Terminal { terminal } => match &**terminal {
                Terminal::Succeeded { .. } => "succeeded",
                Terminal::Rejected { .. } => "rejected",
                Terminal::Failed { .. } => "failed",
                Terminal::CancelledBeforeEffect => "cancelled_before_effect",
                Terminal::ExpiredBeforeEffect => "expired_before_effect",
                Terminal::OutcomeUnknown { .. } => "outcome_unknown",
            },
        };
        let line = serde_json::json!({
            "protocol_version": acknowledgement.protocol_version,
            "operation_id_hash": hash_bytes(acknowledgement.operation_id.as_bytes()),
            "action_hash": acknowledgement.action_hash,
            "sequence": acknowledgement.sequence,
            "state": terminal_kind,
            "recorded_at_ms": now_ms()
        });
        let existed = path.exists();
        let mut file = private_open_options()
            .create(true)
            .append(true)
            .open(&path)?;
        restrict_file(&file)?;
        serde_json::to_writer(&mut file, &line)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        if !existed {
            sync_parent(&path)?;
        }
        Ok(())
    }
}

fn acquire_ledger_lock(path: &Path) -> Result<LedgerLock, ProtocolError> {
    require_private_storage()?;
    if let Some(parent) = path.parent() {
        ensure_directory(parent, false)?;
    }
    #[cfg(windows)]
    let _path_guard = windows_acl::lock_path(path)?;
    let existed = path.exists();
    let file = private_open_options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    restrict_file(&file)?;
    if !existed {
        sync_parent(path)?;
    }
    file.lock_exclusive()?;
    Ok(LedgerLock(file))
}

fn repair_jsonl_tail<T: DeserializeOwned>(
    path: &Path,
    invalid_record_message: &str,
) -> Result<(), ProtocolError> {
    let mut file = match private_open_options().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    restrict_file(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let durable_len = if bytes.last() == Some(&b'\n') {
        bytes.len()
    } else {
        bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1)
    };
    let mut offset = 0;
    let truncate_at = durable_len;
    while offset < durable_len {
        let end = offset
            + bytes[offset..durable_len]
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(durable_len - offset)
            + 1;
        let line = &bytes[offset..end - 1];
        if !line.iter().all(u8::is_ascii_whitespace) && serde_json::from_slice::<T>(line).is_err() {
            return Err(ProtocolError::InvalidRequest(
                invalid_record_message.to_string(),
            ));
        }
        offset = end;
    }
    if truncate_at != bytes.len() {
        file.set_len(truncate_at as u64)?;
        file.sync_all()?;
    }
    Ok(())
}

fn persistence_unknown_ack(mut acknowledgement: ActionAck) -> ActionAck {
    if let AckState::Terminal { terminal } = &mut acknowledgement.state
        && matches!(&**terminal, Terminal::Succeeded { .. })
    {
        let previous = std::mem::replace(&mut **terminal, Terminal::CancelledBeforeEffect);
        if let Terminal::Succeeded { receipt } = previous {
            **terminal = Terminal::OutcomeUnknown {
                receipt,
                message: "action completed but terminal receipt durability is unknown".to_string(),
            };
        }
    }
    acknowledgement
}

struct LedgerLock(File);

impl Drop for LedgerLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn validate_request(request: &ActionRequest) -> Result<(), ProtocolError> {
    if request.protocol_version != PROTOCOL_VERSION
        || request.action_version != PROTOCOL_VERSION
        || request.target_version != PROTOCOL_VERSION
        || request.verification_version != PROTOCOL_VERSION
        || request.interaction_mode == InteractionMode::Unknown
    {
        return Err(ProtocolError::InvalidRequest(
            "unsupported protocol version".to_string(),
        ));
    }
    for (name, value) in [
        ("operation_id", request.operation_id.as_str()),
        ("subject", request.subject.as_str()),
        ("session_id", request.session_id.as_str()),
    ] {
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':'))
        {
            return Err(ProtocolError::InvalidRequest(format!("invalid {name}")));
        }
    }
    if matches!(request.target, TargetRef::None) {
        return Err(ProtocolError::InvalidRequest(
            "action requires a target".to_string(),
        ));
    }
    if matches!(request.target, TargetRef::Coordinates { .. }) {
        return Err(ProtocolError::InvalidRequest(
            "coordinate targets require artifact-bound observation provenance".to_string(),
        ));
    }
    validate_action(&request.action)?;
    validate_verification(&request.verification)?;
    match (&request.action, &request.verification) {
        (Action::SetValue { value }, VerificationPolicy::TargetValueHash { sha256 })
            if semantic_hash(sha256) && hash_bytes(value.as_bytes()) == *sha256 => {}
        (Action::SetValue { .. }, _) | (_, VerificationPolicy::TargetValueHash { .. }) => {
            return Err(ProtocolError::InvalidRequest(
                "invalid target value verification".to_string(),
            ));
        }
        _ => {}
    }
    if request.deadline_at_ms <= 0
        || request.authority.signature.len() != 128
        || !request
            .authority
            .signature
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProtocolError::InvalidRequest(
            "invalid deadline or authority signature".to_string(),
        ));
    }
    let valid_snapshot = match &request.target {
        TargetRef::Coordinates {
            snapshot_id,
            display_id,
            display_geometry_hash,
            snapshot_content_hash,
            ..
        } => {
            !snapshot_id.is_empty()
                && snapshot_id.len() <= 256
                && !display_id.is_empty()
                && display_id.len() <= 256
                && display_geometry_hash.len() == 64
                && snapshot_content_hash.len() == 64
        }
        TargetRef::Element { target } => {
            semantic_hash(&target.observation_id)
                && target.generation > 0
                && semantic_hash(&target.provenance_hash)
                && semantic_hash(&target.element_id)
                && semantic_hash(&target.fingerprint_hash)
        }
        TargetRef::None => true,
    };
    if !valid_snapshot {
        return Err(ProtocolError::InvalidRequest(
            "invalid target provenance".to_string(),
        ));
    }
    let snapshot_id = match &request.target {
        TargetRef::Coordinates { snapshot_id, .. } => Some(snapshot_id),
        TargetRef::Element { target } => Some(&target.observation_id),
        TargetRef::None => None,
    };
    if snapshot_id.is_some_and(|snapshot_id| !valid_protocol_snapshot_id(snapshot_id)) {
        return Err(ProtocolError::InvalidRequest(
            "invalid snapshot ID".to_string(),
        ));
    }
    Ok(())
}

fn validate_action(action: &Action) -> Result<(), ProtocolError> {
    let valid = match action {
        Action::Invoke => true,
        Action::Click { count, .. } => (1..=3).contains(count),
        Action::TypeText { text, delay_ms, .. } => {
            !text.is_empty()
                && text.len() <= 16 * 1024
                && delay_ms.is_none_or(|delay| delay <= 1_000)
        }
        Action::Press {
            key,
            count,
            delay_ms,
        } => {
            !key.is_empty()
                && key.len() <= 64
                && (1..=100).contains(count)
                && delay_ms.is_none_or(|delay| delay <= 1_000)
        }
        Action::Paste { text } => !text.is_empty() && text.len() <= 16 * 1024,
        Action::Hotkey { keys } => {
            !keys.is_empty()
                && keys.len() <= 8
                && keys.iter().all(|key| !key.is_empty() && key.len() <= 64)
        }
        Action::Scroll { amount, .. } => (1..=100).contains(amount),
        Action::Move => true,
        Action::SetValue { value } => value.len() <= 16 * 1024,
    };
    if valid {
        Ok(())
    } else {
        Err(ProtocolError::InvalidRequest(
            "invalid action parameters".to_string(),
        ))
    }
}

fn validate_verification(verification: &VerificationPolicy) -> Result<(), ProtocolError> {
    let VerificationPolicy::TargetState { expected } = verification else {
        return Ok(());
    };
    let mut stack = vec![(expected, 0_usize)];
    let mut nodes = 0_usize;
    let mut bytes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > MAX_VERIFICATION_JSON_NODES || depth > MAX_VERIFICATION_JSON_DEPTH {
            return Err(ProtocolError::InvalidRequest(
                "verification state is too large".to_string(),
            ));
        }
        match value {
            Value::Null | Value::Bool(_) => {}
            Value::Number(value) => bytes = bytes.saturating_add(value.to_string().len()),
            Value::String(value) => bytes = bytes.saturating_add(value.len()),
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth.saturating_add(1))));
            }
            Value::Object(values) => {
                for (key, value) in values {
                    bytes = bytes.saturating_add(key.len());
                    stack.push((value, depth.saturating_add(1)));
                }
            }
        }
        if bytes > MAX_VERIFICATION_JSON_BYTES {
            return Err(ProtocolError::InvalidRequest(
                "verification state is too large".to_string(),
            ));
        }
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':'))
}

fn is_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn normalized_action_hash(request: &ActionRequest) -> Result<String, ProtocolError> {
    validate_verification(&request.verification)?;
    hash_serializable(&(
        request.protocol_version,
        request.action_version,
        request.target_version,
        request.verification_version,
        &request.subject,
        &request.session_id,
        &request.action,
        &request.target,
        request.interaction_mode,
        request.deadline_at_ms,
        &request.verification,
        request.safety,
    ))
}

pub fn element_fingerprint_hash(fingerprint: &ElementFingerprint) -> Result<String, ProtocolError> {
    hash_serializable(fingerprint)
}

fn verify(
    policy: &VerificationPolicy,
    before: &Observation,
    after: Option<&Observation>,
    expected_target_fingerprint_hash: Option<&str>,
) -> (Effect, Vec<String>) {
    match (policy, after) {
        (VerificationPolicy::None, _) => (
            Effect::ExecutedUnverified,
            vec!["post-action verification was not requested".to_string()],
        ),
        (_, None) => (
            Effect::ExecutedUnverified,
            vec!["post-action observation failed".to_string()],
        ),
        (VerificationPolicy::SnapshotChanged, Some(after))
            if before.evidence.observation_hash != after.evidence.observation_hash =>
        {
            (
                Effect::ExecutedUnverified,
                vec![
                    "post-action observation changed but does not verify the requested effect"
                        .to_string(),
                ],
            )
        }
        (VerificationPolicy::SnapshotChanged, Some(_)) => (
            Effect::ExecutedUnverified,
            vec!["post-action observation did not change".to_string()],
        ),
        (VerificationPolicy::TargetValueHash { sha256 }, Some(after))
            if after.state.get("value_hash").and_then(Value::as_str) == Some(sha256.as_str())
                && before.evidence.target_fingerprint_hash.is_some()
                && before.evidence.target_fingerprint_hash
                    == after.evidence.target_fingerprint_hash
                && before.evidence.target_fingerprint_hash.as_deref()
                    == expected_target_fingerprint_hash
                && before.evidence.display_geometry_hash
                    == after.evidence.display_geometry_hash =>
        {
            (Effect::Verified, Vec::new())
        }
        (VerificationPolicy::TargetValueHash { .. }, Some(_)) => (
            Effect::ExecutedUnverified,
            vec!["target value hash did not match the expected value".to_string()],
        ),
        (VerificationPolicy::TargetState { expected }, Some(after))
            if &after.state == expected
                && before.evidence.target_fingerprint_hash.is_some()
                && before.evidence.target_fingerprint_hash
                    == after.evidence.target_fingerprint_hash
                && before.evidence.target_fingerprint_hash.as_deref()
                    == expected_target_fingerprint_hash
                && before.evidence.display_geometry_hash
                    == after.evidence.display_geometry_hash =>
        {
            (Effect::Verified, Vec::new())
        }
        (VerificationPolicy::TargetState { .. }, Some(_)) => (
            Effect::ExecutedUnverified,
            vec!["target state did not match the expected value".to_string()],
        ),
    }
}

fn protocol_failure(error: ProtocolError) -> Terminal {
    if matches!(error, ProtocolError::ObservationCancelled) {
        return Terminal::CancelledBeforeEffect;
    }
    if matches!(error, ProtocolError::ObservationExpired) {
        return Terminal::ExpiredBeforeEffect;
    }
    let code = match &error {
        ProtocolError::StaleTarget(_) => FailureCode::StaleTarget,
        ProtocolError::TargetNotFound(_) => FailureCode::TargetNotFound,
        ProtocolError::InvalidRequest(_) => FailureCode::InvalidRequest,
        _ => FailureCode::DispatchFailed,
    };
    let rejected = matches!(
        &error,
        ProtocolError::StaleTarget(_)
            | ProtocolError::TargetNotFound(_)
            | ProtocolError::InvalidRequest(_)
    );
    let message = match error {
        ProtocolError::StaleTarget(_) => "stale target".to_string(),
        ProtocolError::TargetNotFound(_) => "target not found".to_string(),
        ProtocolError::InvalidRequest(_) => "invalid request".to_string(),
        ProtocolError::AuthorityDenied => "authority denied".to_string(),
        _ => "executor failed".to_string(),
    };
    if rejected {
        Terminal::Rejected { code, message }
    } else {
        Terminal::Failed { code, message }
    }
}

fn no_effect(message: &str) -> DispatchError {
    DispatchError {
        message: message.to_string(),
        effect: EffectKnowledge::NoEffect,
        code: FailureCode::InvalidRequest,
    }
}

fn interrupted(effect: EffectKnowledge) -> DispatchError {
    DispatchError {
        message: match effect {
            EffectKnowledge::CancelledBeforeEffect => "cancelled before effect",
            EffectKnowledge::ExpiredBeforeEffect => "expired before effect",
            _ => "interrupted",
        }
        .to_string(),
        effect,
        code: FailureCode::DispatchFailed,
    }
}

fn unsupported(message: &str) -> DispatchError {
    DispatchError {
        message: message.to_string(),
        effect: EffectKnowledge::NoEffect,
        code: FailureCode::Unsupported,
    }
}

fn ambiguous(message: &str) -> DispatchError {
    DispatchError {
        message: message.to_string(),
        effect: EffectKnowledge::Unknown,
        code: FailureCode::DispatchFailed,
    }
}

fn ambiguous_dispatch(error: NativeError) -> DispatchError {
    let _ = error;
    ambiguous("desktop backend failed after dispatch began")
}

fn dispatch_message(error: &DispatchError) -> String {
    match error.effect {
        EffectKnowledge::Unknown => "the action outcome is unknown".to_string(),
        EffectKnowledge::NoEffect => "the action was not dispatched".to_string(),
        EffectKnowledge::CancelledBeforeEffect => {
            "the action was cancelled before dispatch".to_string()
        }
        EffectKnowledge::ExpiredBeforeEffect => "the action expired before dispatch".to_string(),
    }
}

fn redact_message(_message: &str) -> String {
    "desktop backend error".to_string()
}

fn coordinate_observation_path(snapshot_id: &str) -> Result<PathBuf, ProtocolError> {
    if !valid_native_snapshot_id(snapshot_id) {
        return Err(ProtocolError::InvalidRequest(
            "invalid snapshot ID".to_string(),
        ));
    }
    Ok(observation_root()
        .join("praefectus")
        .join("observations")
        .join(format!("{snapshot_id}.json")))
}

fn fallback_temp_dir() -> PathBuf {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::OnceLock;
    static FALLBACK: OnceLock<PathBuf> = OnceLock::new();
    FALLBACK
        .get_or_init(|| {
            let random_id = std::collections::hash_map::RandomState::new()
                .build_hasher()
                .finish();
            std::env::temp_dir().join(format!("praefectus-{random_id:016x}"))
        })
        .clone()
}

#[cfg(not(windows))]
fn observation_root() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(fallback_temp_dir)
}

#[cfg(windows)]
fn observation_root() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(fallback_temp_dir)
}

fn private_observation_path(observation_id: &str) -> Result<PathBuf, ProtocolError> {
    if !is_hash(observation_id) {
        return Err(ProtocolError::InvalidRequest(
            "invalid observation ID".to_string(),
        ));
    }
    Ok(observation_root()
        .join("praefectus")
        .join("observations")
        .join(format!("semantic-{observation_id}.json")))
}

fn private_storage_available() -> bool {
    ensure_directory(
        &observation_root().join("praefectus").join("observations"),
        true,
    )
    .is_ok()
}

pub(crate) fn persist_private_observation(
    observation_id: &str,
    observation: &impl Serialize,
) -> Result<(), ProtocolError> {
    persist_observation(&private_observation_path(observation_id)?, observation)
}

pub(crate) fn load_private_observation<T: serde::de::DeserializeOwned>(
    observation_id: &str,
) -> Result<T, ProtocolError> {
    let path = private_observation_path(observation_id)?;
    #[cfg(windows)]
    let _path_guard = windows_acl::lock_path(&path)?;
    let file = private_open_options().read(true).open(path).map_err(|_| {
        ProtocolError::StaleTarget("semantic observation is unavailable".to_string())
    })?;
    restrict_file(&file)?;
    serde_json::from_reader(file)
        .map_err(|_| ProtocolError::StaleTarget("semantic observation is invalid".to_string()))
}

fn semantic_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_protocol_snapshot_id(snapshot_id: &str) -> bool {
    !snapshot_id.is_empty()
        && snapshot_id.len() <= 256
        && snapshot_id.chars().all(|character| !character.is_control())
}

fn valid_native_snapshot_id(snapshot_id: &str) -> bool {
    snapshot_id.len() <= 256
        && snapshot_id.starts_with("native-")
        && snapshot_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn native_snapshot_id(display_geometry_hash: &str) -> String {
    static OBSERVATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    format!(
        "native-{display_geometry_hash}-{}-{}-{}",
        std::process::id(),
        now_ms(),
        OBSERVATION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(target_os = "macos")]
fn next_semantic_generation() -> u64 {
    static SEMANTIC_GENERATION: AtomicU64 = AtomicU64::new(1);

    SEMANTIC_GENERATION.fetch_add(1, Ordering::Relaxed)
}

#[cfg(target_os = "macos")]
fn semantic_protocol_error(error: semantic::SemanticError) -> ProtocolError {
    match error {
        semantic::SemanticError::StaleObservation | semantic::SemanticError::StaleTarget => {
            ProtocolError::StaleTarget("semantic observation changed".to_string())
        }
        semantic::SemanticError::TargetNotFound => {
            ProtocolError::TargetNotFound("semantic target not found".to_string())
        }
        semantic::SemanticError::AmbiguousTarget => {
            ProtocolError::StaleTarget("semantic target is ambiguous".to_string())
        }
        semantic::SemanticError::TargetNotActionable => {
            ProtocolError::StaleTarget("semantic target is not actionable".to_string())
        }
        semantic::SemanticError::InvalidObservation
        | semantic::SemanticError::UnsupportedAction => {
            ProtocolError::InvalidRequest("invalid semantic target".to_string())
        }
    }
}

#[cfg(target_os = "windows")]
fn semantic_target_observation(
    target: &semantic::SemanticTargetRef,
    element: &semantic::SemanticElement,
    value_hash: Option<&str>,
    capabilities: &Capabilities,
) -> Result<Observation, ProtocolError> {
    let state = serde_json::json!({
        "visible": element.actionability.visible,
        "enabled": element.actionability.enabled,
        "stable": element.actionability.stable,
        "invokable": element.actionability.invokable,
        "editable": element.actionability.editable,
        "value_hash": value_hash,
    });
    Ok(Observation {
        evidence: Evidence {
            observation_hash: hash_serializable(&(
                &capabilities.display_geometry_hash,
                &target.fingerprint_hash,
                &state,
            ))?,
            target_fingerprint_hash: Some(target.fingerprint_hash.clone()),
            display_geometry_hash: capabilities.display_geometry_hash.clone(),
            observed_at_ms: now_ms(),
        },
        element: None,
        state,
    })
}

fn persist_coordinate_observation(
    observation: &CoordinateObservation,
) -> Result<(), ProtocolError> {
    let path = coordinate_observation_path(&observation.snapshot_id)?;
    persist_observation(&path, observation)
}

#[cfg(target_os = "macos")]
fn persist_element_observations(
    observation_id: &str,
    elements: &[ElementObservation],
) -> Result<(), ProtocolError> {
    persist_private_observation(
        observation_id,
        &ElementObservations {
            protocol_version: PROTOCOL_VERSION,
            observation_id: observation_id.to_string(),
            elements: elements.to_vec(),
        },
    )
}

fn persist_observation(path: &Path, observation: &impl Serialize) -> Result<(), ProtocolError> {
    require_private_storage()?;
    let parent = path
        .parent()
        .ok_or_else(|| ProtocolError::InvalidRequest("invalid observation path".to_string()))?;
    ensure_directory(parent, true)?;
    #[cfg(windows)]
    let _path_guard = windows_acl::lock_path(parent)?;
    let temporary = path.with_extension("tmp");
    let mut file = private_open_options()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    restrict_file(&file)?;
    serde_json::to_writer(&mut file, observation)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    #[cfg(not(windows))]
    std::fs::rename(&temporary, path)?;
    #[cfg(windows)]
    windows_acl::replace_file_durable(&temporary, path)?;
    sync_parent(path)
}

fn load_coordinate_observation(snapshot_id: &str) -> Result<CoordinateObservation, ProtocolError> {
    let path = coordinate_observation_path(snapshot_id)?;
    #[cfg(windows)]
    let _path_guard = windows_acl::lock_path(&path)?;
    let file = private_open_options().read(true).open(path).map_err(|_| {
        ProtocolError::StaleTarget("coordinate observation is unavailable".to_string())
    })?;
    restrict_file(&file)?;
    serde_json::from_reader(file)
        .map_err(|_| ProtocolError::StaleTarget("coordinate observation is invalid".to_string()))
}

#[cfg(target_os = "macos")]
fn load_element_observation(
    observation_id: &str,
    element_id: &str,
) -> Result<ElementObservation, ProtocolError> {
    let observations: ElementObservations = load_private_observation(observation_id)?;
    if observations.protocol_version != PROTOCOL_VERSION
        || observations.observation_id != observation_id
    {
        return Err(ProtocolError::StaleTarget(
            "element observation is invalid".to_string(),
        ));
    }
    let mut matches = observations
        .elements
        .into_iter()
        .filter(|element| element.target.element_id == element_id);
    let observation = matches
        .next()
        .ok_or_else(|| ProtocolError::TargetNotFound("target not found".to_string()))?;
    if matches.next().is_some() {
        return Err(ProtocolError::StaleTarget(
            "semantic target is ambiguous".to_string(),
        ));
    }
    Ok(observation)
}

fn ensure_directory(path: &Path, restrict_existing: bool) -> Result<(), ProtocolError> {
    require_private_storage()?;
    let directory = if path.as_os_str().is_empty() {
        std::env::current_dir()?
    } else {
        path.to_path_buf()
    };
    #[cfg(windows)]
    if windows_acl::validate_directory(&directory, true).is_ok() {
        return Ok(());
    }
    #[cfg(windows)]
    let _initialization = windows_acl::initialization_lock()?;
    #[cfg(windows)]
    if windows_acl::validate_directory(&directory, true).is_ok() {
        return Ok(());
    }
    #[cfg(windows)]
    let mut windows_guards = vec![windows_acl::lock_path(&directory)?];
    let mut missing = Vec::new();
    let mut current = Some(directory.as_path());
    while let Some(candidate) = current {
        if candidate.as_os_str().is_empty() {
            break;
        }
        match std::fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProtocolError::Io(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "Praefectus state directory is not private",
                    )));
                }
                validate_private_directory(candidate, &metadata, candidate == directory)?;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(candidate.to_path_buf());
                current = candidate.parent();
            }
            Err(error) => return Err(error.into()),
        }
    }
    #[cfg(not(windows))]
    std::fs::create_dir_all(&directory)?;
    #[cfg(windows)]
    for directory in missing.iter().rev() {
        match std::fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        windows_guards.push(windows_acl::lock_path(directory)?);
    }
    for directory in missing.iter().rev() {
        restrict_directory(directory)?;
        sync_parent(directory)?;
    }
    if restrict_existing && missing.is_empty() {
        restrict_directory(&directory)?;
    }
    Ok(())
}

#[cfg(unix)]
fn private_open_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    options
}

#[cfg(windows)]
fn private_open_options() -> OpenOptions {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    };

    let mut options = OpenOptions::new();
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_WRITE_THROUGH.0);
    options
}

#[cfg(not(any(unix, windows)))]
fn private_open_options() -> OpenOptions {
    OpenOptions::new()
}

#[cfg(unix)]
fn validate_private_directory(
    _path: &Path,
    metadata: &std::fs::Metadata,
    _strict: bool,
) -> Result<(), ProtocolError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Praefectus state directory is not private",
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_directory(
    path: &Path,
    _metadata: &std::fs::Metadata,
    strict: bool,
) -> Result<(), ProtocolError> {
    windows_acl::validate_directory(path, strict)?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_private_directory(
    _path: &Path,
    _metadata: &std::fs::Metadata,
    _strict: bool,
) -> Result<(), ProtocolError> {
    Ok(())
}

#[cfg(not(windows))]
fn require_private_storage() -> Result<(), ProtocolError> {
    Ok(())
}

#[cfg(windows)]
fn require_private_storage() -> Result<(), ProtocolError> {
    if !windows_acl::available() {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private Praefectus state is unavailable on this platform",
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), ProtocolError> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(windows)]
fn sync_parent(path: &Path) -> Result<(), ProtocolError> {
    if let Some(parent) = path.parent() {
        windows_acl::sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent(_path: &Path) -> Result<(), ProtocolError> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(file: &File) -> Result<(), ProtocolError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), ProtocolError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_file(file: &File) -> Result<(), ProtocolError> {
    windows_acl::restrict_file(file)?;
    Ok(())
}

#[cfg(windows)]
fn restrict_directory(path: &Path) -> Result<(), ProtocolError> {
    windows_acl::restrict_directory(path)?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn restrict_file(_file: &File) -> Result<(), ProtocolError> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn restrict_directory(_path: &Path) -> Result<(), ProtocolError> {
    Ok(())
}

fn empty_receipt(
    request: &ActionRequest,
    action_hash: &str,
    effect: Effect,
    session_isolation: SessionIsolation,
) -> Receipt {
    Receipt {
        protocol_version: PROTOCOL_VERSION,
        action_name: request.action.name().to_string(),
        action_hash: action_hash.to_string(),
        started_at_ms: now_ms(),
        finished_at_ms: now_ms(),
        backend: "unknown".to_string(),
        fallback_chain: Vec::new(),
        delivery_route: request_delivery_route(&request.action, &request.target),
        session_isolation,
        interaction_mode: request.interaction_mode,
        context_preservation: recovered_context_preservation(
            request.interaction_mode,
            session_isolation,
        ),
        effect,
        before: None,
        after: None,
        warnings: Vec::new(),
    }
}

fn recovered_context_preservation(
    interaction_mode: InteractionMode,
    session_isolation: SessionIsolation,
) -> ContextPreservation {
    match (interaction_mode, session_isolation) {
        (InteractionMode::Interactive, _) => ContextPreservation::NotApplicable,
        (InteractionMode::BackgroundOnly, SessionIsolation::HostIsolated) => {
            ContextPreservation::HostIsolated
        }
        _ => ContextPreservation::Unavailable,
    }
}

fn ack(
    request: &ActionRequest,
    action_hash: &str,
    sequence: u32,
    state: AckState,
    replayed: bool,
) -> ActionAck {
    ActionAck {
        protocol_version: PROTOCOL_VERSION,
        operation_id: request.operation_id.clone(),
        sequence,
        action_hash: action_hash.to_string(),
        replayed,
        state,
    }
}

fn terminal_ack(
    request: &ActionRequest,
    action_hash: &str,
    terminal: Terminal,
    replayed: bool,
) -> ActionAck {
    ack(
        request,
        action_hash,
        2,
        AckState::Terminal {
            terminal: Box::new(terminal),
        },
        replayed,
    )
}

fn hash_value(value: &Value) -> Result<String, ProtocolError> {
    hash_serializable(value)
}

pub fn canonical_authority_bytes(grant: &AuthorityGrant) -> Result<Vec<u8>, ProtocolError> {
    canonical_json_bytes(grant)
}

pub(crate) fn hash_serializable(value: &impl Serialize) -> Result<String, ProtocolError> {
    Ok(hash_bytes(&canonical_json_bytes(value)?))
}

fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>, ProtocolError> {
    let mut value = serde_json::to_value(value)?;
    canonicalize_json(&mut value);
    serde_json::to_vec(&value).map_err(ProtocolError::from)
}

fn canonicalize_json(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(canonicalize_json),
        Value::Object(values) => {
            let mut entries = std::mem::take(values).into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, mut value) in entries {
                canonicalize_json(&mut value);
                values.insert(key, value);
            }
        }
        _ => {}
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

#[cfg(not(windows))]
pub fn default_ledger_path() -> PathBuf {
    Path::new("praefectus-operations.jsonl").to_path_buf()
}

#[cfg(windows)]
pub fn default_ledger_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(fallback_temp_dir)
        .join("praefectus")
        .join("praefectus-operations.jsonl")
}

#[cfg(test)]
mod tests {
    use super::{
        AckState, Action, ActionAck, ActionRequest, AuthorityGrant, CancellationToken,
        ContextPreservation, DeliveryRoute, Effect, EffectKnowledge, Evidence, Executor,
        FailureCode, InteractionMode, MouseButton, NativeBounds, NativeElement, NativeExecutor,
        NativePoint, Observation, OperationLedger, PROTOCOL_VERSION, Receipt, ResolvedTarget,
        SafetyClass, SessionIsolation, SignedAuthority, TargetRef, Terminal, VerificationPolicy,
        canonical_authority_bytes, default_ledger_path, native_snapshot_id, target_capture_bounds,
        validate_matching_live_element, verify,
    };

    #[test]
    fn test_default_ledger_path() {
        let path = default_ledger_path();
        assert!(path.ends_with("praefectus-operations.jsonl"));

        #[cfg(windows)]
        {
            // On Windows, the path should contain "praefectus" before the filename
            let parent = path.parent().unwrap();
            assert_eq!(parent.file_name().unwrap(), "praefectus");
        }
    }

    #[test]
    fn authority_bytes_have_stable_key_order() {
        let grant = AuthorityGrant {
            protocol_version: PROTOCOL_VERSION,
            issuer: "host".to_string(),
            key_id: "key".to_string(),
            operation_id: "operation".to_string(),
            subject: "subject".to_string(),
            session_id: "session".to_string(),
            risk: SafetyClass::Reversible,
            expires_at_ms: 1,
            policy_generation: "generation".to_string(),
            action_hash: "0".repeat(64),
        };
        let value = String::from_utf8(canonical_authority_bytes(&grant).unwrap()).unwrap();
        assert_eq!(
            value,
            format!(
                "{{\"action_hash\":\"{}\",\"expires_at_ms\":1,\"issuer\":\"host\",\"key_id\":\"key\",\"operation_id\":\"operation\",\"policy_generation\":\"generation\",\"protocol_version\":2,\"risk\":\"reversible\",\"session_id\":\"session\",\"subject\":\"subject\"}}",
                "0".repeat(64)
            )
        );
    }

    #[test]
    fn protocol_debug_output_redacts_actions_and_authority() {
        let authority = SignedAuthority {
            grant: AuthorityGrant {
                protocol_version: PROTOCOL_VERSION,
                issuer: "secret-issuer".to_string(),
                key_id: "secret-key".to_string(),
                operation_id: "operation".to_string(),
                subject: "secret-subject".to_string(),
                session_id: "secret-session".to_string(),
                risk: SafetyClass::Reversible,
                expires_at_ms: 2,
                policy_generation: "secret-policy".to_string(),
                action_hash: "a".repeat(64),
            },
            signature: "secret-signature".to_string(),
        };
        let request = ActionRequest {
            protocol_version: PROTOCOL_VERSION,
            action_version: 1,
            target_version: 1,
            verification_version: 1,
            operation_id: "operation".to_string(),
            subject: "secret-subject".to_string(),
            session_id: "secret-session".to_string(),
            authority: authority.clone(),
            action: Action::TypeText {
                text: "secret-text".to_string(),
                clear: true,
                press_return: false,
                delay_ms: None,
            },
            target: TargetRef::None,
            interaction_mode: InteractionMode::Interactive,
            deadline_at_ms: 2,
            verification: VerificationPolicy::TargetState {
                expected: serde_json::json!({"value": "secret-state"}),
            },
            safety: SafetyClass::Reversible,
        };
        let outputs = [
            format!("{authority:?}"),
            format!("{request:?}"),
            format!(
                "{:?}",
                Action::Paste {
                    text: "secret-paste".to_string(),
                }
            ),
            format!(
                "{:?}",
                Action::SetValue {
                    value: "secret-value".to_string(),
                }
            ),
            format!(
                "{:?}",
                Action::Press {
                    key: "secret-keypress".to_string(),
                    count: 1,
                    delay_ms: None,
                }
            ),
            format!(
                "{:?}",
                Action::Hotkey {
                    keys: vec!["secret-hotkey".to_string()],
                }
            ),
        ];
        for output in outputs {
            assert!(output.contains("[redacted]"));
            assert!(!output.contains("secret-"));
        }
    }

    #[test]
    fn native_snapshot_ids_are_unique() {
        let geometry_hash = "0".repeat(64);
        assert_ne!(
            native_snapshot_id(&geometry_hash),
            native_snapshot_id(&geometry_hash)
        );
    }

    #[test]
    fn target_capture_is_bounded_to_its_display() {
        let display = NativeBounds {
            x: 100,
            y: 50,
            width: 200,
            height: 100,
        };
        assert_eq!(
            target_capture_bounds(&display, &NativePoint { x: 100, y: 50 }).map(|bounds| (
                bounds.x,
                bounds.y,
                bounds.width,
                bounds.height
            )),
            Some((100, 50, 64, 64))
        );
        assert!(target_capture_bounds(&display, &NativePoint { x: 300, y: 50 }).is_none());
    }

    #[test]
    fn matching_live_element_must_remain_enabled_and_visible() {
        let expected = NativeElement {
            backend: "test".to_string(),
            id: "element".to_string(),
            app: "app".to_string(),
            process_id: Some(1),
            window: Some("window".to_string()),
            role: "button".to_string(),
            label: Some("label".to_string()),
            title: None,
            bounds: Some(NativeBounds {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            }),
            state: serde_json::json!({"visible": true, "hidden": false}),
            enabled: Some(true),
        };
        let mut current = expected.clone();
        current.enabled = Some(false);
        assert!(validate_matching_live_element(&current, &expected).is_err());
        current.enabled = Some(true);
        current.state = serde_json::json!({"visible": false, "hidden": true});
        assert!(validate_matching_live_element(&current, &expected).is_err());
    }

    #[test]
    fn repeated_semantic_click_is_rejected_before_effect() {
        let target = ResolvedTarget::Element(Box::new(NativeElement {
            backend: "test".to_string(),
            id: "element".to_string(),
            app: "app".to_string(),
            process_id: Some(1),
            window: Some("window".to_string()),
            role: "button".to_string(),
            label: Some("Button".to_string()),
            title: None,
            bounds: Some(NativeBounds {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            }),
            state: serde_json::json!({"visible": true, "hidden": false}),
            enabled: Some(true),
        }));
        let error = NativeExecutor::default()
            .dispatch(
                &Action::Click {
                    button: MouseButton::Left,
                    count: 2,
                    allow_coordinate_fallback: false,
                },
                &target,
                &VerificationPolicy::None,
                &CancellationToken::default(),
                i64::MAX,
            )
            .unwrap_err();

        assert_eq!(error.effect, EffectKnowledge::NoEffect);
        assert!(matches!(error.code, FailureCode::Unsupported));
    }

    #[test]
    fn effectful_terminal_persistence_failure_is_outcome_unknown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ledger.jsonl");
        std::fs::create_dir(&path).unwrap();
        let ledger = OperationLedger::new(path);
        let acknowledgement = ActionAck {
            protocol_version: PROTOCOL_VERSION,
            operation_id: "operation".to_string(),
            sequence: 2,
            action_hash: "0".repeat(64),
            replayed: false,
            state: AckState::Terminal {
                terminal: Box::new(Terminal::Succeeded {
                    receipt: Receipt {
                        protocol_version: PROTOCOL_VERSION,
                        action_name: "click".to_string(),
                        action_hash: "0".repeat(64),
                        started_at_ms: 1,
                        finished_at_ms: 2,
                        backend: "test".to_string(),
                        fallback_chain: Vec::new(),
                        delivery_route: DeliveryRoute::Pointer,
                        session_isolation: SessionIsolation::SharedDesktop,
                        interaction_mode: InteractionMode::Interactive,
                        context_preservation: ContextPreservation::NotApplicable,
                        effect: Effect::Verified,
                        before: None,
                        after: None,
                        warnings: Vec::new(),
                    },
                }),
            },
        };

        let mut settled = ledger.finish_after_effect(acknowledgement);

        assert!(matches!(
            &settled.state,
            AckState::Terminal { terminal }
                if matches!(&**terminal, Terminal::OutcomeUnknown { receipt, .. }
                    if receipt.effect == Effect::Verified)
        ));
        if let AckState::Terminal { terminal } = &mut settled.state
            && let Terminal::OutcomeUnknown { message, .. } = &mut **terminal
        {
            *message = "classified outcome is unknown".to_string();
        }
        let settled = ledger.finish_after_effect(settled);
        assert!(matches!(
            settled.state,
            AckState::Terminal { terminal }
                if matches!(&*terminal, Terminal::OutcomeUnknown { message, .. }
                    if message == "classified outcome is unknown")
        ));
    }

    #[test]
    fn torn_trajectory_tail_is_repaired_before_append() {
        use std::io::Write;

        let directory = tempfile::tempdir().unwrap();
        super::restrict_directory(directory.path()).unwrap();
        let ledger = OperationLedger::new(directory.path().join("ledger.jsonl"));
        let acknowledgement = ActionAck {
            protocol_version: PROTOCOL_VERSION,
            operation_id: "operation".to_string(),
            sequence: 0,
            action_hash: "0".repeat(64),
            replayed: false,
            state: AckState::Accepted,
        };
        ledger.trajectory(&acknowledgement).unwrap();
        let path = ledger.path.with_extension("trajectory.jsonl");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"{\"protocol_version\":").unwrap();
        file.sync_all().unwrap();
        drop(file);

        ledger.trajectory(&acknowledgement).unwrap();

        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.ends_with('\n'));
        assert_eq!(contents.lines().count(), 2);
        assert!(
            contents
                .lines()
                .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
        );
    }

    #[test]
    fn terminated_invalid_ledger_tail_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        super::restrict_directory(directory.path()).unwrap();
        let ledger = OperationLedger::new(directory.path().join("ledger.jsonl"));
        std::fs::write(&ledger.path, b"{\"kind\":\"claim\"\n").unwrap();

        assert!(matches!(
            ledger.repair_tail(),
            Err(super::ProtocolError::InvalidRequest(_))
        ));
        assert_eq!(
            std::fs::read(&ledger.path).unwrap(),
            b"{\"kind\":\"claim\"\n"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_actionability_requires_stable_targeted_routing() {
        let action = Action::Invoke;
        let mut actionability = super::semantic::Actionability {
            visible: true,
            enabled: true,
            unambiguous: true,
            stable: true,
            receives_events: false,
            invokable: true,
            editable: true,
        };
        assert!(super::mac_actionability_allows(&action, &actionability));
        assert!(super::mac_actionability_matches_observation(
            &action,
            &actionability,
            &actionability
        ));
        let mut changed = actionability;
        changed.receives_events = true;
        assert!(!super::mac_actionability_matches_observation(
            &action,
            &actionability,
            &changed
        ));
        actionability.invokable = false;
        assert!(!super::mac_actionability_allows(&action, &actionability));
        actionability.invokable = true;
        actionability.stable = false;
        assert!(!super::mac_actionability_allows(
            &Action::SetValue {
                value: "value".to_string()
            },
            &actionability
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_observation_errors_preserve_request_boundary() {
        let active = CancellationToken::default();
        assert!(matches!(
            super::mac_observation_error(
                &active,
                super::now_ms().saturating_add(1_000),
                super::ProtocolError::StaleTarget("changed".to_string())
            ),
            super::ProtocolError::StaleTarget(_)
        ));

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(matches!(
            super::mac_observation_error(
                &cancelled,
                super::now_ms(),
                super::ProtocolError::StaleTarget("changed".to_string())
            ),
            super::ProtocolError::ObservationCancelled
        ));

        assert!(matches!(
            super::mac_observation_error(
                &active,
                super::now_ms(),
                super::ProtocolError::StaleTarget("changed".to_string())
            ),
            super::ProtocolError::ObservationExpired
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_string_arrays_reject_non_string_members() {
        use core_foundation::array::CFArray;
        use core_foundation::base::{CFType, TCFType};
        use core_foundation::number::CFNumber;
        use core_foundation::string::CFString;

        let valid = CFArray::<CFType>::from_CFTypes(&[CFString::new("AXPress").as_CFType()]);
        assert_eq!(
            super::mac_bounded_string_array(valid.into_untyped(), 1, 128, 512).unwrap(),
            vec!["AXPress"]
        );

        let invalid = CFArray::<CFType>::from_CFTypes(&[CFNumber::from(1).as_CFType()]);
        assert!(super::mac_bounded_string_array(invalid.into_untyped(), 1, 128, 512).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn persisted_element_observation_excludes_accessibility_text() {
        let fingerprint = super::ElementFingerprint {
            backend: "backend".to_string(),
            id: "private-identifier".to_string(),
            app: "private-app".to_string(),
            process_id: 1,
            window: "private-window".to_string(),
            role: "button".to_string(),
            label: "private-label".to_string(),
            bounds: Some(super::Rect {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            }),
        };
        let observation = super::ElementObservation {
            protocol_version: PROTOCOL_VERSION,
            target: super::semantic::SemanticTargetRef {
                observation_id: "0".repeat(64),
                generation: 1,
                provenance_hash: "1".repeat(64),
                element_id: "2".repeat(64),
                fingerprint_hash: super::hash_serializable(&fingerprint).unwrap(),
            },
            actionability: super::semantic::Actionability {
                visible: true,
                enabled: true,
                unambiguous: true,
                stable: true,
                receives_events: true,
                invokable: true,
                editable: false,
            },
            process_id: 1,
            process_generation: "generation".to_string(),
            window_id: "window".to_string(),
            path: vec![0, 1],
            backend_id_hash: "3".repeat(64),
            display_geometry_hash: "1".repeat(64),
            element_fingerprint_hash: super::hash_serializable(&fingerprint).unwrap(),
            observed_at_ms: 1,
        };
        let persisted = serde_json::to_string(&observation).unwrap();

        assert!(!persisted.contains("private-"));
    }

    #[test]
    fn target_value_hash_requires_the_same_fenced_target() {
        let evidence = Evidence {
            observation_hash: "observation".to_string(),
            target_fingerprint_hash: Some("1".repeat(64)),
            display_geometry_hash: "2".repeat(64),
            observed_at_ms: 1,
        };
        let before = Observation {
            evidence: evidence.clone(),
            element: None,
            state: serde_json::json!({"value_hash": "3".repeat(64)}),
        };
        let after = Observation {
            evidence,
            element: None,
            state: serde_json::json!({"value_hash": "4".repeat(64)}),
        };
        assert_eq!(
            verify(
                &VerificationPolicy::TargetValueHash {
                    sha256: "4".repeat(64),
                },
                &before,
                Some(&after),
                Some(&"1".repeat(64)),
            )
            .0,
            Effect::Verified
        );
        let mut replaced = after;
        replaced.evidence.target_fingerprint_hash = Some("5".repeat(64));
        assert_eq!(
            verify(
                &VerificationPolicy::TargetValueHash {
                    sha256: "4".repeat(64),
                },
                &before,
                Some(&replaced),
                Some(&"1".repeat(64)),
            )
            .0,
            Effect::ExecutedUnverified
        );
    }
}
