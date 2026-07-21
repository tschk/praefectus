use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
const MAX_COORDINATE_OBSERVATION_AGE_MS: i64 = 30_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    pub protocol_version: u16,
    pub action_version: u16,
    pub target_version: u16,
    pub operation_id: String,
    pub subject: String,
    pub session_id: String,
    pub authority: SignedAuthority,
    pub action: Action,
    pub target: TargetRef,
    pub deadline_at_ms: i64,
    pub verification: VerificationPolicy,
    pub safety: SafetyClass,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthority {
    pub grant: AuthorityGrant,
    pub signature: String,
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
        selector: String,
        snapshot_id: String,
        element_fingerprint: ElementFingerprint,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
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

impl Action {
    fn requires_target(&self) -> bool {
        matches!(
            self,
            Self::Click { .. } | Self::Move | Self::SetValue { .. }
        )
    }

    fn name(&self) -> &'static str {
        match self {
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
    pub effect: Effect,
    pub before: Option<Evidence>,
    pub after: Option<Evidence>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
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
    pub supported_actions: Vec<String>,
    pub permissions: BTreeMap<String, bool>,
    pub display_geometry_hash: String,
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
struct ElementObservation {
    protocol_version: u16,
    snapshot_id: String,
    selector_hash: String,
    display_geometry_hash: String,
    element_fingerprint: ElementFingerprint,
    observed_at_ms: i64,
}

#[derive(Clone, Debug)]
pub enum ResolvedTarget {
    Point(NativePoint),
    Element(Box<NativeElement>),
    None,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativePoint {
    pub x: i64,
    pub y: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

impl NativeRuntime {
    fn new() -> Self {
        Self
    }

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

    fn resolve_selector(
        &self,
        selector: &str,
        _snapshot: Option<&str>,
    ) -> Result<NativeElement, NativeError> {
        native_resolve_selector(selector)
    }

    fn click_with_options(
        &self,
        target: Target,
        button: &str,
        _background: bool,
    ) -> Result<(), NativeError> {
        match target {
            Target::Point(point) => native_click(&point, button),
            Target::Element(element) if button == "left" => native_element_press(&element),
            Target::Element(_) => Err(NativeError),
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
        Err(NativeError)
    }

    fn press(&self, _key: &str, _count: u32, _delay_ms: Option<u64>) -> Result<(), NativeError> {
        Err(NativeError)
    }

    fn paste(&self, _text: &str) -> Result<(), NativeError> {
        Err(NativeError)
    }

    fn hotkey(&self, _keys: &[&str]) -> Result<(), NativeError> {
        Err(NativeError)
    }

    fn scroll(&self, _direction: Direction, _amount: u32) -> Result<(), NativeError> {
        Err(NativeError)
    }

    fn set_value(&self, target: Target, value: &str) -> Result<(), NativeError> {
        match target {
            Target::Element(element) => native_element_set_value(&element, value),
            Target::Point(_) => Err(NativeError),
        }
    }
}

fn native_backend() -> &'static str {
    match std::env::consts::OS {
        "macos" => "praefectus-coregraphics",
        "windows" => "praefectus-unavailable-windows",
        "linux" => "praefectus-unavailable-linux",
        _ => "praefectus-unavailable",
    }
}

fn native_permissions() -> Value {
    native_platform_permissions()
}

#[cfg(target_os = "macos")]
fn native_platform_permissions() -> Value {
    serde_json::json!({
        "accessibility": unsafe { accessibility_sys::AXIsProcessTrusted() },
        "screen_recording": core_graphics::access::ScreenCaptureAccess.preflight(),
        "private_state": true,
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn native_platform_permissions() -> Value {
    serde_json::json!({"accessibility": false, "screen_recording": false, "private_state": true})
}

#[cfg(windows)]
fn native_platform_permissions() -> Value {
    serde_json::json!({"accessibility": false, "screen_recording": false, "private_state": false})
}

#[cfg(not(any(unix, windows)))]
fn native_platform_permissions() -> Value {
    serde_json::json!({"accessibility": false, "screen_recording": false, "private_state": false})
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
    #[cfg(not(target_os = "macos"))]
    Ok(Value::Array(Vec::new()))
}

fn native_screen_content_hash() -> Result<String, NativeError> {
    #[cfg(target_os = "macos")]
    {
        use core_graphics::display::CGDisplay;

        if !native_permissions()
            .get("screen_recording")
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
    #[cfg(not(target_os = "macos"))]
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
            .get("screen_recording")
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
    #[cfg(not(target_os = "macos"))]
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
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| NativeError)?;
        let event = CGEvent::new_mouse_event(source, down, position, mouse_button)
            .map_err(|_| NativeError)?;
        event.post(CGEventTapLocation::HID);
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| NativeError)?;
        let event = CGEvent::new_mouse_event(source, up, position, mouse_button)
            .map_err(|_| NativeError)?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
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
    #[cfg(not(target_os = "macos"))]
    {
        let _ = point;
        Err(NativeError)
    }
}

fn selector_point(selector: &str) -> Result<NativePoint, NativeError> {
    let values = selector
        .strip_prefix("macos-ax:")
        .ok_or(NativeError)?
        .split_once(':')
        .ok_or(NativeError)?;
    let x = values.0.parse().map_err(|_| NativeError)?;
    let y = values.1.parse().map_err(|_| NativeError)?;
    Ok(NativePoint { x, y })
}

fn native_resolve_selector(selector: &str) -> Result<NativeElement, NativeError> {
    let point = selector_point(selector)?;
    native_element_at(&point)
}

#[cfg(target_os = "macos")]
struct AxElement(accessibility_sys::AXUIElementRef);

#[cfg(target_os = "macos")]
impl AxElement {
    fn created(raw: accessibility_sys::AXUIElementRef) -> Result<Self, NativeError> {
        if raw.is_null() {
            Err(NativeError)
        } else {
            Ok(Self(raw))
        }
    }

    fn attribute(&self, name: &str) -> Result<core_foundation::base::CFType, NativeError> {
        use accessibility_sys::{AXUIElementCopyAttributeValue, kAXErrorSuccess};
        use core_foundation::base::{CFType, TCFType};
        use core_foundation::string::CFString;
        use std::ptr;

        let key = CFString::new(name);
        let mut raw: core_foundation::base::CFTypeRef = ptr::null();
        if unsafe { AXUIElementCopyAttributeValue(self.0, key.as_concrete_TypeRef(), &mut raw) }
            != kAXErrorSuccess
            || raw.is_null()
        {
            return Err(NativeError);
        }
        Ok(unsafe { CFType::wrap_under_create_rule(raw) })
    }

    fn string(&self, name: &str) -> Option<String> {
        use core_foundation::string::CFString;

        self.attribute(name)
            .ok()?
            .downcast::<CFString>()
            .map(|value| value.to_string())
    }

    fn boolean(&self, name: &str) -> Option<bool> {
        use core_foundation::boolean::CFBoolean;

        self.attribute(name)
            .ok()?
            .downcast::<CFBoolean>()
            .map(bool::from)
    }

    fn element(&self, name: &str) -> Result<Self, NativeError> {
        use accessibility_sys::AXUIElementGetTypeID;
        use core_foundation::base::{CFGetTypeID, CFRetain, TCFType};

        let value = self.attribute(name)?;
        let raw = value.as_CFTypeRef();
        if unsafe { CFGetTypeID(raw) } != unsafe { AXUIElementGetTypeID() } {
            return Err(NativeError);
        }
        unsafe { CFRetain(raw) };
        Self::created(raw.cast_mut().cast())
    }
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
fn native_element_at(point: &NativePoint) -> Result<NativeElement, NativeError> {
    mac_native_element(&mac_ax_element_at(point)?)
}

#[cfg(target_os = "macos")]
fn mac_native_element(element: &AxElement) -> Result<NativeElement, NativeError> {
    use accessibility_sys::{AXUIElementCreateApplication, AXUIElementGetPid, kAXErrorSuccess};

    let mut process_id = 0;
    if unsafe { AXUIElementGetPid(element.0, &mut process_id) } != kAXErrorSuccess
        || process_id <= 0
    {
        return Err(NativeError);
    }
    let bounds = mac_ax_bounds(element)?;
    let role = element.string("AXRole").ok_or(NativeError)?;
    let title = element.string("AXTitle");
    let label = element
        .string("AXDescription")
        .filter(|value| !value.is_empty())
        .or_else(|| title.clone());
    let identifier = element
        .string("AXIdentifier")
        .filter(|value| !value.is_empty())
        .ok_or(NativeError)?;
    let enabled = element.boolean("AXEnabled");
    let focused = element.boolean("AXFocused");
    let window = element
        .element("AXWindow")
        .or_else(|_| element.element("AXTopLevelUIElement"))?;
    let minimized = window.boolean("AXMinimized").unwrap_or(false);
    let window_title = window
        .string("AXTitle")
        .filter(|value| !value.is_empty())
        .ok_or(NativeError)?;
    let window_identifier = window
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
        .ok_or(NativeError)?;
    let process_generation = mac_process_generation(process_id)?;
    let window_identity = format!("{process_generation}:{window_identifier}:{window_title}");
    let app = AxElement::created(unsafe { AXUIElementCreateApplication(process_id) })?
        .string("AXTitle")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("pid-{process_id}"));
    let value = element
        .string("AXValue")
        .map(Value::String)
        .unwrap_or(Value::Null);
    let visible = !minimized
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
            "value": value,
        }),
        enabled,
    })
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

#[cfg(not(target_os = "macos"))]
fn native_element_at(_point: &NativePoint) -> Result<NativeElement, NativeError> {
    Err(NativeError)
}

fn native_element_press(expected: &NativeElement) -> Result<(), NativeError> {
    #[cfg(target_os = "macos")]
    {
        use accessibility_sys::{AXUIElementPerformAction, kAXErrorSuccess};
        use core_foundation::base::TCFType;
        use core_foundation::string::CFString;

        let bounds = expected.bounds.as_ref().ok_or(NativeError)?;
        let point = NativePoint {
            x: bounds.x.saturating_add(bounds.width / 2),
            y: bounds.y.saturating_add(bounds.height / 2),
        };
        let element = mac_ax_element_at(&point)?;
        let current = mac_native_element(&element)?;
        if ElementFingerprint::from(&current) != ElementFingerprint::from(expected) {
            return Err(NativeError);
        }
        let action = CFString::new("AXPress");
        if unsafe { AXUIElementPerformAction(element.0, action.as_concrete_TypeRef()) }
            == kAXErrorSuccess
        {
            Ok(())
        } else {
            Err(NativeError)
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = expected;
        Err(NativeError)
    }
}

fn native_element_set_value(expected: &NativeElement, value: &str) -> Result<(), NativeError> {
    #[cfg(target_os = "macos")]
    {
        use accessibility_sys::{AXUIElementSetAttributeValue, kAXErrorSuccess};
        use core_foundation::base::TCFType;
        use core_foundation::string::CFString;

        let bounds = expected.bounds.as_ref().ok_or(NativeError)?;
        let point = NativePoint {
            x: bounds.x.saturating_add(bounds.width / 2),
            y: bounds.y.saturating_add(bounds.height / 2),
        };
        let element = mac_ax_element_at(&point)?;
        let current = mac_native_element(&element)?;
        if ElementFingerprint::from(&current) != ElementFingerprint::from(expected) {
            return Err(NativeError);
        }
        let attribute = CFString::new("AXValue");
        let value = CFString::new(value);
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
            Err(NativeError)
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (expected, value);
        Err(NativeError)
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
    fn observe(&self, target: &TargetRef) -> Result<Observation, ProtocolError>;
    fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, ProtocolError>;
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
    pub fn new(keys: impl IntoIterator<Item = (String, String, String, VerifyingKey)>) -> Self {
        Self {
            issuers: keys
                .into_iter()
                .map(|(issuer, key_id, policy_generation, key)| {
                    ((issuer, key_id), (policy_generation, key))
                })
                .collect(),
        }
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
        let _operation_guard = self.ledger.execution_lock()?;
        self.ledger.repair_tail()?;
        match self.ledger.claim(request, &action_hash)? {
            ClaimResult::Replay(mut acknowledgement) => {
                acknowledgement.replayed = true;
                return Ok(ExecuteReport {
                    acknowledgements: vec![*acknowledgement],
                });
            }
            ClaimResult::RecoveredUnknown => {
                let receipt = empty_receipt(request, &action_hash, Effect::Unknown);
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

        let before = match self.executor.observe(&request.target) {
            Ok(observation) => observation,
            Err(error) => {
                let terminal = protocol_failure(error);
                return self.finish_early(request, &action_hash, terminal);
            }
        };
        let resolved = match self.executor.resolve(&request.target) {
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

        let started_at_ms = now_ms();
        let dispatched = self.executor.dispatch(
            &request.action,
            &resolved,
            &request.verification,
            cancellation,
            effect_deadline_at_ms,
        );
        let terminal = match dispatched {
            Ok(dispatch) => {
                let after = self.executor.observe(&request.target);
                let (effect, warnings) =
                    verify(&request.verification, &before, after.as_ref().ok());
                let receipt = Receipt {
                    protocol_version: PROTOCOL_VERSION,
                    action_name: request.action.name().to_string(),
                    action_hash: action_hash.clone(),
                    started_at_ms,
                    finished_at_ms: now_ms(),
                    backend: dispatch.backend,
                    fallback_chain: dispatch.fallback_chain,
                    effect,
                    before: Some(before.evidence),
                    after: after.ok().map(|value| value.evidence),
                    warnings,
                };
                if matches!(request.verification, VerificationPolicy::None)
                    || matches!(receipt.effect, Effect::Verified)
                {
                    Terminal::Succeeded { receipt }
                } else {
                    Terminal::OutcomeUnknown {
                        receipt,
                        message: "action dispatched but requested verification failed".to_string(),
                    }
                }
            }
            Err(error) if error.effect == EffectKnowledge::Unknown => {
                let mut receipt = empty_receipt(request, &action_hash, Effect::Unknown);
                receipt.started_at_ms = started_at_ms;
                receipt.finished_at_ms = now_ms();
                receipt.before = Some(before.evidence);
                Terminal::OutcomeUnknown {
                    receipt,
                    message: dispatch_message(&error),
                }
            }
            Err(error) if error.effect == EffectKnowledge::CancelledBeforeEffect => {
                Terminal::CancelledBeforeEffect
            }
            Err(error) if error.effect == EffectKnowledge::ExpiredBeforeEffect => {
                Terminal::ExpiredBeforeEffect
            }
            Err(error) => Terminal::Failed {
                code: error.code,
                message: dispatch_message(&error),
            },
        };
        let terminal_ack = terminal_ack(request, &action_hash, terminal, false);
        self.ledger.finish(&terminal_ack)?;
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
        self.ledger.status(operation_id)
    }

    pub fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
        self.executor.capabilities()
    }
}

pub struct NativeExecutor {
    runtime: NativeRuntime,
}

impl Default for NativeExecutor {
    fn default() -> Self {
        Self {
            runtime: NativeRuntime::new(),
        }
    }
}

impl NativeExecutor {
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

    pub fn observe_element_at(&self, x: i64, y: i64) -> Result<TargetRef, ProtocolError> {
        let capabilities = self.capabilities()?;
        if !capabilities
            .permissions
            .get("accessibility")
            .copied()
            .unwrap_or(false)
        {
            return Err(ProtocolError::Executor("desktop backend error".to_string()));
        }
        let selector = format!("macos-ax:{x}:{y}");
        let element = self
            .runtime
            .resolve_selector(&selector, None)
            .map_err(|_| ProtocolError::TargetNotFound("target not found".to_string()))?;
        validate_live_element(&element)?;
        let snapshot_id = native_snapshot_id(&capabilities.display_geometry_hash);
        let element_fingerprint = ElementFingerprint::from(&element);
        persist_element_observation(&ElementObservation {
            protocol_version: PROTOCOL_VERSION,
            snapshot_id: snapshot_id.clone(),
            selector_hash: hash_bytes(selector.as_bytes()),
            display_geometry_hash: capabilities.display_geometry_hash,
            element_fingerprint: element_fingerprint.clone(),
            observed_at_ms: now_ms(),
        })?;
        Ok(TargetRef::Element {
            selector,
            snapshot_id,
            element_fingerprint,
        })
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
    fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
        let permission_value = self.runtime.permissions();
        let permissions: BTreeMap<String, bool> = permission_value
            .as_object()
            .map(|values| {
                values
                    .iter()
                    .filter_map(|(key, value)| value.as_bool().map(|value| (key.clone(), value)))
                    .collect()
            })
            .unwrap_or_default();
        let screens = self
            .runtime
            .list_screens()
            .map_err(|error| ProtocolError::Executor(redact_message(&error.to_string())))?;
        let accessibility = permissions.get("accessibility").copied().unwrap_or(false);
        let screen_recording = permissions
            .get("screen_recording")
            .copied()
            .unwrap_or(false);
        let mut supported_actions = Vec::new();
        if accessibility {
            supported_actions.extend(["click", "set_value"]);
        }
        if accessibility && screen_recording {
            supported_actions.push("move");
        }
        Ok(Capabilities {
            platform: std::env::consts::OS.to_string(),
            backend: self.runtime.resolve_backend().to_string(),
            supported_actions: supported_actions.into_iter().map(str::to_string).collect(),
            permissions,
            display_geometry_hash: hash_value(&screens)?,
        })
    }

    fn observe(&self, target: &TargetRef) -> Result<Observation, ProtocolError> {
        let capabilities = self.capabilities()?;
        let element = match target {
            TargetRef::Element { selector, .. } => {
                let element = self
                    .runtime
                    .resolve_selector(selector, None)
                    .map_err(|_| ProtocolError::TargetNotFound("target not found".to_string()))?;
                validate_live_element(&element)?;
                Some(element)
            }
            _ => None,
        };
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
            .map(|fingerprint| hash_serializable(&fingerprint))
            .transpose()?;
        let observation_hash = hash_serializable(&(
            &capabilities.display_geometry_hash,
            &target_fingerprint_hash,
            &state,
        ))?;
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
            TargetRef::Element {
                selector,
                snapshot_id,
                element_fingerprint,
                ..
            } => {
                let observation = load_element_observation(snapshot_id)?;
                let capabilities = self.capabilities()?;
                if observation.protocol_version != PROTOCOL_VERSION
                    || observation.snapshot_id != *snapshot_id
                    || observation.selector_hash != hash_bytes(selector.as_bytes())
                    || observation.display_geometry_hash != capabilities.display_geometry_hash
                    || observation.element_fingerprint != *element_fingerprint
                    || observation.observed_at_ms > now_ms()
                    || now_ms().saturating_sub(observation.observed_at_ms)
                        > MAX_COORDINATE_OBSERVATION_AGE_MS
                {
                    return Err(ProtocolError::StaleTarget(
                        "element observation provenance does not match".to_string(),
                    ));
                }
                let node = self
                    .runtime
                    .resolve_selector(selector, None)
                    .map_err(|_| ProtocolError::TargetNotFound("target not found".to_string()))?;
                validate_live_element(&node)?;
                if ElementFingerprint::from(&node) != *element_fingerprint {
                    return Err(ProtocolError::StaleTarget(
                        "live element fingerprint changed".to_string(),
                    ));
                }
                Ok(ResolvedTarget::Element(Box::new(node)))
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
            Action::Click { button, count, .. } => {
                if !(1..=3).contains(count) {
                    return Err(no_effect("click count must be between one and three"));
                }
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
                    self.runtime
                        .click_with_options(
                            native_target()?,
                            match button {
                                MouseButton::Left => "left",
                                MouseButton::Right => "right",
                                MouseButton::Middle => "middle",
                            },
                            false,
                        )
                        .map_err(ambiguous_dispatch)?;
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
                if key.is_empty()
                    || key.len() > 64
                    || !(1..=100).contains(count)
                    || delay_ms.is_some_and(|delay| delay > 1_000)
                {
                    return Err(no_effect("press action parameters are invalid"));
                }
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
            Action::Paste { text } => {
                if text.is_empty() || text.len() > 16 * 1024 {
                    return Err(no_effect("paste parameters are invalid"));
                }
                self.runtime.paste(text)
            }
            Action::Hotkey { keys } => {
                let keys = keys.iter().map(String::as_str).collect::<Vec<_>>();
                if keys.is_empty()
                    || keys.len() > 8
                    || keys.iter().any(|key| key.is_empty() || key.len() > 64)
                {
                    return Err(no_effect("hotkey parameters are invalid"));
                }
                self.runtime.hotkey(&keys)
            }
            Action::Scroll { direction, amount } => {
                if !(1..=100).contains(amount) {
                    return Err(no_effect("scroll amount is invalid"));
                }
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
                if !cfg!(target_os = "macos") || value.len() > 16 * 1024 {
                    return Err(unsupported("set_value is unavailable on this backend"));
                }
                if !matches!(target, ResolvedTarget::Element(element) if element.bounds.is_some()) {
                    return Err(no_effect("set_value requires an element with bounds"));
                }
                Self::check_before_effect(cancellation, deadline_at_ms)?;
                self.runtime.set_value(native_target()?, value)
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

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LedgerRecord {
    Claim {
        operation_id: String,
        action_hash: String,
        claimed_at_ms: i64,
    },
    Terminal {
        acknowledgement: Box<ActionAck>,
    },
}

enum ClaimResult {
    New,
    Replay(Box<ActionAck>),
    RecoveredUnknown,
}

struct OperationLedger {
    path: PathBuf,
}

impl OperationLedger {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn execution_lock(&self) -> Result<LedgerLock, ProtocolError> {
        require_private_storage()?;
        let path = self.path.with_extension("lock");
        if let Some(parent) = path.parent() {
            ensure_directory(parent, false)?;
        }
        let existed = path.exists();
        let file = private_open_options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        restrict_file(&file)?;
        if !existed {
            sync_parent(&path)?;
        }
        file.lock_exclusive()?;
        Ok(LedgerLock(file))
    }

    fn repair_tail(&self) -> Result<(), ProtocolError> {
        let mut file = match private_open_options()
            .read(true)
            .write(true)
            .open(&self.path)
        {
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
        let mut truncate_at = durable_len;
        while offset < durable_len {
            let end = offset
                + bytes[offset..durable_len]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .unwrap_or(durable_len - offset)
                + 1;
            let line = &bytes[offset..end - 1];
            if !line.iter().all(u8::is_ascii_whitespace)
                && serde_json::from_slice::<LedgerRecord>(line).is_err()
            {
                if end != durable_len {
                    return Err(ProtocolError::InvalidRequest(
                        "ledger contains an invalid non-terminal record".to_string(),
                    ));
                }
                truncate_at = offset;
                break;
            }
            offset = end;
        }
        if truncate_at != bytes.len() {
            file.set_len(truncate_at as u64)?;
            file.sync_all()?;
        }
        Ok(())
    }

    fn claim(
        &self,
        request: &ActionRequest,
        action_hash: &str,
    ) -> Result<ClaimResult, ProtocolError> {
        let records = self.records()?;
        let mut claimed_hash = None;
        let mut terminal = None;
        for record in records {
            match record {
                LedgerRecord::Claim {
                    operation_id,
                    action_hash,
                    ..
                } if operation_id == request.operation_id => claimed_hash = Some(action_hash),
                LedgerRecord::Terminal { acknowledgement }
                    if acknowledgement.operation_id == request.operation_id =>
                {
                    terminal = Some(acknowledgement)
                }
                _ => {}
            }
        }
        if let Some(existing_hash) = claimed_hash {
            if existing_hash != action_hash {
                return Err(ProtocolError::Conflict);
            }
            return Ok(terminal
                .map(ClaimResult::Replay)
                .unwrap_or(ClaimResult::RecoveredUnknown));
        }
        self.append(&LedgerRecord::Claim {
            operation_id: request.operation_id.clone(),
            action_hash: action_hash.to_string(),
            claimed_at_ms: now_ms(),
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

    fn status(&self, operation_id: &str) -> Result<Option<ActionAck>, ProtocolError> {
        let _guard = self.execution_lock()?;
        self.repair_tail()?;
        Ok(self
            .records()?
            .into_iter()
            .rev()
            .find_map(|record| match record {
                LedgerRecord::Terminal { acknowledgement }
                    if acknowledgement.operation_id == operation_id =>
                {
                    Some(*acknowledgement)
                }
                _ => None,
            }))
    }

    fn records(&self) -> Result<Vec<LedgerRecord>, ProtocolError> {
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
        if let Some(parent) = path.parent() {
            ensure_directory(parent, false)?;
        }
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
    if request.action.requires_target() && matches!(request.target, TargetRef::None) {
        return Err(ProtocolError::InvalidRequest(
            "action requires a target".to_string(),
        ));
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
        TargetRef::Element {
            snapshot_id,
            selector,
            element_fingerprint,
            ..
        } => {
            !snapshot_id.is_empty()
                && snapshot_id.len() <= 256
                && !selector.is_empty()
                && selector.len() <= 1024
                && !element_fingerprint.backend.is_empty()
                && !element_fingerprint.id.is_empty()
                && !element_fingerprint.app.is_empty()
                && element_fingerprint.process_id > 0
                && !element_fingerprint.window.is_empty()
                && !element_fingerprint.role.is_empty()
                && element_fingerprint
                    .bounds
                    .is_some_and(|bounds| bounds.width > 0 && bounds.height > 0)
        }
        TargetRef::None => true,
    };
    if !valid_snapshot {
        return Err(ProtocolError::InvalidRequest(
            "invalid target provenance".to_string(),
        ));
    }
    if let TargetRef::Coordinates { snapshot_id, .. } | TargetRef::Element { snapshot_id, .. } =
        &request.target
        && !valid_protocol_snapshot_id(snapshot_id)
    {
        return Err(ProtocolError::InvalidRequest(
            "invalid snapshot ID".to_string(),
        ));
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
    hash_serializable(&(
        request.protocol_version,
        request.action_version,
        request.target_version,
        &request.subject,
        &request.session_id,
        &request.action,
        &request.target,
        request.deadline_at_ms,
        &request.verification,
        request.safety,
    ))
}

fn verify(
    policy: &VerificationPolicy,
    before: &Observation,
    after: Option<&Observation>,
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
            (Effect::Verified, Vec::new())
        }
        (VerificationPolicy::SnapshotChanged, Some(_)) => (
            Effect::ExecutedUnverified,
            vec!["post-action observation did not change".to_string()],
        ),
        (VerificationPolicy::TargetState { expected }, Some(after)) if &after.state == expected => {
            (Effect::Verified, Vec::new())
        }
        (VerificationPolicy::TargetState { .. }, Some(_)) => (
            Effect::ExecutedUnverified,
            vec!["target state did not match the expected value".to_string()],
        ),
    }
}

fn protocol_failure(error: ProtocolError) -> Terminal {
    let code = match &error {
        ProtocolError::StaleTarget(_) => FailureCode::StaleTarget,
        ProtocolError::TargetNotFound(_) => FailureCode::TargetNotFound,
        ProtocolError::InvalidRequest(_) => FailureCode::InvalidRequest,
        _ => FailureCode::DispatchFailed,
    };
    Terminal::Failed {
        code,
        message: match error {
            ProtocolError::StaleTarget(_) => "stale target".to_string(),
            ProtocolError::TargetNotFound(_) => "target not found".to_string(),
            ProtocolError::InvalidRequest(_) => "invalid request".to_string(),
            ProtocolError::AuthorityDenied => "authority denied".to_string(),
            _ => "executor failed".to_string(),
        },
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
    let root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(std::env::temp_dir);
    Ok(root
        .join("praefectus")
        .join("observations")
        .join(format!("{snapshot_id}.json")))
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
        "native-{display_geometry_hash}-{}-{}",
        now_ms(),
        OBSERVATION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn persist_coordinate_observation(
    observation: &CoordinateObservation,
) -> Result<(), ProtocolError> {
    let path = coordinate_observation_path(&observation.snapshot_id)?;
    persist_observation(&path, observation)
}

fn persist_element_observation(observation: &ElementObservation) -> Result<(), ProtocolError> {
    let path = coordinate_observation_path(&observation.snapshot_id)?;
    persist_observation(&path, observation)
}

fn persist_observation(path: &Path, observation: &impl Serialize) -> Result<(), ProtocolError> {
    require_private_storage()?;
    let parent = path
        .parent()
        .ok_or_else(|| ProtocolError::InvalidRequest("invalid observation path".to_string()))?;
    ensure_directory(parent, true)?;
    let temporary = path.with_extension("tmp");
    let mut file = private_open_options()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    restrict_file(&file)?;
    serde_json::to_writer(&mut file, observation)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    sync_parent(path)
}

fn load_coordinate_observation(snapshot_id: &str) -> Result<CoordinateObservation, ProtocolError> {
    let path = coordinate_observation_path(snapshot_id)?;
    let file = private_open_options().read(true).open(path).map_err(|_| {
        ProtocolError::StaleTarget("coordinate observation is unavailable".to_string())
    })?;
    restrict_file(&file)?;
    serde_json::from_reader(file)
        .map_err(|_| ProtocolError::StaleTarget("coordinate observation is invalid".to_string()))
}

fn load_element_observation(snapshot_id: &str) -> Result<ElementObservation, ProtocolError> {
    let path = coordinate_observation_path(snapshot_id)?;
    let file = private_open_options().read(true).open(path).map_err(|_| {
        ProtocolError::StaleTarget("element observation is unavailable".to_string())
    })?;
    restrict_file(&file)?;
    serde_json::from_reader(file)
        .map_err(|_| ProtocolError::StaleTarget("element observation is invalid".to_string()))
}

fn ensure_directory(path: &Path, restrict_existing: bool) -> Result<(), ProtocolError> {
    require_private_storage()?;
    let directory = if path.as_os_str().is_empty() {
        std::env::current_dir()?
    } else {
        path.to_path_buf()
    };
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
                validate_private_directory(candidate, &metadata)?;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(candidate.to_path_buf());
                current = candidate.parent();
            }
            Err(error) => return Err(error.into()),
        }
    }
    std::fs::create_dir_all(&directory)?;
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

#[cfg(not(unix))]
fn private_open_options() -> OpenOptions {
    OpenOptions::new()
}

#[cfg(unix)]
fn validate_private_directory(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), ProtocolError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Praefectus state directory is not private: {}",
                path.display()
            ),
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory(
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), ProtocolError> {
    Ok(())
}

#[cfg(not(windows))]
fn require_private_storage() -> Result<(), ProtocolError> {
    Ok(())
}

#[cfg(windows)]
fn require_private_storage() -> Result<(), ProtocolError> {
    Err(ProtocolError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "private Praefectus state is unavailable on this platform",
    )))
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), ProtocolError> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
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

#[cfg(not(unix))]
fn restrict_file(_file: &File) -> Result<(), ProtocolError> {
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<(), ProtocolError> {
    Ok(())
}

fn empty_receipt(request: &ActionRequest, action_hash: &str, effect: Effect) -> Receipt {
    Receipt {
        protocol_version: PROTOCOL_VERSION,
        action_name: request.action.name().to_string(),
        action_hash: action_hash.to_string(),
        started_at_ms: now_ms(),
        finished_at_ms: now_ms(),
        backend: "unknown".to_string(),
        fallback_chain: Vec::new(),
        effect,
        before: None,
        after: None,
        warnings: Vec::new(),
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

fn hash_serializable(value: &impl Serialize) -> Result<String, ProtocolError> {
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

pub fn default_ledger_path() -> PathBuf {
    Path::new("praefectus-operations.jsonl").to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorityGrant, NativeBounds, NativePoint, PROTOCOL_VERSION, SafetyClass,
        canonical_authority_bytes, native_snapshot_id, target_capture_bounds,
    };

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
                "{{\"action_hash\":\"{}\",\"expires_at_ms\":1,\"issuer\":\"host\",\"key_id\":\"key\",\"operation_id\":\"operation\",\"policy_generation\":\"generation\",\"protocol_version\":1,\"risk\":\"reversible\",\"session_id\":\"session\",\"subject\":\"subject\"}}",
                "0".repeat(64)
            )
        );
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
}
