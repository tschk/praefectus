use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use windows::Win32::Foundation::{FILETIME, HANDLE, HWND, LPARAM, POINT, RECT};
use windows::Win32::Graphics::Dwm::{DWMWA_CLOAKED, DwmGetWindowAttribute};
use windows::Win32::Graphics::Gdi::{
    EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
    SAFEARRAY,
};
use windows::Win32::System::Ole::{
    SafeArrayDestroy, SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetElemsize,
    SafeArrayGetLBound, SafeArrayGetUBound, SafeArrayGetVartype,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::Variant::VT_I4;
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomation2, IUIAutomationElement, IUIAutomationInvokePattern,
    IUIAutomationScrollPattern, IUIAutomationTreeWalker, IUIAutomationValuePattern,
    ScrollAmount_LargeDecrement, ScrollAmount_LargeIncrement, ScrollAmount_NoAmount,
    UIA_InvokePatternId, UIA_ScrollPatternId, UIA_ValuePatternId,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GA_ROOT, GetAncestor, GetCursorPos, GetForegroundWindow, GetWindowRect,
    GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible,
};
use windows::core::{BOOL, BSTR, Interface};

use crate::semantic::{
    Actionability, MAX_SEMANTIC_ELEMENTS, MAX_SEMANTIC_OBSERVATION_AGE_MS, SemanticBackend,
    SemanticElement, SemanticObservation, SemanticProvenance, SemanticTargetRef, opaque_element_id,
    semantic_fingerprint, semantic_tag,
};
use crate::{
    CancellationToken, Direction, DispatchError, DispatchReceipt, EffectKnowledge, FailureCode,
    NativeBounds, NativeError, PROTOCOL_VERSION, ProtocolError, Rect, SurfaceDescriptor,
    SurfaceRef, ambiguous, hash_bytes, hash_serializable, interrupted, no_effect, now_ms,
};

const BACKEND: &str = "praefectus-windows-uia";
const MAX_PROVIDER_TIMEOUT_MS: u32 = 2_000;
const MAX_SURFACES: usize = 512;
const MAX_RUNTIME_PATH_DEPTH: usize = 64;
const MAX_RUNTIME_PATH_INTEGERS: usize = 131_072;
const MAX_RUNTIME_PATH_BYTES: usize = 1024 * 1024;
const MAX_PRIVATE_MAPPING_BYTES: usize = 2 * 1024 * 1024;
static GENERATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn backend() -> &'static str {
    BACKEND
}

struct Apartment(bool);

impl Apartment {
    fn initialize() -> Self {
        Self(unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok())
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

struct Automation {
    client: IUIAutomation,
    _apartment: Apartment,
}

impl Automation {
    fn new(timeout_ms: u32) -> Result<Self, NativeError> {
        let apartment = Apartment::initialize();
        let client = unsafe {
            CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
        }
        .map_err(|_| NativeError)?;
        let configured = client.cast::<IUIAutomation2>().map_err(|_| NativeError)?;
        unsafe {
            configured
                .SetConnectionTimeout(timeout_ms)
                .map_err(|_| NativeError)?;
            configured
                .SetTransactionTimeout(timeout_ms)
                .map_err(|_| NativeError)?;
        }
        Ok(Self {
            client,
            _apartment: apartment,
        })
    }
}

struct RuntimeId(*mut SAFEARRAY);

impl RuntimeId {
    fn from_element(element: &IUIAutomationElement) -> Result<Self, NativeError> {
        let value = unsafe { element.GetRuntimeId() }.map_err(|_| NativeError)?;
        if value.is_null() {
            Err(NativeError)
        } else {
            Ok(Self(value))
        }
    }

    fn values(&self) -> Result<Vec<i32>, NativeError> {
        if unsafe { SafeArrayGetDim(self.0) } != 1
            || unsafe { SafeArrayGetElemsize(self.0) } != 4
            || unsafe { SafeArrayGetVartype(self.0) }.map_err(|_| NativeError)? != VT_I4
        {
            return Err(NativeError);
        }
        let lower = unsafe { SafeArrayGetLBound(self.0, 1) }.map_err(|_| NativeError)?;
        let upper = unsafe { SafeArrayGetUBound(self.0, 1) }.map_err(|_| NativeError)?;
        let length = upper
            .checked_sub(lower)
            .and_then(|value| value.checked_add(1))
            .and_then(|value| usize::try_from(value).ok())
            .filter(|length| (1..=64).contains(length))
            .ok_or(NativeError)?;
        let mut values = Vec::with_capacity(length);
        for index in lower..=upper {
            let mut value = 0i32;
            unsafe { SafeArrayGetElement(self.0, &index, (&mut value as *mut i32).cast()) }
                .map_err(|_| NativeError)?;
            values.push(value);
        }
        Ok(values)
    }
}

impl Drop for RuntimeId {
    fn drop(&mut self) {
        let _ = unsafe { SafeArrayDestroy(self.0) };
    }
}

struct ProcessHandle(HANDLE);

impl ProcessHandle {
    fn open(process_id: u32) -> Result<Self, NativeError> {
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
            .map(Self)
            .map_err(|_| NativeError)
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    protocol_version: u16,
    observation_id: String,
    generation: u64,
    provenance_hash: String,
    process_id: u32,
    process_generation: String,
    surface_id: String,
    window_handle: i64,
    window_id: String,
    display_geometry_hash: String,
    observed_at_ms: i64,
    expires_at_ms: i64,
    entries: Vec<MappingEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MappingEntry {
    element_id: String,
    runtime_id: Vec<i32>,
    runtime_path: Vec<Vec<i32>>,
    fingerprint_hash: String,
    unambiguous: bool,
    stable: bool,
}

#[derive(Clone, Debug)]
struct SurfaceRecord {
    descriptor: SurfaceDescriptor,
    window: HWND,
}

struct WindowEnumeration {
    windows: Vec<HWND>,
    full: bool,
}

type PendingElement = (IUIAutomationElement, Option<String>, Vec<Vec<i32>>);

#[derive(Default)]
struct RuntimePathBudget {
    integers: usize,
    bytes: usize,
}

struct ByteCounter {
    bytes: usize,
    limit: usize,
}

impl Write for ByteCounter {
    fn write(&mut self, value: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(value.len())
            .filter(|bytes| *bytes <= self.limit)
            .ok_or_else(|| io::Error::other("serialized value exceeds limit"))?;
        Ok(value.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl RuntimePathBudget {
    fn charge(&mut self, path: &[Vec<i32>]) -> Result<(), ProtocolError> {
        let integers = path.iter().try_fold(0usize, |total, runtime_id| {
            total.checked_add(runtime_id.len())
        });
        let bytes = runtime_path_serialized_bytes(path);
        self.charge_counts(integers, bytes)
    }

    fn charge_appended(
        &mut self,
        path: &[Vec<i32>],
        runtime_id: &[i32],
    ) -> Result<(), ProtocolError> {
        let integers = path.iter().try_fold(runtime_id.len(), |total, ancestor| {
            total.checked_add(ancestor.len())
        });
        let bytes = runtime_path_serialized_bytes(path).and_then(|bytes| {
            bytes
                .checked_add(usize::from(!path.is_empty()))?
                .checked_add(runtime_id_serialized_bytes(runtime_id)?)
        });
        self.charge_counts(integers, bytes)
    }

    fn charge_counts(
        &mut self,
        integers: Option<usize>,
        bytes: Option<usize>,
    ) -> Result<(), ProtocolError> {
        self.integers = integers
            .and_then(|integers| self.integers.checked_add(integers))
            .filter(|integers| *integers <= MAX_RUNTIME_PATH_INTEGERS)
            .ok_or_else(snapshot_budget_error)?;
        self.bytes = bytes
            .and_then(|bytes| self.bytes.checked_add(bytes))
            .filter(|bytes| *bytes <= MAX_RUNTIME_PATH_BYTES)
            .ok_or_else(snapshot_budget_error)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ElementState {
    runtime_id: Vec<i32>,
    process_id: u32,
    process_generation: String,
    window_id: String,
    role: String,
    name: Option<String>,
    bounds: NativeBounds,
    visible: bool,
    enabled: bool,
    invokable: bool,
    editable: bool,
    horizontally_scrollable: bool,
    vertically_scrollable: bool,
}

#[derive(Eq, PartialEq)]
struct FocusIdentity {
    window: HWND,
    process_id: u32,
    process_generation: String,
    runtime_id: Vec<i32>,
    fingerprint_hash: String,
}

pub(crate) fn available() -> bool {
    Automation::new(MAX_PROVIDER_TIMEOUT_MS)
        .and_then(|uia| unsafe { uia.client.GetRootElement() }.map_err(|_| NativeError))
        .is_ok()
}

pub(crate) fn screens() -> Result<Value, NativeError> {
    unsafe extern "system" fn collect(
        monitor: HMONITOR,
        _device: HDC,
        _bounds: *mut RECT,
        state: LPARAM,
    ) -> BOOL {
        let displays = unsafe { &mut *(state.0 as *mut Vec<Value>) };
        let mut information = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if unsafe { GetMonitorInfoW(monitor, &mut information) }.as_bool() {
            let bounds = information.rcMonitor;
            displays.push(serde_json::json!({
                "display_id": format!("monitor-{:x}", monitor.0 as usize),
                "x": bounds.left,
                "y": bounds.top,
                "width": bounds.right.saturating_sub(bounds.left),
                "height": bounds.bottom.saturating_sub(bounds.top),
            }));
        }
        BOOL::from(true)
    }

    let mut displays = Vec::<Value>::new();
    let result = unsafe {
        EnumDisplayMonitors(
            None,
            None,
            Some(collect),
            LPARAM((&mut displays as *mut Vec<Value>) as isize),
        )
    };
    if !result.as_bool() || displays.is_empty() {
        return Err(NativeError);
    }
    displays.sort_by_key(|display| {
        (
            display.get("x").and_then(Value::as_i64).unwrap_or_default(),
            display.get("y").and_then(Value::as_i64).unwrap_or_default(),
            display
                .get("display_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        )
    });
    Ok(Value::Array(displays))
}

pub(crate) fn list_surfaces(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<Vec<SurfaceDescriptor>, ProtocolError> {
    Ok(surface_records(cancellation, deadline_at_ms)?
        .into_iter()
        .map(|record| record.descriptor)
        .collect())
}

pub(crate) fn shared_desktop_context_hash(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<String, ProtocolError> {
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let window = unsafe { GetForegroundWindow() };
    if window.is_invalid() || !unsafe { IsWindow(Some(window)) }.as_bool() {
        return Err(shared_context_error(cancellation, deadline_at_ms));
    }
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let process_id = window_process_id(window)
        .map_err(|_| shared_context_error(cancellation, deadline_at_ms))?;
    let foreground_process_generation = process_generation(process_id)
        .map_err(|_| shared_context_error(cancellation, deadline_at_ms))?;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let automation = Automation::new(provider_timeout(deadline_at_ms))
        .map_err(|_| shared_context_error(cancellation, deadline_at_ms))?;
    let focused = focused_identity(&automation.client, cancellation, deadline_at_ms)
        .map_err(|_| shared_context_error(cancellation, deadline_at_ms))?;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    if !focus_matches_foreground(window, process_id, &foreground_process_generation, &focused) {
        return Err(shared_context_error(cancellation, deadline_at_ms));
    }
    let mut cursor = POINT::default();
    unsafe { GetCursorPos(&mut cursor) }
        .map_err(|_| shared_context_error(cancellation, deadline_at_ms))?;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let focused_after = focused_identity(&automation.client, cancellation, deadline_at_ms)
        .map_err(|_| shared_context_error(cancellation, deadline_at_ms))?;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let window_after = unsafe { GetForegroundWindow() };
    let process_id_after = window_process_id(window)
        .map_err(|_| shared_context_error(cancellation, deadline_at_ms))?;
    let process_generation_after = process_generation(process_id)
        .map_err(|_| shared_context_error(cancellation, deadline_at_ms))?;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    if window_after != window
        || process_id_after != process_id
        || process_generation_after != foreground_process_generation
        || focused_after != focused
    {
        return Err(shared_context_error(cancellation, deadline_at_ms));
    }
    shared_context_identity_hash(
        (
            window.0 as usize,
            process_id,
            &foreground_process_generation,
        ),
        (cursor.x, cursor.y),
        (
            focused.window.0 as usize,
            focused.process_id,
            &focused.process_generation,
            &focused.runtime_id,
            &focused.fingerprint_hash,
        ),
    )
}

fn shared_context_identity_hash(
    foreground: (usize, u32, &str),
    cursor: (i32, i32),
    focused: (usize, u32, &str, &[i32], &str),
) -> Result<String, ProtocolError> {
    hash_serializable(&(BACKEND, foreground, cursor, focused))
}

fn shared_context_error(cancellation: &CancellationToken, deadline_at_ms: i64) -> ProtocolError {
    observation_boundary_error(
        cancellation,
        deadline_at_ms,
        ProtocolError::Executor("shared desktop context is unavailable".to_string()),
    )
}

pub(crate) fn snapshot_surface(
    surface: &SurfaceRef,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<SemanticObservation, ProtocolError> {
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let mut matches = surface_records(cancellation, deadline_at_ms)?
        .into_iter()
        .filter(|record| record.descriptor.surface == *surface);
    let record = matches.next().ok_or_else(|| {
        ProtocolError::TargetNotFound("selected surface is unavailable".to_string())
    })?;
    if matches.next().is_some() {
        return Err(ProtocolError::StaleTarget(
            "selected surface is ambiguous".to_string(),
        ));
    }
    snapshot_window(record, cancellation, deadline_at_ms)
}

pub(crate) fn snapshot(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<SemanticObservation, ProtocolError> {
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let window = unsafe { GetForegroundWindow() };
    if window.is_invalid() {
        return Err(ProtocolError::TargetNotFound(
            "foreground window is unavailable".to_string(),
        ));
    }
    let process_id = window_process_id(window)?;
    let process_generation = process_generation(process_id)
        .map_err(|_| observation_call_error(cancellation, deadline_at_ms))?;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let displays = screens().map_err(|_| observation_call_error(cancellation, deadline_at_ms))?;
    let display_geometry_hash = hash_serializable(&displays)?;
    let descriptor = surface_descriptor(
        window,
        process_id,
        process_generation,
        display_geometry_hash,
        &displays,
    )?
    .ok_or_else(|| ProtocolError::TargetNotFound("foreground window is unavailable".to_string()))?;
    snapshot_window(
        SurfaceRecord { descriptor, window },
        cancellation,
        deadline_at_ms,
    )
}

fn snapshot_window(
    record: SurfaceRecord,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<SemanticObservation, ProtocolError> {
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let automation = Automation::new(provider_timeout(deadline_at_ms))
        .map_err(|_| observation_call_error(cancellation, deadline_at_ms))?;
    let SurfaceRecord { descriptor, window } = record;
    validate_surface_record(&descriptor, window, cancellation, deadline_at_ms)?;
    let process_id = descriptor.process_id;
    let process_generation = descriptor.process_generation.clone();
    let window_id = descriptor.window_id.clone();
    let display_geometry_hash = descriptor.display_geometry_hash.clone();
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed);
    if generation == 0 {
        return Err(ProtocolError::Executor(
            "semantic snapshot failed".to_string(),
        ));
    }
    let observed_at_ms = now_ms();
    let observation_id = semantic_fingerprint(&(
        BACKEND,
        process_id,
        &process_generation,
        &window_id,
        &display_geometry_hash,
        observed_at_ms,
        generation,
    ))
    .map_err(|_| ProtocolError::Executor("semantic snapshot failed".to_string()))?;
    let provenance = SemanticProvenance {
        backend: SemanticBackend::Accessibility,
        backend_name: BACKEND.to_string(),
        process_id,
        process_generation: process_generation.clone(),
        window_id: window_id.clone(),
        document_id: None,
        display_geometry_hash,
    };
    let provenance_hash = semantic_fingerprint(&(
        PROTOCOL_VERSION,
        &observation_id,
        generation,
        &provenance,
        observed_at_ms,
        observed_at_ms.saturating_add(MAX_SEMANTIC_OBSERVATION_AGE_MS),
    ))
    .map_err(|_| ProtocolError::Executor("semantic snapshot failed".to_string()))?;
    let root = unsafe { automation.client.ElementFromHandle(window) }.map_err(|_| {
        observation_boundary_error(
            cancellation,
            deadline_at_ms,
            ProtocolError::TargetNotFound("selected accessibility root is unavailable".to_string()),
        )
    })?;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let walker = unsafe { automation.client.ControlViewWalker() }.map_err(|_| {
        observation_boundary_error(
            cancellation,
            deadline_at_ms,
            ProtocolError::Executor("semantic snapshot failed".to_string()),
        )
    })?;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let mut queue = VecDeque::from([(root, None::<String>, Vec::<Vec<i32>>::new())]);
    let mut runtime_path_budget = RuntimePathBudget::default();
    runtime_path_budget.charge(&[])?;
    let mut seen = BTreeMap::<Vec<i32>, usize>::new();
    let mut elements = Vec::<SemanticElement>::new();
    let mut entries = Vec::<MappingEntry>::new();
    let mut truncated = false;
    let mut visited_nodes = 0usize;

    while let Some((element, parent_id, runtime_path)) = queue.pop_front() {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        if visited_nodes >= MAX_SEMANTIC_ELEMENTS || elements.len() >= MAX_SEMANTIC_ELEMENTS {
            truncated = true;
            break;
        }
        visited_nodes += 1;
        let state = match describe(&automation.client, &element, cancellation, deadline_at_ms) {
            Ok(state) => state,
            Err(_) => {
                check_observation_boundary(cancellation, deadline_at_ms)?;
                truncated = true;
                truncated |= enqueue_children(
                    &walker,
                    &element,
                    parent_id,
                    runtime_path,
                    (&mut runtime_path_budget, &mut queue),
                    cancellation,
                    deadline_at_ms,
                )?;
                continue;
            }
        };
        check_observation_boundary(cancellation, deadline_at_ms)?;
        if state.process_id != process_id
            || state.process_generation != process_generation
            || state.window_id != window_id
        {
            truncated |= enqueue_children(
                &walker,
                &element,
                parent_id,
                runtime_path,
                (&mut runtime_path_budget, &mut queue),
                cancellation,
                deadline_at_ms,
            )?;
            continue;
        }
        if let Some(index) = seen.get(&state.runtime_id).copied() {
            elements[index].actionability.unambiguous = false;
            entries[index].unambiguous = false;
            truncated |= enqueue_children(
                &walker,
                &element,
                parent_id,
                runtime_path,
                (&mut runtime_path_budget, &mut queue),
                cancellation,
                deadline_at_ms,
            )?;
            continue;
        }
        let state_fingerprint = fingerprint(&state).ok();
        let stable = match describe(&automation.client, &element, cancellation, deadline_at_ms) {
            Ok(repeated) => state_fingerprint.as_ref().is_some_and(|state| {
                fingerprint(&repeated).is_ok_and(|repeated| state == &repeated)
            }),
            Err(_) => {
                truncated = true;
                false
            }
        };
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let backend_id = runtime_id_text(&state.runtime_id);
        let element_id = opaque_element_id(&observation_id, &backend_id)
            .map_err(|_| ProtocolError::Executor("semantic snapshot failed".to_string()))?;
        let receives_events = state.visible && state.enabled;
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let fingerprint_hash = fingerprint(&state)?;
        let index = elements.len();
        seen.insert(state.runtime_id.clone(), index);
        elements.push(SemanticElement {
            tag: semantic_tag(index)
                .map_err(|_| ProtocolError::Executor("semantic snapshot failed".to_string()))?,
            element_id: element_id.clone(),
            parent_id: parent_id.clone(),
            fingerprint_hash: fingerprint_hash.clone(),
            role: state.role.clone(),
            name: state.name.clone(),
            bounds: Some(Rect {
                x: state.bounds.x,
                y: state.bounds.y,
                width: state.bounds.width,
                height: state.bounds.height,
            }),
            actionability: Actionability {
                visible: state.visible,
                enabled: state.enabled,
                unambiguous: true,
                stable,
                receives_events,
                invokable: state.invokable,
                editable: state.editable,
            },
        });
        runtime_path_budget.charge_appended(&runtime_path, &state.runtime_id)?;
        let mut entry_path = runtime_path;
        entry_path.push(state.runtime_id.clone());
        entries.push(MappingEntry {
            element_id: element_id.clone(),
            runtime_id: state.runtime_id,
            runtime_path: entry_path.clone(),
            fingerprint_hash,
            unambiguous: true,
            stable,
        });
        truncated |= enqueue_children(
            &walker,
            &element,
            Some(element_id),
            entry_path,
            (&mut runtime_path_budget, &mut queue),
            cancellation,
            deadline_at_ms,
        )?;
    }
    let expires_at_ms = observed_at_ms.saturating_add(MAX_SEMANTIC_OBSERVATION_AGE_MS);
    let observation = SemanticObservation {
        protocol_version: PROTOCOL_VERSION,
        observation_id: observation_id.clone(),
        generation,
        provenance,
        observed_at_ms,
        expires_at_ms,
        truncated,
        elements,
    };
    check_observation_boundary(cancellation, deadline_at_ms)?;
    observation
        .validate(now_ms())
        .map_err(|_| ProtocolError::Executor("semantic snapshot failed".to_string()))?;
    validate_surface_record(&descriptor, window, cancellation, deadline_at_ms)?;
    let mapping = Mapping {
        protocol_version: PROTOCOL_VERSION,
        observation_id: observation_id.clone(),
        generation,
        provenance_hash,
        process_id,
        process_generation,
        surface_id: descriptor.surface.id,
        window_handle: window.0 as i64,
        window_id,
        display_geometry_hash: observation.provenance.display_geometry_hash.clone(),
        observed_at_ms,
        expires_at_ms,
        entries,
    };
    ensure_serialized_mapping_budget(&mapping)?;
    crate::persist_private_observation(&observation_id, &mapping)?;
    Ok(observation)
}

fn validate_surface_record(
    expected: &SurfaceDescriptor,
    window: HWND,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(), ProtocolError> {
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let displays = screens().map_err(|_| observation_call_error(cancellation, deadline_at_ms))?;
    let display_geometry_hash = hash_serializable(&displays)?;
    if display_geometry_hash != expected.display_geometry_hash {
        return Err(ProtocolError::StaleTarget(
            "selected surface display topology changed".to_string(),
        ));
    }
    let current = surface_descriptor(
        window,
        expected.process_id,
        expected.process_generation.clone(),
        display_geometry_hash,
        &displays,
    )?
    .ok_or_else(|| ProtocolError::StaleTarget("selected surface changed".to_string()))?;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    if current != *expected {
        return Err(ProtocolError::StaleTarget(
            "selected surface changed".to_string(),
        ));
    }
    Ok(())
}

fn surface_records(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<Vec<SurfaceRecord>, ProtocolError> {
    check_observation_boundary(cancellation, deadline_at_ms)?;
    unsafe extern "system" fn collect(window: HWND, state: LPARAM) -> BOOL {
        let enumeration = unsafe { &mut *(state.0 as *mut WindowEnumeration) };
        if !unsafe { IsWindowVisible(window) }.as_bool() || unsafe { IsIconic(window) }.as_bool() {
            return BOOL::from(true);
        }
        if enumeration.windows.len() >= MAX_SURFACES {
            enumeration.full = true;
            return BOOL::from(false);
        }
        enumeration.windows.push(window);
        BOOL::from(true)
    }

    let displays = screens().map_err(|_| observation_call_error(cancellation, deadline_at_ms))?;
    let display_geometry_hash = hash_serializable(&displays)?;
    let mut enumeration = WindowEnumeration {
        windows: Vec::new(),
        full: false,
    };
    let result = unsafe {
        EnumWindows(
            Some(collect),
            LPARAM((&mut enumeration as *mut WindowEnumeration) as isize),
        )
    };
    if result.is_err() && !enumeration.full {
        return Err(observation_call_error(cancellation, deadline_at_ms));
    }
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let mut records = Vec::with_capacity(enumeration.windows.len());
    for window in enumeration.windows {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let process_id = match window_process_id(window) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let process_generation = match process_generation(process_id) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(descriptor) = surface_descriptor(
            window,
            process_id,
            process_generation,
            display_geometry_hash.clone(),
            &displays,
        )? {
            records.push(SurfaceRecord { descriptor, window });
        }
    }
    records.sort_by(|left, right| left.descriptor.surface.id.cmp(&right.descriptor.surface.id));
    Ok(records)
}

fn surface_descriptor(
    window: HWND,
    process_id: u32,
    expected_process_generation: String,
    display_geometry_hash: String,
    displays: &Value,
) -> Result<Option<SurfaceDescriptor>, ProtocolError> {
    if window.is_invalid()
        || !unsafe { IsWindow(Some(window)) }.as_bool()
        || !unsafe { IsWindowVisible(window) }.as_bool()
        || unsafe { IsIconic(window) }.as_bool()
        || !window_is_uncloaked(window).unwrap_or(false)
        || unsafe { GetAncestor(window, GA_ROOT) } != window
    {
        return Ok(None);
    }
    let mut rectangle = RECT::default();
    if unsafe { GetWindowRect(window, &mut rectangle) }.is_err() {
        return Ok(None);
    }
    let bounds = match native_bounds(rectangle) {
        Ok(value) if intersects_displays(&value, displays) => value,
        _ => return Ok(None),
    };
    if window_process_id(window).ok() != Some(process_id)
        || process_generation(process_id).ok().as_deref()
            != Some(expected_process_generation.as_str())
    {
        return Ok(None);
    }
    let window_id = window_identity(window, &expected_process_generation)
        .map_err(|_| ProtocolError::Executor("surface identity is unavailable".to_string()))?;
    let surface = SurfaceRef {
        id: semantic_fingerprint(&(
            PROTOCOL_VERSION,
            BACKEND,
            window.0 as usize,
            process_id,
            &expected_process_generation,
            &window_id,
            &display_geometry_hash,
            &bounds,
        ))
        .map_err(|_| ProtocolError::Executor("surface identity is unavailable".to_string()))?,
    };
    Ok(Some(SurfaceDescriptor {
        protocol_version: PROTOCOL_VERSION,
        surface,
        backend: BACKEND.to_string(),
        process_id,
        process_generation: expected_process_generation,
        window_id,
        display_geometry_hash,
        bounds: Some(Rect {
            x: bounds.x,
            y: bounds.y,
            width: bounds.width,
            height: bounds.height,
        }),
    }))
}

fn intersects_displays(bounds: &NativeBounds, displays: &Value) -> bool {
    displays.as_array().is_some_and(|displays| {
        displays.iter().any(|display| {
            let Some((x, y, width, height)) = display
                .get("x")
                .and_then(Value::as_i64)
                .zip(display.get("y").and_then(Value::as_i64))
                .zip(display.get("width").and_then(Value::as_i64))
                .zip(display.get("height").and_then(Value::as_i64))
                .map(|(((x, y), width), height)| (x, y, width, height))
            else {
                return false;
            };
            width > 0
                && height > 0
                && bounds.x < x.saturating_add(width)
                && x < bounds.x.saturating_add(bounds.width)
                && bounds.y < y.saturating_add(height)
                && y < bounds.y.saturating_add(bounds.height)
        })
    })
}

pub(crate) fn observe_target(
    target: &SemanticTargetRef,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(SemanticElement, Option<String>), ProtocolError> {
    let (automation, element, state, index) = resolve(target, cancellation, deadline_at_ms)
        .map_err(|_| ProtocolError::StaleTarget("semantic target is unavailable".to_string()))?;
    let repeated =
        describe(&automation.client, &element, cancellation, deadline_at_ms).map_err(|_| {
            observation_boundary_error(
                cancellation,
                deadline_at_ms,
                ProtocolError::StaleTarget("semantic target is unavailable".to_string()),
            )
        })?;
    let stable = fingerprint(&state)? == fingerprint(&repeated)?;
    let value_hash = unsafe {
        element
            .GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
            .ok()
            .and_then(|pattern| pattern.CurrentValue().ok())
    }
    .map(|value| hash_ui_value(&value.to_string()));
    let semantic_element = SemanticElement {
        tag: semantic_tag(index)
            .map_err(|_| ProtocolError::StaleTarget("semantic target is invalid".to_string()))?,
        element_id: target.element_id.clone(),
        parent_id: None,
        fingerprint_hash: target.fingerprint_hash.clone(),
        role: state.role,
        name: state.name,
        bounds: Some(Rect {
            x: state.bounds.x,
            y: state.bounds.y,
            width: state.bounds.width,
            height: state.bounds.height,
        }),
        actionability: Actionability {
            visible: state.visible,
            enabled: state.enabled,
            unambiguous: true,
            stable,
            receives_events: true,
            invokable: state.invokable,
            editable: state.editable,
        },
    };
    Ok((semantic_element, value_hash))
}

pub(crate) fn invoke(
    target: &SemanticTargetRef,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<DispatchReceipt, DispatchError> {
    let (automation, element, state, _) = resolve(target, cancellation, deadline_at_ms)?;
    let pattern: IUIAutomationInvokePattern =
        unsafe { element.GetCurrentPatternAs(UIA_InvokePatternId) }.map_err(|_| {
            before_effect_error(
                cancellation,
                deadline_at_ms,
                "semantic target is not invokable",
            )
        })?;
    ensure_live_state(
        &automation.client,
        &element,
        &state,
        cancellation,
        deadline_at_ms,
    )?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    unsafe { pattern.Invoke() }
        .map_err(|_| ambiguous("accessibility action outcome is unknown"))?;
    check_after_effect(cancellation, deadline_at_ms)?;
    Ok(receipt())
}

pub(crate) fn set_value(
    target: &SemanticTargetRef,
    value: &str,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<DispatchReceipt, DispatchError> {
    if value.len() > 16 * 1024 {
        return Err(no_effect("value is too large"));
    }
    let (automation, element, state, _) = resolve(target, cancellation, deadline_at_ms)?;
    let pattern: IUIAutomationValuePattern =
        unsafe { element.GetCurrentPatternAs(UIA_ValuePatternId) }.map_err(|_| {
            before_effect_error(
                cancellation,
                deadline_at_ms,
                "semantic target is not editable",
            )
        })?;
    let read_only = unsafe { pattern.CurrentIsReadOnly() }.map_err(|_| {
        before_effect_error(
            cancellation,
            deadline_at_ms,
            "semantic target editability is unavailable",
        )
    })?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    if read_only.as_bool() {
        return Err(no_effect("semantic target is read-only"));
    }
    ensure_live_state(
        &automation.client,
        &element,
        &state,
        cancellation,
        deadline_at_ms,
    )?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    unsafe { pattern.SetValue(&BSTR::from(value)) }
        .map_err(|_| ambiguous("accessibility action outcome is unknown"))?;
    check_after_effect(cancellation, deadline_at_ms)?;
    Ok(receipt())
}

pub(crate) fn scroll(
    target: &SemanticTargetRef,
    direction: Direction,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<DispatchReceipt, DispatchError> {
    let (automation, element, state, _) = resolve(target, cancellation, deadline_at_ms)?;
    let pattern: IUIAutomationScrollPattern =
        unsafe { element.GetCurrentPatternAs(UIA_ScrollPatternId) }.map_err(|_| {
            before_effect_error(
                cancellation,
                deadline_at_ms,
                "semantic target is not scrollable",
            )
        })?;
    let (horizontal, vertical) = match direction {
        Direction::Up if state.vertically_scrollable => {
            (ScrollAmount_NoAmount, ScrollAmount_LargeDecrement)
        }
        Direction::Down if state.vertically_scrollable => {
            (ScrollAmount_NoAmount, ScrollAmount_LargeIncrement)
        }
        Direction::Left if state.horizontally_scrollable => {
            (ScrollAmount_LargeDecrement, ScrollAmount_NoAmount)
        }
        Direction::Right if state.horizontally_scrollable => {
            (ScrollAmount_LargeIncrement, ScrollAmount_NoAmount)
        }
        _ => return Err(no_effect("semantic target cannot scroll in that direction")),
    };
    ensure_live_state(
        &automation.client,
        &element,
        &state,
        cancellation,
        deadline_at_ms,
    )?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    unsafe { pattern.Scroll(horizontal, vertical) }
        .map_err(|_| ambiguous("accessibility action outcome is unknown"))?;
    check_after_effect(cancellation, deadline_at_ms)?;
    Ok(receipt())
}

fn resolve(
    target: &SemanticTargetRef,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(Automation, IUIAutomationElement, ElementState, usize), DispatchError> {
    check_effect_boundary(cancellation, deadline_at_ms)?;
    let mapping: Mapping = crate::load_private_observation(&target.observation_id)
        .map_err(|_| no_effect("semantic observation is unavailable"))?;
    if mapping.protocol_version != PROTOCOL_VERSION
        || mapping.observation_id != target.observation_id
        || mapping.generation != target.generation
        || mapping.provenance_hash != target.provenance_hash
        || mapping.observed_at_ms <= 0
        || mapping.expires_at_ms.saturating_sub(mapping.observed_at_ms)
            != MAX_SEMANTIC_OBSERVATION_AGE_MS
        || now_ms() >= mapping.expires_at_ms
        || mapping.entries.len() > MAX_SEMANTIC_ELEMENTS
    {
        return Err(no_effect("semantic target is stale"));
    }
    let provenance = SemanticProvenance {
        backend: SemanticBackend::Accessibility,
        backend_name: BACKEND.to_string(),
        process_id: mapping.process_id,
        process_generation: mapping.process_generation.clone(),
        window_id: mapping.window_id.clone(),
        document_id: None,
        display_geometry_hash: mapping.display_geometry_hash.clone(),
    };
    if semantic_fingerprint(&(
        PROTOCOL_VERSION,
        &mapping.observation_id,
        mapping.generation,
        provenance,
        mapping.observed_at_ms,
        mapping.expires_at_ms,
    ))
    .map_err(|_| no_effect("semantic target is stale"))?
        != mapping.provenance_hash
    {
        return Err(no_effect("semantic target is stale"));
    }
    let mut matches = mapping
        .entries
        .iter()
        .filter(|entry| entry.element_id == target.element_id);
    let entry = matches
        .next()
        .ok_or_else(|| no_effect("semantic target is unavailable"))?;
    if matches.next().is_some() || entry.fingerprint_hash != target.fingerprint_hash {
        return Err(no_effect("semantic target is ambiguous or stale"));
    }
    if entry.runtime_id.is_empty()
        || entry.runtime_id.len() > 64
        || entry.runtime_path.is_empty()
        || entry.runtime_path.len() > MAX_RUNTIME_PATH_DEPTH
        || entry
            .runtime_path
            .iter()
            .any(|runtime_id| runtime_id.is_empty() || runtime_id.len() > 64)
        || entry.runtime_path.last() != Some(&entry.runtime_id)
        || opaque_element_id(&mapping.observation_id, &runtime_id_text(&entry.runtime_id))
            .map_err(|_| no_effect("semantic target is stale"))?
            != entry.element_id
    {
        return Err(no_effect("semantic target is stale"));
    }
    ensure_entry_unambiguous(entry)?;
    if !entry.stable {
        return Err(no_effect("semantic target was unstable when observed"));
    }
    check_effect_boundary(cancellation, deadline_at_ms)?;
    let display_geometry_hash = hash_serializable(&screens().map_err(|_| {
        before_effect_error(
            cancellation,
            deadline_at_ms,
            "display geometry is unavailable",
        )
    })?)
    .map_err(|_| {
        before_effect_error(
            cancellation,
            deadline_at_ms,
            "display geometry is unavailable",
        )
    })?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    if display_geometry_hash != mapping.display_geometry_hash {
        return Err(no_effect("display geometry changed"));
    }
    let window = HWND(mapping.window_handle as isize as *mut _);
    if window.is_invalid()
        || !unsafe { IsWindow(Some(window)) }.as_bool()
        || !unsafe { IsWindowVisible(window) }.as_bool()
        || unsafe { IsIconic(window) }.as_bool()
        || window_process_id(window).map_err(|_| no_effect("semantic surface is unavailable"))?
            != mapping.process_id
        || process_generation(mapping.process_id)
            .map_err(|_| no_effect("semantic surface is unavailable"))?
            != mapping.process_generation
        || window_identity(window, &mapping.process_generation)
            .map_err(|_| no_effect("semantic surface is unavailable"))?
            != mapping.window_id
    {
        return Err(no_effect("semantic surface changed"));
    }
    let displays = screens().map_err(|_| {
        before_effect_error(
            cancellation,
            deadline_at_ms,
            "display geometry is unavailable",
        )
    })?;
    let descriptor = surface_descriptor(
        window,
        mapping.process_id,
        mapping.process_generation.clone(),
        mapping.display_geometry_hash.clone(),
        &displays,
    )
    .map_err(|_| no_effect("semantic surface is unavailable"))?
    .ok_or_else(|| no_effect("semantic surface is unavailable"))?;
    if descriptor.surface.id != mapping.surface_id {
        return Err(no_effect("semantic surface changed"));
    }
    let automation = Automation::new(provider_timeout(deadline_at_ms)).map_err(|_| {
        before_effect_error(cancellation, deadline_at_ms, "accessibility is unavailable")
    })?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    let element = resolve_runtime_path(
        &automation.client,
        window,
        &entry.runtime_path,
        cancellation,
        deadline_at_ms,
    )?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    let state =
        describe(&automation.client, &element, cancellation, deadline_at_ms).map_err(|_| {
            before_effect_error(
                cancellation,
                deadline_at_ms,
                "semantic target is unavailable",
            )
        })?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    if state.runtime_id != entry.runtime_id
        || state.process_id != mapping.process_id
        || state.process_generation != mapping.process_generation
        || state.window_id != mapping.window_id
        || fingerprint(&state).map_err(|_| no_effect("semantic target is unavailable"))?
            != entry.fingerprint_hash
        || !state.visible
        || !state.enabled
    {
        return Err(no_effect("semantic target changed"));
    }
    let repeated =
        describe(&automation.client, &element, cancellation, deadline_at_ms).map_err(|_| {
            before_effect_error(
                cancellation,
                deadline_at_ms,
                "semantic target stability is unavailable",
            )
        })?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    if fingerprint(&repeated).map_err(|_| no_effect("semantic target is unavailable"))?
        != entry.fingerprint_hash
    {
        return Err(no_effect("semantic target is unstable"));
    }
    let index = mapping
        .entries
        .iter()
        .position(|candidate| candidate.element_id == target.element_id)
        .ok_or_else(|| no_effect("semantic target is unavailable"))?;
    Ok((automation, element, repeated, index))
}

fn ensure_entry_unambiguous(entry: &MappingEntry) -> Result<(), DispatchError> {
    if !entry.unambiguous {
        return Err(no_effect("semantic target was ambiguous when observed"));
    }
    Ok(())
}

fn ensure_live_state(
    automation: &IUIAutomation,
    element: &IUIAutomationElement,
    expected: &ElementState,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(), DispatchError> {
    check_effect_boundary(cancellation, deadline_at_ms)?;
    let (current, window) = describe_with_window(automation, element, cancellation, deadline_at_ms)
        .map_err(|_| {
            before_effect_error(
                cancellation,
                deadline_at_ms,
                "semantic target is unavailable",
            )
        })?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    if fingerprint(&current).map_err(|_| no_effect("semantic target is unavailable"))?
        != fingerprint(expected).map_err(|_| no_effect("semantic target is unavailable"))?
    {
        return Err(no_effect("semantic target changed before effect"));
    }
    let uncloaked = window_is_uncloaked(window).map_err(|_| {
        before_effect_error(
            cancellation,
            deadline_at_ms,
            "semantic surface visibility is unavailable",
        )
    })?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    if !uncloaked {
        return Err(no_effect("semantic surface became cloaked before effect"));
    }
    Ok(())
}

fn describe(
    automation: &IUIAutomation,
    element: &IUIAutomationElement,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<ElementState, NativeError> {
    describe_with_window(automation, element, cancellation, deadline_at_ms).map(|(state, _)| state)
}

fn describe_with_window(
    automation: &IUIAutomation,
    element: &IUIAutomationElement,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(ElementState, HWND), NativeError> {
    if check_observation_boundary(cancellation, deadline_at_ms).is_err() {
        return Err(NativeError);
    }
    let runtime_id = runtime_values(element)?;
    if check_observation_boundary(cancellation, deadline_at_ms).is_err() {
        return Err(NativeError);
    }
    let process_id = u32::try_from(unsafe { element.CurrentProcessId() }.map_err(|_| NativeError)?)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(NativeError)?;
    let generation = process_generation(process_id)?;
    let window = element_window(automation, element, cancellation, deadline_at_ms)?;
    let window_id = window_identity(window, &generation)?;
    let rectangle = unsafe { element.CurrentBoundingRectangle() }.map_err(|_| NativeError)?;
    let bounds = native_bounds(rectangle)?;
    if check_observation_boundary(cancellation, deadline_at_ms).is_err() {
        return Err(NativeError);
    }
    let enabled = unsafe { element.CurrentIsEnabled() }
        .map_err(|_| NativeError)?
        .as_bool();
    let visible = !unsafe { element.CurrentIsOffscreen() }
        .map_err(|_| NativeError)?
        .as_bool();
    let role = format!(
        "uia-{}",
        unsafe { element.CurrentControlType() }
            .map_err(|_| NativeError)?
            .0
    );
    let name = bounded_bstr(unsafe { element.CurrentName() }.ok());
    if check_observation_boundary(cancellation, deadline_at_ms).is_err() {
        return Err(NativeError);
    }
    let invokable =
        unsafe { element.GetCurrentPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId) }
            .is_ok();
    let editable =
        unsafe { element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) }
            .ok()
            .and_then(|pattern| unsafe { pattern.CurrentIsReadOnly() }.ok())
            .is_some_and(|value| !value.as_bool());
    let scroll =
        unsafe { element.GetCurrentPatternAs::<IUIAutomationScrollPattern>(UIA_ScrollPatternId) }
            .ok();
    let horizontally_scrollable = scroll
        .as_ref()
        .and_then(|pattern| unsafe { pattern.CurrentHorizontallyScrollable() }.ok())
        .is_some_and(|value| value.as_bool());
    let vertically_scrollable = scroll
        .as_ref()
        .and_then(|pattern| unsafe { pattern.CurrentVerticallyScrollable() }.ok())
        .is_some_and(|value| value.as_bool());
    if check_observation_boundary(cancellation, deadline_at_ms).is_err() {
        return Err(NativeError);
    }
    Ok((
        ElementState {
            runtime_id,
            process_id,
            process_generation: generation,
            window_id,
            role,
            name,
            bounds,
            visible,
            enabled,
            invokable,
            editable,
            horizontally_scrollable,
            vertically_scrollable,
        },
        window,
    ))
}

fn enqueue_children(
    walker: &IUIAutomationTreeWalker,
    element: &IUIAutomationElement,
    parent_id: Option<String>,
    runtime_path: Vec<Vec<i32>>,
    pending: (&mut RuntimePathBudget, &mut VecDeque<PendingElement>),
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<bool, ProtocolError> {
    let (runtime_path_budget, queue) = pending;
    check_observation_boundary(cancellation, deadline_at_ms)?;
    if runtime_path.len() >= MAX_RUNTIME_PATH_DEPTH {
        return Ok(true);
    }
    let Some(mut child) = optional_element(unsafe { walker.GetFirstChildElement(element) })
        .map_err(|_| observation_call_error(cancellation, deadline_at_ms))?
    else {
        return Ok(false);
    };
    check_observation_boundary(cancellation, deadline_at_ms)?;
    let mut siblings = BTreeSet::new();
    loop {
        check_observation_boundary(cancellation, deadline_at_ms)?;
        let runtime_id = runtime_values(&child)
            .map_err(|_| observation_call_error(cancellation, deadline_at_ms))?;
        check_observation_boundary(cancellation, deadline_at_ms)?;
        if !accept_sibling(queue.len(), &mut siblings, runtime_id) {
            return Ok(true);
        }
        runtime_path_budget.charge(&runtime_path)?;
        queue.push_back((child.clone(), parent_id.clone(), runtime_path.clone()));
        let Some(next) = optional_element(unsafe { walker.GetNextSiblingElement(&child) })
            .map_err(|_| observation_call_error(cancellation, deadline_at_ms))?
        else {
            return Ok(false);
        };
        check_observation_boundary(cancellation, deadline_at_ms)?;
        child = next;
    }
}

fn accept_sibling(
    queue_len: usize,
    siblings: &mut BTreeSet<Vec<i32>>,
    runtime_id: Vec<i32>,
) -> bool {
    queue_len < MAX_SEMANTIC_ELEMENTS && siblings.insert(runtime_id)
}

fn runtime_path_serialized_bytes(path: &[Vec<i32>]) -> Option<usize> {
    path.iter()
        .enumerate()
        .try_fold(2usize, |total, (path_index, runtime_id)| {
            runtime_id_serialized_bytes(runtime_id).and_then(|runtime_bytes| {
                total
                    .checked_add(usize::from(path_index > 0))?
                    .checked_add(runtime_bytes)
            })
        })
}

fn runtime_id_serialized_bytes(runtime_id: &[i32]) -> Option<usize> {
    runtime_id
        .iter()
        .enumerate()
        .try_fold(2usize, |total, (index, value)| {
            total
                .checked_add(usize::from(index > 0))?
                .checked_add(decimal_i32_bytes(*value))
        })
}

fn decimal_i32_bytes(value: i32) -> usize {
    let mut value = i64::from(value);
    let mut length = usize::from(value < 0);
    if value < 0 {
        value = -value;
    }
    loop {
        length += 1;
        value /= 10;
        if value == 0 {
            return length;
        }
    }
}

fn ensure_serialized_mapping_budget(mapping: &Mapping) -> Result<(), ProtocolError> {
    let mut counter = ByteCounter {
        bytes: 0,
        limit: MAX_PRIVATE_MAPPING_BYTES,
    };
    serde_json::to_writer(&mut counter, mapping).map_err(|_| snapshot_budget_error())
}

fn snapshot_budget_error() -> ProtocolError {
    ProtocolError::Executor("semantic snapshot exceeded its private budget".to_string())
}

fn optional_element(
    result: windows::core::Result<IUIAutomationElement>,
) -> Result<Option<IUIAutomationElement>, NativeError> {
    match result {
        Ok(element) => Ok(Some(element)),
        Err(error) if error.code().is_ok() => Ok(None),
        Err(_) => Err(NativeError),
    }
}

fn resolve_runtime_path(
    automation: &IUIAutomation,
    window: HWND,
    runtime_path: &[Vec<i32>],
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<IUIAutomationElement, DispatchError> {
    let (root_runtime_id, descendants) = runtime_path
        .split_first()
        .ok_or_else(|| no_effect("semantic target path is unavailable"))?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    let mut current = unsafe { automation.ElementFromHandle(window) }.map_err(|_| {
        before_effect_error(
            cancellation,
            deadline_at_ms,
            "semantic surface is unavailable",
        )
    })?;
    check_effect_boundary(cancellation, deadline_at_ms)?;
    if runtime_values(&current).map_err(|_| no_effect("semantic surface changed"))?
        != *root_runtime_id
    {
        return Err(no_effect("semantic surface changed"));
    }
    let walker = unsafe { automation.ControlViewWalker() }.map_err(|_| {
        before_effect_error(
            cancellation,
            deadline_at_ms,
            "semantic target path is unavailable",
        )
    })?;
    for target_runtime_id in descendants {
        check_effect_boundary(cancellation, deadline_at_ms)?;
        let Some(mut child) = optional_element(unsafe { walker.GetFirstChildElement(&current) })
            .map_err(|_| {
                before_effect_error(
                    cancellation,
                    deadline_at_ms,
                    "semantic target path is unavailable",
                )
            })?
        else {
            return Err(no_effect("semantic target path changed"));
        };
        let mut found = None;
        for index in 0..MAX_SEMANTIC_ELEMENTS {
            check_effect_boundary(cancellation, deadline_at_ms)?;
            if runtime_values(&child).is_ok_and(|runtime_id| runtime_id == *target_runtime_id) {
                if found.is_some() {
                    return Err(no_effect("semantic target path is ambiguous"));
                }
                found = Some(child.clone());
            }
            let Some(next) = optional_element(unsafe { walker.GetNextSiblingElement(&child) })
                .map_err(|_| {
                    before_effect_error(
                        cancellation,
                        deadline_at_ms,
                        "semantic target path is unavailable",
                    )
                })?
            else {
                break;
            };
            if index + 1 == MAX_SEMANTIC_ELEMENTS {
                return Err(no_effect("semantic target path is too large"));
            }
            child = next;
        }
        current = found.ok_or_else(|| no_effect("semantic target path changed"))?;
    }
    Ok(current)
}

fn element_window(
    automation: &IUIAutomation,
    element: &IUIAutomationElement,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<HWND, NativeError> {
    let walker = unsafe { automation.ControlViewWalker() }.map_err(|_| NativeError)?;
    let mut current = element.clone();
    for _ in 0..64 {
        if check_observation_boundary(cancellation, deadline_at_ms).is_err() {
            return Err(NativeError);
        }
        if let Ok(window) = unsafe { current.CurrentNativeWindowHandle() } {
            if !window.is_invalid() {
                let root = unsafe { GetAncestor(window, GA_ROOT) };
                return Ok(if root.is_invalid() { window } else { root });
            }
        }
        current = unsafe { walker.GetParentElement(&current) }.map_err(|_| NativeError)?;
    }
    Err(NativeError)
}

fn runtime_values(element: &IUIAutomationElement) -> Result<Vec<i32>, NativeError> {
    RuntimeId::from_element(element)?.values()
}

fn focused_identity(
    automation: &IUIAutomation,
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<FocusIdentity, NativeError> {
    if check_observation_boundary(cancellation, deadline_at_ms).is_err() {
        return Err(NativeError);
    }
    let focused = unsafe { automation.GetFocusedElement() }.map_err(|_| NativeError)?;
    if check_observation_boundary(cancellation, deadline_at_ms).is_err() {
        return Err(NativeError);
    }
    let (state, window) = describe_with_window(automation, &focused, cancellation, deadline_at_ms)?;
    if check_observation_boundary(cancellation, deadline_at_ms).is_err() {
        return Err(NativeError);
    }
    let fingerprint_hash = fingerprint(&state).map_err(|_| NativeError)?;
    let runtime_id = state.runtime_id;
    let process_id = state.process_id;
    let generation = state.process_generation;
    if window_process_id(window).ok() != Some(process_id)
        || process_generation(process_id).ok().as_deref() != Some(generation.as_str())
    {
        return Err(NativeError);
    }
    Ok(FocusIdentity {
        window,
        process_id,
        process_generation: generation,
        runtime_id,
        fingerprint_hash,
    })
}

fn focus_matches_foreground(
    window: HWND,
    process_id: u32,
    process_generation: &str,
    focused: &FocusIdentity,
) -> bool {
    focused.window == window
        && focused.process_id == process_id
        && focused.process_generation == process_generation
}

fn runtime_id_text(values: &[i32]) -> String {
    values
        .iter()
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn native_bounds(value: RECT) -> Result<NativeBounds, NativeError> {
    let width = value.right.checked_sub(value.left).ok_or(NativeError)?;
    let height = value.bottom.checked_sub(value.top).ok_or(NativeError)?;
    if width <= 0 || height <= 0 {
        return Err(NativeError);
    }
    Ok(NativeBounds {
        x: i64::from(value.left),
        y: i64::from(value.top),
        width: i64::from(width),
        height: i64::from(height),
    })
}

fn bounded_bstr(value: Option<BSTR>) -> Option<String> {
    value.map(|value| value.to_string()).and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty() && trimmed.len() <= 1_024).then(|| trimmed.to_string())
    })
}

fn hash_ui_value(value: &str) -> String {
    hash_bytes(value.as_bytes())
}

fn provider_timeout(deadline_at_ms: i64) -> u32 {
    u32::try_from(deadline_at_ms.saturating_sub(now_ms()))
        .unwrap_or(MAX_PROVIDER_TIMEOUT_MS)
        .clamp(1, MAX_PROVIDER_TIMEOUT_MS)
}

fn window_is_uncloaked(window: HWND) -> Result<bool, NativeError> {
    let mut cloaked = 0u32;
    unsafe {
        DwmGetWindowAttribute(
            window,
            DWMWA_CLOAKED,
            std::ptr::from_mut(&mut cloaked).cast(),
            u32::try_from(std::mem::size_of_val(&cloaked)).map_err(|_| NativeError)?,
        )
    }
    .map_err(|_| NativeError)?;
    Ok(cloak_state_is_uncloaked(cloaked))
}

fn cloak_state_is_uncloaked(cloaked: u32) -> bool {
    cloaked == 0
}

fn process_generation(process_id: u32) -> Result<String, NativeError> {
    let process = ProcessHandle::open(process_id)?;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) }
        .map_err(|_| NativeError)?;
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if value == 0 {
        return Err(NativeError);
    }
    Ok(value.to_string())
}

fn window_process_id(window: HWND) -> Result<u32, ProtocolError> {
    let mut process_id = 0u32;
    if unsafe { GetWindowThreadProcessId(window, Some(&mut process_id)) } == 0 || process_id == 0 {
        return Err(ProtocolError::TargetNotFound(
            "foreground process is unavailable".to_string(),
        ));
    }
    Ok(process_id)
}

fn window_identity(window: HWND, process_generation: &str) -> Result<String, NativeError> {
    hash_serializable(&(BACKEND, window.0 as usize, process_generation)).map_err(|_| NativeError)
}

fn fingerprint(state: &ElementState) -> Result<String, ProtocolError> {
    semantic_fingerprint(&(
        &state.runtime_id,
        state.process_id,
        &state.process_generation,
        &state.window_id,
        &state.role,
        &state.name,
        &state.bounds,
        state.visible,
        state.enabled,
        state.invokable,
        state.editable,
        state.horizontally_scrollable,
        state.vertically_scrollable,
    ))
    .map_err(|_| ProtocolError::Executor("semantic snapshot failed".to_string()))
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

fn observation_call_error(cancellation: &CancellationToken, deadline_at_ms: i64) -> ProtocolError {
    observation_boundary_error(
        cancellation,
        deadline_at_ms,
        ProtocolError::Executor("accessibility provider call failed".to_string()),
    )
}

fn observation_boundary_error(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
    fallback: ProtocolError,
) -> ProtocolError {
    match check_observation_boundary(cancellation, deadline_at_ms) {
        Err(error) => error,
        Ok(()) => fallback,
    }
}

fn before_effect_error(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
    message: &str,
) -> DispatchError {
    match check_effect_boundary(cancellation, deadline_at_ms) {
        Err(error) => error,
        Ok(()) => DispatchError {
            message: message.to_string(),
            effect: EffectKnowledge::NoEffect,
            code: FailureCode::DispatchFailed,
        },
    }
}

fn check_effect_boundary(
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
            "accessibility action completed at the cancellation or deadline boundary",
        ));
    }
    Ok(())
}

fn receipt() -> DispatchReceipt {
    DispatchReceipt {
        backend: BACKEND.to_string(),
        fallback_chain: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_ids_are_stable_and_bounded() {
        assert_eq!(runtime_id_text(&[42, -7, 9]), "42.-7.9");
        assert_eq!(runtime_id_text(&[]), "");
    }

    #[test]
    fn runtime_path_budget_counts_integers_and_serialized_bytes() {
        let path = vec![vec![0, -1, i32::MIN], vec![42]];
        assert_eq!(
            runtime_path_serialized_bytes(&path),
            serde_json::to_vec(&path).ok().map(|value| value.len())
        );
        let mut budget = RuntimePathBudget {
            integers: MAX_RUNTIME_PATH_INTEGERS - path.iter().map(Vec::len).sum::<usize>(),
            bytes: MAX_RUNTIME_PATH_BYTES
                - runtime_path_serialized_bytes(&path).expect("path size"),
        };
        budget.charge(&path).expect("exact budget");
        assert!(budget.charge(&path).is_err());
    }

    #[test]
    fn private_mapping_serialization_is_bounded() {
        let mapping = Mapping {
            protocol_version: PROTOCOL_VERSION,
            observation_id: "a".repeat(64),
            generation: 1,
            provenance_hash: "b".repeat(64),
            process_id: 1,
            process_generation: "generation".to_string(),
            surface_id: "x".repeat(MAX_PRIVATE_MAPPING_BYTES),
            window_handle: 1,
            window_id: "c".repeat(64),
            display_geometry_hash: "d".repeat(64),
            observed_at_ms: 1,
            expires_at_ms: 2,
            entries: Vec::new(),
        };
        assert!(ensure_serialized_mapping_budget(&mapping).is_err());
    }

    #[test]
    fn shared_context_hash_binds_focused_provider_identity() {
        let original = shared_context_identity_hash(
            (1, 2, "foreground-generation"),
            (3, 4),
            (1, 2, "focused-generation", &[5, 6], "fingerprint-a"),
        )
        .expect("context identity must hash");
        let changed = shared_context_identity_hash(
            (1, 2, "foreground-generation"),
            (3, 4),
            (1, 2, "focused-generation", &[5, 7], "fingerprint-a"),
        )
        .expect("context identity must hash");
        let replaced = shared_context_identity_hash(
            (1, 2, "foreground-generation"),
            (3, 4),
            (1, 2, "focused-generation", &[5, 6], "fingerprint-b"),
        )
        .expect("context identity must hash");
        assert_ne!(original, changed);
        assert_ne!(original, replaced);
    }

    #[test]
    fn shared_context_errors_preserve_boundary_classification() {
        let cancellation = CancellationToken::default();
        assert!(matches!(
            shared_context_error(&cancellation, 0),
            ProtocolError::ObservationExpired
        ));
        assert!(matches!(
            shared_context_error(&cancellation, i64::MAX),
            ProtocolError::Executor(_)
        ));
        cancellation.cancel();
        assert!(matches!(
            shared_context_error(&cancellation, i64::MAX),
            ProtocolError::ObservationCancelled
        ));
    }

    #[test]
    fn display_intersections_reject_offscreen_surfaces() {
        let bounds = NativeBounds {
            x: 10,
            y: 10,
            width: 20,
            height: 20,
        };
        let displays = serde_json::json!([{
            "display_id": "display",
            "x": 0,
            "y": 0,
            "width": 100,
            "height": 100
        }]);
        assert!(intersects_displays(&bounds, &displays));
        let offscreen = NativeBounds { x: 100, ..bounds };
        assert!(!intersects_displays(&offscreen, &displays));
    }

    #[test]
    fn mappings_reject_duplicate_targets() {
        let entry = MappingEntry {
            element_id: "a".repeat(64),
            runtime_id: vec![1, 2],
            runtime_path: vec![vec![1], vec![1, 2]],
            fingerprint_hash: "b".repeat(64),
            unambiguous: false,
            stable: true,
        };
        let entries = [entry.clone(), entry];
        assert!(entries.iter().all(|entry| !entry.unambiguous));
        let persisted: MappingEntry = serde_json::from_slice(
            &serde_json::to_vec(&entries[0]).expect("mapping entry must serialize"),
        )
        .expect("mapping entry must deserialize");
        assert!(ensure_entry_unambiguous(&persisted).is_err());
        assert_eq!(
            entries
                .iter()
                .filter(|candidate| candidate.element_id == "a".repeat(64))
                .count(),
            2
        );
    }

    #[test]
    fn focus_must_belong_to_exact_foreground_identity() {
        let mut foreground_storage = 0u8;
        let foreground = HWND(std::ptr::from_mut(&mut foreground_storage).cast());
        let mut other_storage = 0u8;
        let other = HWND(std::ptr::from_mut(&mut other_storage).cast());
        let focused = FocusIdentity {
            window: foreground,
            process_id: 2,
            process_generation: "generation".to_string(),
            runtime_id: vec![3],
            fingerprint_hash: "fingerprint".to_string(),
        };
        assert!(focus_matches_foreground(
            foreground,
            2,
            "generation",
            &focused
        ));
        assert!(!focus_matches_foreground(other, 2, "generation", &focused));
        assert!(!focus_matches_foreground(
            foreground,
            5,
            "generation",
            &focused
        ));
        assert!(!focus_matches_foreground(
            foreground,
            2,
            "changed-generation",
            &focused
        ));
    }

    #[test]
    fn ui_values_are_only_exposed_as_hashes() {
        let value = "sensitive value";
        let hash = hash_ui_value(value);
        assert_eq!(hash.len(), 64);
        assert_ne!(hash, value);
        assert_eq!(hash, hash_ui_value(value));
    }

    #[test]
    fn provider_timeouts_are_bounded() {
        assert_eq!(provider_timeout(i64::MAX), MAX_PROVIDER_TIMEOUT_MS);
        assert!((1..=MAX_PROVIDER_TIMEOUT_MS).contains(&provider_timeout(now_ms())));
    }

    #[test]
    fn only_zero_dwm_cloak_state_is_uncloaked() {
        assert!(cloak_state_is_uncloaked(0));
        assert!(!cloak_state_is_uncloaked(1));
        assert!(!cloak_state_is_uncloaked(2));
        assert!(!cloak_state_is_uncloaked(4));
        assert!(!cloak_state_is_uncloaked(7));
    }

    #[test]
    fn sibling_walks_reject_cycles_and_full_queues() {
        let mut siblings = BTreeSet::new();
        assert!(accept_sibling(0, &mut siblings, vec![1, 2]));
        assert!(!accept_sibling(1, &mut siblings, vec![1, 2]));
        assert!(!accept_sibling(
            MAX_SEMANTIC_ELEMENTS,
            &mut siblings,
            vec![3, 4]
        ));
    }
}
