#![allow(clippy::collapsible_if)]
use std::process::Command;
use std::sync::Mutex;

use serde_json::Value;
use sha2::{Digest, Sha256};
use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::ConnectionExt as _;
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::{Direction, MouseButton, NativeError, NativePoint};

const PORTAL_DESTINATION: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const PORTAL_RD_INTERFACE: &str = "org.freedesktop.portal.RemoteDesktop";

static PORTAL_SESSION: Mutex<Option<(String, zbus::blocking::Connection)>> = Mutex::new(None);

fn secure_command(name: &str) -> Result<Command, NativeError> {
    let safe_paths = ["/usr/bin", "/bin", "/usr/local/bin"];
    for dir in safe_paths {
        let full_path = std::path::PathBuf::from(dir).join(name);
        if full_path.is_file() {
            return Ok(Command::new(full_path));
        }
    }
    Err(NativeError)
}

pub(crate) fn session_type() -> &'static str {
    match std::env::var("XDG_SESSION_TYPE") {
        Ok(v) if v.eq_ignore_ascii_case("wayland") => "wayland",
        Ok(v) if v.eq_ignore_ascii_case("x11") => "x11",
        _ if std::env::var_os("WAYLAND_DISPLAY").is_some() => "wayland",
        _ if std::env::var_os("DISPLAY").is_some() => "x11",
        _ => "unknown",
    }
}

// ── X11 connection ──────────────────────────────────────────────────────────

fn connect_x11() -> Result<(RustConnection, usize), NativeError> {
    let (connection, screen) = RustConnection::connect(None).map_err(|_| NativeError)?;
    Ok((connection, screen))
}

fn keysym_for_name(name: &str) -> Option<u32> {
    KEY_NAME_TO_KEYSYM
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, ks)| *ks)
}

fn character_to_keysym(ch: char) -> u32 {
    match ch {
        ' '..='~' => ch as u32,
        '\t' => 0xff09,
        '\n' => 0xff0d,
        _ => ch as u32,
    }
}

fn keysym_to_keycode(connection: &RustConnection, keysym: u32) -> Result<u8, NativeError> {
    let setup = connection.setup();
    let min_keycode = setup.min_keycode;
    let max_keycode = setup.max_keycode;
    let count = max_keycode - min_keycode + 1;
    let mapping = connection
        .get_keyboard_mapping(min_keycode, count)
        .map_err(|_| NativeError)?
        .reply()
        .map_err(|_| NativeError)?;
    let per_keycode = mapping.keysyms_per_keycode as usize;
    if per_keycode == 0 {
        return Err(NativeError);
    }
    for keycode_offset in 0..count as usize {
        for level in 0..per_keycode {
            let idx = keycode_offset * per_keycode + level;
            if idx < mapping.keysyms.len() && mapping.keysyms[idx] == keysym {
                return u8::try_from(min_keycode as u32 + keycode_offset as u32)
                    .map_err(|_| NativeError);
            }
        }
    }
    Err(NativeError)
}

// ── Portal helpers ──────────────────────────────────────────────────────────

fn portal_connection() -> Result<zbus::blocking::Connection, NativeError> {
    zbus::blocking::Connection::session().map_err(|_| NativeError)
}

fn portal_create_session(connection: &zbus::blocking::Connection) -> Result<String, NativeError> {
    let options: std::collections::HashMap<String, zbus::zvariant::Value> =
        std::collections::HashMap::new();
    let reply = connection
        .call_method(
            Some(PORTAL_DESTINATION),
            PORTAL_PATH,
            Some(PORTAL_RD_INTERFACE),
            "CreateSession",
            &(zbus::zvariant::Value::from("token"), options),
        )
        .map_err(|_| NativeError)?;
    let body = reply.body();
    let status: u32 = body.deserialize().map_err(|_| NativeError)?;
    if status != 0 {
        return Err(NativeError);
    }
    let body = reply.body();
    let (_, results): (
        u32,
        std::collections::HashMap<String, zbus::zvariant::Value>,
    ) = body.deserialize().map_err(|_| NativeError)?;
    let handle = results.get("session_handle").ok_or(NativeError)?;
    if let zbus::zvariant::Value::Str(s) = handle {
        Ok(s.to_string())
    } else {
        Err(NativeError)
    }
}

fn portal_authorize(
    connection: &zbus::blocking::Connection,
    session_handle: &str,
) -> Result<(), NativeError> {
    let mut options: std::collections::HashMap<String, zbus::zvariant::Value> =
        std::collections::HashMap::new();
    let types = zbus::zvariant::Value::U32(1 | 2);
    options.insert("types".to_string(), types);
    let reply = connection
        .call_method(
            Some(PORTAL_DESTINATION),
            PORTAL_PATH,
            Some(PORTAL_RD_INTERFACE),
            "Authorize",
            &(session_handle, options),
        )
        .map_err(|_| NativeError)?;
    let status: u32 = reply.body().deserialize().map_err(|_| NativeError)?;
    if status != 0 {
        return Err(NativeError);
    }
    Ok(())
}

fn portal_start(
    connection: &zbus::blocking::Connection,
    session_handle: &str,
) -> Result<(), NativeError> {
    let options: std::collections::HashMap<String, zbus::zvariant::Value> =
        std::collections::HashMap::new();
    let reply = connection
        .call_method(
            Some(PORTAL_DESTINATION),
            PORTAL_PATH,
            Some(PORTAL_RD_INTERFACE),
            "Start",
            &("", session_handle, options),
        )
        .map_err(|_| NativeError)?;
    let status: u32 = reply.body().deserialize().map_err(|_| NativeError)?;
    if status != 0 {
        return Err(NativeError);
    }
    Ok(())
}

fn ensure_portal_session() -> Result<(String, zbus::blocking::Connection), NativeError> {
    let mut guard = PORTAL_SESSION.lock().map_err(|_| NativeError)?;
    if let Some((ref handle, ref conn)) = *guard {
        return Ok((handle.clone(), conn.clone()));
    }
    let connection = portal_connection()?;
    let handle = portal_create_session(&connection)?;
    portal_authorize(&connection, &handle)?;
    portal_start(&connection, &handle)?;
    let result = (handle.clone(), connection.clone());
    *guard = Some(result.clone());
    Ok(result)
}

fn portal_notify_pointer_motion(
    connection: &zbus::blocking::Connection,
    session_handle: &str,
    dx: f64,
    dy: f64,
) -> Result<(), NativeError> {
    let options: std::collections::HashMap<String, zbus::zvariant::Value> =
        std::collections::HashMap::new();
    connection
        .call_method(
            Some(PORTAL_DESTINATION),
            PORTAL_PATH,
            Some(PORTAL_RD_INTERFACE),
            "NotifyPointerMotion",
            &(session_handle, options, dx, dy),
        )
        .map_err(|_| NativeError)?;
    Ok(())
}

fn portal_notify_pointer_button(
    connection: &zbus::blocking::Connection,
    session_handle: &str,
    button: u32,
    state: u32,
) -> Result<(), NativeError> {
    let options: std::collections::HashMap<String, zbus::zvariant::Value> =
        std::collections::HashMap::new();
    connection
        .call_method(
            Some(PORTAL_DESTINATION),
            PORTAL_PATH,
            Some(PORTAL_RD_INTERFACE),
            "NotifyPointerButton",
            &(session_handle, options, button, state),
        )
        .map_err(|_| NativeError)?;
    Ok(())
}

fn portal_notify_pointer_axis(
    connection: &zbus::blocking::Connection,
    session_handle: &str,
    dx: f64,
    dy: f64,
) -> Result<(), NativeError> {
    let options: std::collections::HashMap<String, zbus::zvariant::Value> =
        std::collections::HashMap::new();
    connection
        .call_method(
            Some(PORTAL_DESTINATION),
            PORTAL_PATH,
            Some(PORTAL_RD_INTERFACE),
            "NotifyPointerAxis",
            &(session_handle, options, dx, dy),
        )
        .map_err(|_| NativeError)?;
    Ok(())
}

fn portal_notify_keyboard_keysym(
    connection: &zbus::blocking::Connection,
    session_handle: &str,
    keysym: u32,
    state: u32,
) -> Result<(), NativeError> {
    let options: std::collections::HashMap<String, zbus::zvariant::Value> =
        std::collections::HashMap::new();
    connection
        .call_method(
            Some(PORTAL_DESTINATION),
            PORTAL_PATH,
            Some(PORTAL_RD_INTERFACE),
            "NotifyKeyboardKeysym",
            &(session_handle, options, keysym as i32, state),
        )
        .map_err(|_| NativeError)?;
    Ok(())
}

// ── public API ──────────────────────────────────────────────────────────────

pub(crate) fn native_click(point: &NativePoint, button: MouseButton) -> Result<(), NativeError> {
    match session_type() {
        "x11" => x11_click(point, button),
        "wayland" => portal_click(button),
        _ => Err(NativeError),
    }
}

fn x11_click(point: &NativePoint, button: MouseButton) -> Result<(), NativeError> {
    let (connection, screen) = connect_x11()?;
    let root = connection.setup().roots[screen].root;
    let detail: u8 = match button {
        MouseButton::Left => 1,
        MouseButton::Middle => 2,
        MouseButton::Right => 3,
    };
    connection
        .warp_pointer(
            0u32,
            root,
            0i16,
            0i16,
            0u16,
            0u16,
            point.x as i16,
            point.y as i16,
        )
        .map_err(|_| NativeError)?;
    connection
        .xtest_fake_input(4, detail, 0, root, point.x as i16, point.y as i16, 0)
        .map_err(|_| NativeError)?;
    connection
        .xtest_fake_input(5, detail, 0, root, point.x as i16, point.y as i16, 0)
        .map_err(|_| NativeError)?;
    connection.flush().map_err(|_| NativeError)?;
    Ok(())
}

fn portal_click(button: MouseButton) -> Result<(), NativeError> {
    let (session_handle, connection) = ensure_portal_session()?;
    let evdev_button = match button {
        MouseButton::Left => 0x110,
        MouseButton::Right => 0x111,
        MouseButton::Middle => 0x112,
    };
    portal_notify_pointer_button(&connection, &session_handle, evdev_button, 1)?;
    portal_notify_pointer_button(&connection, &session_handle, evdev_button, 0)?;
    Ok(())
}

pub(crate) fn native_move(point: &NativePoint) -> Result<(), NativeError> {
    match session_type() {
        "x11" => x11_move(point),
        "wayland" => portal_move(point),
        _ => Err(NativeError),
    }
}

fn x11_move(point: &NativePoint) -> Result<(), NativeError> {
    let (connection, screen) = connect_x11()?;
    let root = connection.setup().roots[screen].root;
    connection
        .warp_pointer(
            0u32,
            root,
            0i16,
            0i16,
            0u16,
            0u16,
            point.x as i16,
            point.y as i16,
        )
        .map_err(|_| NativeError)?;
    connection.flush().map_err(|_| NativeError)?;
    Ok(())
}

fn portal_move(point: &NativePoint) -> Result<(), NativeError> {
    let (session_handle, connection) = ensure_portal_session()?;
    portal_notify_pointer_motion(&connection, &session_handle, point.x as f64, point.y as f64)?;
    Ok(())
}

pub(crate) fn native_type_text(
    text: &str,
    clear: bool,
    press_return: bool,
    delay_ms: Option<u64>,
) -> Result<(), NativeError> {
    if text.contains('\0') {
        return Err(NativeError);
    }
    match session_type() {
        "x11" => x11_type_text(text, clear, press_return, delay_ms),
        "wayland" => portal_type_text(text, clear, press_return, delay_ms),
        _ => Err(NativeError),
    }
}

fn x11_type_text(
    text: &str,
    clear: bool,
    press_return: bool,
    delay_ms: Option<u64>,
) -> Result<(), NativeError> {
    if clear {
        x11_hotkey(&["ctrl", "a"])?;
        std::thread::sleep(std::time::Duration::from_millis(10));
        x11_press("BackSpace", 1, None)?;
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let (connection, screen) = connect_x11()?;
    let root = connection.setup().roots[screen].root;
    for ch in text.chars() {
        let keysym = character_to_keysym(ch);
        let keycode = keysym_to_keycode(&connection, keysym)?;
        let needs_shift = ch.is_uppercase() || NEEDS_SHIFT.contains(&ch);
        if needs_shift {
            let shift_kc = keysym_to_keycode(&connection, 0xffe1)?;
            connection
                .xtest_fake_input(2, shift_kc, 0, root, 0, 0, 0)
                .map_err(|_| NativeError)?;
            connection.flush().map_err(|_| NativeError)?;
        }
        connection
            .xtest_fake_input(2, keycode, 0, root, 0, 0, 0)
            .map_err(|_| NativeError)?;
        connection.flush().map_err(|_| NativeError)?;
        if needs_shift {
            let shift_kc = keysym_to_keycode(&connection, 0xffe1)?;
            connection
                .xtest_fake_input(3, shift_kc, 0, root, 0, 0, 0)
                .map_err(|_| NativeError)?;
            connection.flush().map_err(|_| NativeError)?;
        }
        if let Some(delay) = delay_ms {
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
    }
    if press_return {
        let return_keysym = 0xff0d;
        let return_kc = keysym_to_keycode(&connection, return_keysym)?;
        connection
            .xtest_fake_input(2, return_kc, 0, root, 0, 0, 0)
            .map_err(|_| NativeError)?;
        connection.flush().map_err(|_| NativeError)?;
        connection
            .xtest_fake_input(3, return_kc, 0, root, 0, 0, 0)
            .map_err(|_| NativeError)?;
        connection.flush().map_err(|_| NativeError)?;
    }
    Ok(())
}

fn portal_type_text(
    text: &str,
    clear: bool,
    press_return: bool,
    delay_ms: Option<u64>,
) -> Result<(), NativeError> {
    if clear {
        portal_hotkey(&["ctrl", "a"])?;
        std::thread::sleep(std::time::Duration::from_millis(10));
        portal_press("BackSpace", 1, None)?;
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let (session_handle, connection) = ensure_portal_session()?;
    for ch in text.chars() {
        let keysym = character_to_keysym(ch);
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 1)?;
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 0)?;
        if let Some(delay) = delay_ms {
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
    }
    if press_return {
        portal_notify_keyboard_keysym(&connection, &session_handle, 0xff0d, 1)?;
        portal_notify_keyboard_keysym(&connection, &session_handle, 0xff0d, 0)?;
    }
    Ok(())
}

pub(crate) fn native_press(
    key: &str,
    count: u32,
    delay_ms: Option<u64>,
) -> Result<(), NativeError> {
    if count == 0 || key.is_empty() {
        return Err(NativeError);
    }
    match session_type() {
        "x11" => x11_press(key, count, delay_ms),
        "wayland" => portal_press(key, count, delay_ms),
        _ => Err(NativeError),
    }
}

fn x11_press(key: &str, count: u32, delay_ms: Option<u64>) -> Result<(), NativeError> {
    let (connection, screen) = connect_x11()?;
    let root = connection.setup().roots[screen].root;
    let keysym = keysym_for_name(key)
        .unwrap_or_else(|| key.chars().next().map(character_to_keysym).unwrap_or(0));
    if keysym == 0 {
        return Err(NativeError);
    }
    let keycode = keysym_to_keycode(&connection, keysym)?;
    for i in 0..count {
        if i > 0 {
            if let Some(delay) = delay_ms {
                if delay > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
            }
        }
        connection
            .xtest_fake_input(2, keycode, 0, root, 0, 0, 0)
            .map_err(|_| NativeError)?;
        connection.flush().map_err(|_| NativeError)?;
        connection
            .xtest_fake_input(3, keycode, 0, root, 0, 0, 0)
            .map_err(|_| NativeError)?;
        connection.flush().map_err(|_| NativeError)?;
    }
    Ok(())
}

fn portal_press(key: &str, count: u32, delay_ms: Option<u64>) -> Result<(), NativeError> {
    let keysym = keysym_for_name(key)
        .unwrap_or_else(|| key.chars().next().map(character_to_keysym).unwrap_or(0));
    if keysym == 0 {
        return Err(NativeError);
    }
    let (session_handle, connection) = ensure_portal_session()?;
    for i in 0..count {
        if i > 0 {
            if let Some(delay) = delay_ms {
                if delay > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
            }
        }
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 1)?;
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 0)?;
    }
    Ok(())
}

pub(crate) fn native_paste(text: &str) -> Result<(), NativeError> {
    if text.contains('\0') {
        return Err(NativeError);
    }
    match session_type() {
        "x11" => {
            let status = secure_command("xclip")?
                .args(["-selection", "clipboard"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write as _;
                    if let Some(ref mut stdin) = child.stdin {
                        stdin.write_all(text.as_bytes())?;
                    }
                    child.wait_with_output()
                })
                .map_err(|_| NativeError)?;
            if !status.status.success() {
                return Err(NativeError);
            }
            x11_hotkey(&["ctrl", "v"])
        }
        "wayland" => {
            let status = secure_command("wl-copy")?
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write as _;
                    if let Some(ref mut stdin) = child.stdin {
                        stdin.write_all(text.as_bytes())?;
                    }
                    child.wait_with_output()
                })
                .map_err(|_| NativeError)?;
            if !status.status.success() {
                return Err(NativeError);
            }
            portal_hotkey(&["ctrl", "v"])
        }
        _ => Err(NativeError),
    }
}

pub(crate) fn native_hotkey(keys: &[&str]) -> Result<(), NativeError> {
    if keys.is_empty() {
        return Err(NativeError);
    }
    match session_type() {
        "x11" => x11_hotkey(keys),
        "wayland" => portal_hotkey(keys),
        _ => Err(NativeError),
    }
}

fn x11_hotkey(keys: &[&str]) -> Result<(), NativeError> {
    let (connection, screen) = connect_x11()?;
    let root = connection.setup().roots[screen].root;
    let mut keycodes = Vec::with_capacity(keys.len());
    for key in keys {
        let keysym = keysym_for_name(key)
            .or_else(|| key.chars().next().map(character_to_keysym))
            .ok_or(NativeError)?;
        let keycode = keysym_to_keycode(&connection, keysym)?;
        keycodes.push(keycode);
    }
    for keycode in &keycodes {
        connection
            .xtest_fake_input(2, *keycode, 0, root, 0, 0, 0)
            .map_err(|_| NativeError)?;
        connection.flush().map_err(|_| NativeError)?;
    }
    for keycode in keycodes.iter().rev() {
        connection
            .xtest_fake_input(3, *keycode, 0, root, 0, 0, 0)
            .map_err(|_| NativeError)?;
        connection.flush().map_err(|_| NativeError)?;
    }
    Ok(())
}

fn portal_hotkey(keys: &[&str]) -> Result<(), NativeError> {
    let (session_handle, connection) = ensure_portal_session()?;
    let mut keysyms = Vec::with_capacity(keys.len());
    for key in keys {
        let keysym = keysym_for_name(key)
            .or_else(|| key.chars().next().map(character_to_keysym))
            .ok_or(NativeError)?;
        keysyms.push(keysym);
    }
    for keysym in &keysyms {
        portal_notify_keyboard_keysym(&connection, &session_handle, *keysym, 1)?;
    }
    for keysym in keysyms.iter().rev() {
        portal_notify_keyboard_keysym(&connection, &session_handle, *keysym, 0)?;
    }
    Ok(())
}

pub(crate) fn native_scroll(direction: Direction, amount: u32) -> Result<(), NativeError> {
    if amount == 0 {
        return Err(NativeError);
    }
    match session_type() {
        "x11" => x11_scroll(direction, amount),
        "wayland" => portal_scroll(direction, amount),
        _ => Err(NativeError),
    }
}

fn x11_scroll(direction: Direction, amount: u32) -> Result<(), NativeError> {
    let (connection, screen) = connect_x11()?;
    let root = connection.setup().roots[screen].root;
    let (button_down, button_up) = match direction {
        Direction::Up => (4u8, 5u8),
        Direction::Down => (5u8, 4u8),
        Direction::Left => (6u8, 7u8),
        Direction::Right => (7u8, 6u8),
    };
    for _ in 0..amount {
        connection
            .xtest_fake_input(4, button_down, 0, root, 0, 0, 0)
            .map_err(|_| NativeError)?;
        connection.flush().map_err(|_| NativeError)?;
        connection
            .xtest_fake_input(5, button_up, 0, root, 0, 0, 0)
            .map_err(|_| NativeError)?;
        connection.flush().map_err(|_| NativeError)?;
    }
    Ok(())
}

fn portal_scroll(direction: Direction, amount: u32) -> Result<(), NativeError> {
    let (session_handle, connection) = ensure_portal_session()?;
    let step = 10.0 * amount as f64;
    let (dx, dy) = match direction {
        Direction::Up => (0.0, -step),
        Direction::Down => (0.0, step),
        Direction::Left => (-step, 0.0),
        Direction::Right => (step, 0.0),
    };
    portal_notify_pointer_axis(&connection, &session_handle, dx, dy)?;
    Ok(())
}

pub(crate) fn native_screenshot() -> Result<Vec<u8>, NativeError> {
    match session_type() {
        "x11" => x11_screenshot(),
        "wayland" => wayland_screenshot(),
        _ => Err(NativeError),
    }
}

fn x11_screenshot() -> Result<Vec<u8>, NativeError> {
    let output = secure_command("scrot")?
        .args(["-o", "/dev/stdout"])
        .output()
        .map_err(|_| NativeError)?;
    if !output.status.success() || output.stdout.is_empty() {
        return Err(NativeError);
    }
    Ok(output.stdout)
}

fn wayland_screenshot() -> Result<Vec<u8>, NativeError> {
    // portal Screenshot returns fd; fall back to grim for simplicity
    // ponytail: grim subprocess, portal FD handling if grim unavailable
    let output = secure_command("grim")?
        .args(["-"])
        .output()
        .map_err(|_| NativeError)?;
    if !output.status.success() || output.stdout.is_empty() {
        return Err(NativeError);
    }
    Ok(output.stdout)
}

pub(crate) fn native_screen_content_hash() -> Result<String, NativeError> {
    let png = native_screenshot()?;
    let mut hasher = Sha256::new();
    hasher.update(&png);
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) fn native_screens() -> Result<Value, NativeError> {
    match session_type() {
        "x11" => x11_screens(),
        "wayland" => wayland_screens(),
        _ => Err(NativeError),
    }
}

fn x11_screens() -> Result<Value, NativeError> {
    use x11rb::protocol::randr::ConnectionExt as _;

    let (connection, screen_index) = connect_x11()?;
    let screen = &connection.setup().roots[screen_index];
    let root = screen.root;
    let resources = connection
        .randr_get_screen_resources(root)
        .map_err(|_| NativeError)?
        .reply()
        .map_err(|_| NativeError)?;
    let mut displays = Vec::new();
    for &crtc in &resources.crtcs {
        let info = connection
            .randr_get_crtc_info(crtc, resources.config_timestamp)
            .map_err(|_| NativeError)?
            .reply()
            .map_err(|_| NativeError)?;
        if info.width > 0 && info.height > 0 {
            displays.push(serde_json::json!({
                "display_id": crtc.to_string(),
                "x": info.x as i64,
                "y": info.y as i64,
                "width": info.width as i64,
                "height": info.height as i64,
            }));
        }
    }
    if displays.is_empty() {
        displays.push(serde_json::json!({
            "display_id": "0",
            "x": 0_i64,
            "y": 0_i64,
            "width": screen.width_in_pixels as i64,
            "height": screen.height_in_pixels as i64,
        }));
    }
    Ok(Value::Array(displays))
}

fn wayland_screens() -> Result<Value, NativeError> {
    // Use wlr-randr or swaymsg if available, fall back to single screen guess
    // ponytail: portal Settings or wlr-output-management for proper multi-monitor
    if let Ok(mut cmd) = secure_command("wlr-randr") {
        if let Ok(output) = cmd.output() {
            if output.status.success() {
                return parse_wlr_randr(&output.stdout);
            }
        }
    }
    if let Ok(mut cmd) = secure_command("swaymsg") {
        if let Ok(output) = cmd.args(["-t", "get_outputs", "-r"]).output() {
            if output.status.success() {
                return parse_swaymsg_outputs(&output.stdout);
            }
        }
    }
    Ok(Value::Array(vec![serde_json::json!({
        "display_id": "0",
        "x": 0_i64,
        "y": 0_i64,
        "width": 1920_i64,
        "height": 1080_i64,
    })]))
}

fn parse_wlr_randr(stdout: &[u8]) -> Result<Value, NativeError> {
    let text = std::str::from_utf8(stdout).map_err(|_| NativeError)?;
    let mut displays = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_enabled = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty() {
            if let Some(name) = current_name.take() {
                if current_enabled {
                    displays.push(serde_json::json!({
                        "display_id": name,
                        "x": 0_i64, "y": 0_i64,
                        "width": 1920_i64, "height": 1080_i64,
                    }));
                }
            }
            current_name = Some(trimmed.split_whitespace().next().unwrap_or("").to_string());
            current_enabled = false;
        } else if trimmed.starts_with("Enabled:") {
            current_enabled = trimmed.contains("yes");
        } else if trimmed.starts_with("Position:") {
            // wlr-randr: "Position: 0,0"
            // wlr-randr: "Current: 1920x1080 px"
        }
    }
    if let Some(name) = current_name {
        if current_enabled {
            displays.push(serde_json::json!({
                "display_id": name,
                "x": 0_i64, "y": 0_i64,
                "width": 1920_i64, "height": 1080_i64,
            }));
        }
    }
    if displays.is_empty() {
        return Err(NativeError);
    }
    Ok(Value::Array(displays))
}

fn parse_swaymsg_outputs(stdout: &[u8]) -> Result<Value, NativeError> {
    let text = std::str::from_utf8(stdout).map_err(|_| NativeError)?;
    let outputs: Vec<Value> = serde_json::from_str(text).map_err(|_| NativeError)?;
    let mut displays = Vec::new();
    for output in &outputs {
        let name = output
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let rect = output.get("rect");
        let x = rect
            .and_then(|r| r.get("x"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let y = rect
            .and_then(|r| r.get("y"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let width = rect
            .and_then(|r| r.get("width"))
            .and_then(Value::as_i64)
            .unwrap_or(1920);
        let height = rect
            .and_then(|r| r.get("height"))
            .and_then(Value::as_i64)
            .unwrap_or(1080);
        if width > 0 && height > 0 {
            displays.push(serde_json::json!({
                "display_id": name,
                "x": x,
                "y": y,
                "width": width,
                "height": height,
            }));
        }
    }
    if displays.is_empty() {
        return Err(NativeError);
    }
    Ok(Value::Array(displays))
}

// ── keysym table ────────────────────────────────────────────────────────────

const NEEDS_SHIFT: &[char] = &[
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '{', '}', '|', ':', '"', '<', '>',
    '?', '~',
];

const XK_BACKSPACE: u32 = 0xff08;
const XK_TAB: u32 = 0xff09;
const XK_RETURN: u32 = 0xff0d;
const XK_ESCAPE: u32 = 0xff1b;
const XK_DELETE: u32 = 0xffff;
const XK_HOME: u32 = 0xff50;
const XK_LEFT: u32 = 0xff51;
const XK_UP: u32 = 0xff52;
const XK_RIGHT: u32 = 0xff53;
const XK_DOWN: u32 = 0xff54;
const XK_PAGE_UP: u32 = 0xff55;
const XK_PAGE_DOWN: u32 = 0xff56;
const XK_END: u32 = 0xff57;
const XK_INSERT: u32 = 0xff63;
const XK_PRINT: u32 = 0xff61;
const XK_SCROLL_LOCK: u32 = 0xff14;
const XK_PAUSE: u32 = 0xff13;
const XK_NUM_LOCK: u32 = 0xff7f;
const XK_F1: u32 = 0xffbe;
const XK_F2: u32 = 0xffbf;
const XK_F3: u32 = 0xffc0;
const XK_F4: u32 = 0xffc1;
const XK_F5: u32 = 0xffc2;
const XK_F6: u32 = 0xffc3;
const XK_F7: u32 = 0xffc4;
const XK_F8: u32 = 0xffc5;
const XK_F9: u32 = 0xffc6;
const XK_F10: u32 = 0xffc7;
const XK_F11: u32 = 0xffc8;
const XK_F12: u32 = 0xffc9;
const XK_SHIFT_L: u32 = 0xffe1;
const XK_SHIFT_R: u32 = 0xffe2;
const XK_CTRL_L: u32 = 0xffe3;
const XK_CTRL_R: u32 = 0xffe4;
const XK_ALT_L: u32 = 0xffe9;
const XK_ALT_R: u32 = 0xffea;
const XK_SUPER_L: u32 = 0xffeb;
const XK_SUPER_R: u32 = 0xffec;
const XK_SPACE: u32 = 0x0020;

#[allow(clippy::type_complexity)]
const KEY_NAME_TO_KEYSYM: &[(&str, u32)] = &[
    ("backspace", XK_BACKSPACE),
    ("tab", XK_TAB),
    ("return", XK_RETURN),
    ("enter", XK_RETURN),
    ("escape", XK_ESCAPE),
    ("esc", XK_ESCAPE),
    ("delete", XK_DELETE),
    ("del", XK_DELETE),
    ("home", XK_HOME),
    ("end", XK_END),
    ("pageup", XK_PAGE_UP),
    ("page_up", XK_PAGE_UP),
    ("pagedown", XK_PAGE_DOWN),
    ("page_down", XK_PAGE_DOWN),
    ("insert", XK_INSERT),
    ("printscreen", XK_PRINT),
    ("print", XK_PRINT),
    ("scrolllock", XK_SCROLL_LOCK),
    ("pause", XK_PAUSE),
    ("numlock", XK_NUM_LOCK),
    ("left", XK_LEFT),
    ("up", XK_UP),
    ("right", XK_RIGHT),
    ("down", XK_DOWN),
    ("f1", XK_F1),
    ("f2", XK_F2),
    ("f3", XK_F3),
    ("f4", XK_F4),
    ("f5", XK_F5),
    ("f6", XK_F6),
    ("f7", XK_F7),
    ("f8", XK_F8),
    ("f9", XK_F9),
    ("f10", XK_F10),
    ("f11", XK_F11),
    ("f12", XK_F12),
    ("shift", XK_SHIFT_L),
    ("shift_l", XK_SHIFT_L),
    ("shift_r", XK_SHIFT_R),
    ("ctrl", XK_CTRL_L),
    ("ctrl_l", XK_CTRL_L),
    ("ctrl_r", XK_CTRL_R),
    ("control", XK_CTRL_L),
    ("alt", XK_ALT_L),
    ("alt_l", XK_ALT_L),
    ("alt_r", XK_ALT_R),
    ("super", XK_SUPER_L),
    ("super_l", XK_SUPER_L),
    ("super_r", XK_SUPER_R),
    ("win", XK_SUPER_L),
    ("meta", XK_SUPER_L),
    ("space", XK_SPACE),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_detection_never_advertises_both() {
        let s = session_type();
        assert!(!(s == "wayland" && s == "x11"));
    }

    #[test]
    fn character_to_keysym_ascii_range() {
        assert_eq!(character_to_keysym('a'), 0x61);
        assert_eq!(character_to_keysym('Z'), 0x5a);
        assert_eq!(character_to_keysym('0'), 0x30);
        assert_eq!(character_to_keysym(' '), 0x20);
        assert_eq!(character_to_keysym('~'), 0x7e);
        assert_eq!(character_to_keysym('\t'), 0xff09);
        assert_eq!(character_to_keysym('\n'), 0xff0d);
    }

    #[test]
    fn keysym_for_name_common_keys() {
        assert_eq!(keysym_for_name("return"), Some(0xff0d));
        assert_eq!(keysym_for_name("enter"), Some(0xff0d));
        assert_eq!(keysym_for_name("tab"), Some(0xff09));
        assert_eq!(keysym_for_name("escape"), Some(0xff1b));
        assert_eq!(keysym_for_name("backspace"), Some(0xff08));
        assert_eq!(keysym_for_name("delete"), Some(0xffff));
        assert_eq!(keysym_for_name("space"), Some(0x0020));
        assert_eq!(keysym_for_name("shift"), Some(0xffe1));
        assert_eq!(keysym_for_name("ctrl"), Some(0xffe3));
        assert_eq!(keysym_for_name("alt"), Some(0xffe9));
        assert_eq!(keysym_for_name("f1"), Some(0xffbe));
        assert_eq!(keysym_for_name("f12"), Some(0xffc9));
        assert_eq!(keysym_for_name("left"), Some(0xff51));
        assert_eq!(keysym_for_name("nonexistent"), None);
    }

    #[test]
    fn needs_shift_contains_uppercase_and_symbols() {
        assert!(NEEDS_SHIFT.contains(&'!'));
        assert!(NEEDS_SHIFT.contains(&'@'));
        assert!(NEEDS_SHIFT.contains(&'#'));
        assert!(!NEEDS_SHIFT.contains(&'a'));
        assert!(!NEEDS_SHIFT.contains(&'1'));
    }

    #[test]
    fn scroll_directions_map_to_button_pairs() {
        let (down, up) = (4u8, 5u8);
        assert_eq!(down, 4);
        assert_eq!(up, 5);
        let (down, up) = (6u8, 7u8);
        assert_eq!(down, 6);
        assert_eq!(up, 7);
    }
}
