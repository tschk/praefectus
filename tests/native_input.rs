#[cfg(target_os = "macos")]
use praefectus::{
    CancellationToken, Direction, Executor, MouseButton, NativeExecutor, NativePoint,
    VerificationPolicy,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[test]
fn capabilities_expose_all_actions() {
    let executor = NativeExecutor::default();
    let caps = executor.capabilities().expect("capabilities");
    let expected = [
        "invoke",
        "set_value",
        "click",
        "type_text",
        "press",
        "paste",
        "hotkey",
        "move",
        "scroll",
    ];
    for action in &expected {
        assert!(
            caps.supported_actions.iter().any(|a| a == action),
            "missing action: {action}"
        );
    }
    assert!(
        caps.permissions
            .get("accessibility")
            .copied()
            .unwrap_or(false)
    );
}

#[test]
fn native_click_at_current_cursor_position() {
    // Move to a safe position first, then click
    let executor = NativeExecutor::default();
    let target = praefectus::ResolvedTarget::Point(NativePoint { x: 100, y: 100 });
    let receipt = executor
        .dispatch(
            &praefectus::Action::Move,
            &target,
            &VerificationPolicy::None,
            &CancellationToken::default(),
            now_ms() + 5000,
        )
        .expect("move should succeed");
    assert_eq!(receipt.backend, "praefectus-macos-ax");

    // Left click
    let receipt = executor
        .dispatch(
            &praefectus::Action::Click {
                button: MouseButton::Left,
                count: 1,
                allow_coordinate_fallback: false,
            },
            &target,
            &VerificationPolicy::None,
            &CancellationToken::default(),
            now_ms() + 5000,
        )
        .expect("click should succeed");
    assert_eq!(receipt.backend, "praefectus-macos-ax");
}

#[test]
fn native_type_text_types_characters() {
    let executor = NativeExecutor::default();
    let receipt = executor
        .dispatch(
            &praefectus::Action::TypeText {
                text: "test".to_string(),
                clear: false,
                press_return: false,
                delay_ms: None,
            },
            &praefectus::ResolvedTarget::Point(NativePoint { x: 100, y: 100 }),
            &VerificationPolicy::None,
            &CancellationToken::default(),
            now_ms() + 5000,
        )
        .expect("type_text should succeed");
    assert_eq!(receipt.backend, "praefectus-macos-ax");
}

#[test]
fn native_press_sends_key_events() {
    let executor = NativeExecutor::default();
    // Press escape — safe, no side effects
    let receipt = executor
        .dispatch(
            &praefectus::Action::Press {
                key: "escape".to_string(),
                count: 1,
                delay_ms: None,
            },
            &praefectus::ResolvedTarget::Point(NativePoint { x: 100, y: 100 }),
            &VerificationPolicy::None,
            &CancellationToken::default(),
            now_ms() + 5000,
        )
        .expect("press should succeed");
    assert_eq!(receipt.backend, "praefectus-macos-ax");
}

#[test]
fn native_hotkey_sends_modifier_combo() {
    let executor = NativeExecutor::default();
    // Cmd+Space — Spotlight toggle, will open/close it
    let receipt = executor
        .dispatch(
            &praefectus::Action::Hotkey {
                keys: vec!["cmd".to_string(), "space".to_string()],
            },
            &praefectus::ResolvedTarget::Point(NativePoint { x: 100, y: 100 }),
            &VerificationPolicy::None,
            &CancellationToken::default(),
            now_ms() + 5000,
        )
        .expect("hotkey should succeed");
    assert_eq!(receipt.backend, "praefectus-macos-ax");
}

#[test]
fn native_scroll_scrolls_vertically() {
    let executor = NativeExecutor::default();
    let receipt = executor
        .dispatch(
            &praefectus::Action::Scroll {
                direction: Direction::Down,
                amount: 3,
            },
            &praefectus::ResolvedTarget::Point(NativePoint { x: 500, y: 500 }),
            &VerificationPolicy::None,
            &CancellationToken::default(),
            now_ms() + 5000,
        )
        .expect("scroll should succeed");
    assert_eq!(receipt.backend, "praefectus-macos-ax");
}

#[test]
fn native_paste_writes_clipboard_and_pastes() {
    let executor = NativeExecutor::default();
    let receipt = executor
        .dispatch(
            &praefectus::Action::Paste {
                text: "praefectus-paste-test".to_string(),
            },
            &praefectus::ResolvedTarget::Point(NativePoint { x: 100, y: 100 }),
            &VerificationPolicy::None,
            &CancellationToken::default(),
            now_ms() + 5000,
        )
        .expect("paste should succeed");
    assert_eq!(receipt.backend, "praefectus-macos-ax");
}
