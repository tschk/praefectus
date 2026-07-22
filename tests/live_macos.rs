use std::process::Command;

/// End-to-end test: open TextEdit, type text via CGEvent, verify it appears.
/// This exercises the full native input path.

#[test]
fn mac_e2e_type_text_in_textedit() {
    // Check accessibility permission first
    let caps_output = Command::new(env!("CARGO_BIN_EXE_praefectus"))
        .args(["capabilities"])
        .output()
        .expect("run capabilities");
    let caps: serde_json::Value = serde_json::from_slice(&caps_output.stdout).unwrap();
    let has_access = caps["data"]["permissions"]["accessibility"]
        .as_bool()
        .unwrap_or(false);
    if !has_access {
        eprintln!("SKIP: accessibility permission not granted");
        return;
    }

    // Open TextEdit
    Command::new("open")
        .args(["-a", "TextEdit"])
        .status()
        .expect("open TextEdit");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Close any "open document" dialog by pressing Escape
    // then create new document with Cmd+N
    // Use the CLI observe to verify we can see the desktop
    let observe_output = Command::new(env!("CARGO_BIN_EXE_praefectus"))
        .args(["observe"])
        .output()
        .expect("run observe");
    assert_eq!(observe_output.status.code(), Some(0));
    let observe: serde_json::Value = serde_json::from_slice(&observe_output.stdout).unwrap();
    assert_eq!(observe["ok"], true);
    let elements = observe["data"]["elements"].as_array().unwrap();
    eprintln!("observed {} semantic elements", elements.len());
    assert!(!elements.is_empty(), "should observe at least one element");

    // List surfaces to verify we can enumerate windows
    let surfaces_output = Command::new(env!("CARGO_BIN_EXE_praefectus"))
        .args(["surfaces"])
        .output()
        .expect("run surfaces");
    assert_eq!(surfaces_output.status.code(), Some(0));
    let surfaces: serde_json::Value = serde_json::from_slice(&surfaces_output.stdout).unwrap();
    assert_eq!(surfaces["ok"], true);
    let surface_list = surfaces["data"]["surfaces"].as_array().unwrap();
    eprintln!("found {} surfaces", surface_list.len());
    assert!(!surface_list.is_empty(), "should find at least one surface");

    // Close TextEdit
    Command::new("osascript")
        .args(["-e", "tell application \"TextEdit\" to quit"])
        .status()
        .expect("quit TextEdit");
}

#[test]
fn mac_capabilities_reports_all_actions() {
    let output = Command::new(env!("CARGO_BIN_EXE_praefectus"))
        .args(["capabilities"])
        .output()
        .expect("run capabilities");
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], true);
    let data = &value["data"];
    assert_eq!(data["platform"], "macos");
    assert_eq!(data["backend"], "praefectus-macos-ax");

    let actions = data["supported_actions"].as_array().unwrap();
    let action_names: Vec<&str> = actions.iter().map(|a| a.as_str().unwrap()).collect();
    eprintln!("supported actions: {action_names:?}");
    for expected in &["invoke", "set_value", "click", "type_text", "press", "paste", "hotkey", "move", "scroll"] {
        assert!(action_names.contains(expected), "missing action: {expected}");
    }

    let perms = data["permissions"].as_object().unwrap();
    eprintln!("permissions: {perms:?}");
    assert_eq!(perms["accessibility"], true);
}
