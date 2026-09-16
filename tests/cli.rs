use std::io::Write;
use std::process::{Command, Stdio};

fn run(arguments: &[&str], stdin: &str) -> std::process::Output {
    run_with_env(arguments, stdin, &[])
}

fn run_with_env(
    arguments: &[&str],
    stdin: &str,
    env: &[(&str, Option<&std::path::Path>)],
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_praefectus"));
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        match value {
            Some(path) => {
                command.env(key, path);
            }
            None => {
                command.env_remove(key);
            }
        }
    }
    let mut child = command.spawn().expect("spawn CLI");
    if let Some(mut child_stdin) = child.stdin.take() {
        let _ = child_stdin.write_all(stdin.as_bytes());
    }
    child.wait_with_output().expect("CLI output")
}

fn error(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("JSON error envelope")
}

#[test]
fn usage_errors_are_json_with_exit_two() {
    for arguments in [&[][..], &["unknown"][..], &["status"][..]] {
        let output = run(arguments, "");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(error(&output)["ok"], false);
        assert_eq!(error(&output)["error"]["code"], "usage");
    }
}

#[test]
fn capabilities_and_status_reject_extra_or_unknown_arguments() {
    for (arguments, message) in [
        (
            &["capabilities", "extra"][..],
            "capabilities does not accept positional arguments",
        ),
        (
            &["capabilities", "--unknown"][..],
            "unknown option: --unknown",
        ),
        (
            &["status", "operation", "extra"][..],
            "status accepts exactly one operation ID",
        ),
        (
            &["status", "operation", "--unknown"][..],
            "unknown option: --unknown",
        ),
        (
            &["status", "operation", "--ledger"][..],
            "--ledger requires a path",
        ),
        (
            &["status", "operation", "--ledger", "one", "--ledger", "two"][..],
            "--ledger may only be specified once",
        ),
        (
            &["surfaces", "extra"][..],
            "surfaces does not accept positional arguments",
        ),
        (
            &["observe-surface"][..],
            "observe-surface requires a surface ID",
        ),
        (
            &["observe-surface", "one", "two"][..],
            "observe-surface accepts exactly one surface ID",
        ),
        (
            &["allow-global-input", "extra"][..],
            "allow-global-input accepts no arguments, allow, deny, or --no-yolo",
        ),
    ] {
        let output = run(arguments, "");
        assert_eq!(output.status.code(), Some(2));
        let value = error(&output);
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "usage");
        assert_eq!(value["error"]["message"], message);
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn success_uses_the_stable_json_envelope() {
    let output = run(&["capabilities"], "");
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON success envelope");
    assert_eq!(value["ok"], true);
    assert!(value["data"].is_object());
    assert_eq!(value["data"]["session_isolation"], "shared_desktop");
    assert_eq!(value["data"]["permissions"]["global_input"], true);
}

#[test]
fn no_yolo_persists_global_input_restriction() {
    let directory = tempfile::tempdir().expect("temp directory");
    let env = [
        ("XDG_STATE_HOME", Some(directory.path())),
        ("HOME", Some(directory.path())),
        ("LOCALAPPDATA", Some(directory.path())),
        ("PRAEFECTUS_ALLOW_GLOBAL_INPUT", None),
        ("PRAEFECTUS_NO_YOLO", None),
    ];

    let unrestricted = run_with_env(&["allow-global-input"], "", &env);
    assert_eq!(unrestricted.status.code(), Some(0));
    let unrestricted_value: serde_json::Value =
        serde_json::from_slice(&unrestricted.stdout).expect("JSON success envelope");
    assert_eq!(unrestricted_value["ok"], true);
    assert_eq!(unrestricted_value["data"]["allowed"], true);
    assert_eq!(unrestricted_value["data"]["no_yolo"], false);

    let restricted = run_with_env(&["allow-global-input", "--no-yolo"], "", &env);
    assert_eq!(restricted.status.code(), Some(0));
    let restricted_value: serde_json::Value =
        serde_json::from_slice(&restricted.stdout).expect("JSON success envelope");
    assert_eq!(restricted_value["ok"], true);
    assert_eq!(restricted_value["data"]["allowed"], false);
    assert_eq!(restricted_value["data"]["no_yolo"], true);
    assert_eq!(restricted_value["data"]["persisted"], true);

    let restored = run_with_env(&["allow-global-input", "allow"], "", &env);
    assert_eq!(restored.status.code(), Some(0));
    let restored_value: serde_json::Value =
        serde_json::from_slice(&restored.stdout).expect("JSON success envelope");
    assert_eq!(restored_value["ok"], true);
    assert_eq!(restored_value["data"]["allowed"], true);
    assert_eq!(restored_value["data"]["persisted"], false);
}

#[test]
fn execute_requires_a_trusted_library_host() {
    let output = run(&["execute"], "{}");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(error(&output)["error"]["code"], "usage");
    assert!(
        error(&output)["error"]["message"]
            .as_str()
            .expect("message")
            .contains("host-injected trusted AuthorityVerifier")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn observe_uses_a_stable_json_envelope() {
    let output = run(&["observe"], "");
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let value = error(&output);
    assert!(value["ok"].is_boolean());
    if output.status.code() == Some(3) {
        assert_eq!(value["error"]["code"], "observation_error");
    }
}

#[test]
fn surface_commands_use_stable_json_envelopes() {
    let output = run(&["surfaces"], "");
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let value = error(&output);
    assert!(value["ok"].is_boolean());
    if output.status.code() == Some(0) {
        assert!(value["data"].is_array());
    } else {
        assert_eq!(value["error"]["code"], "observation_error");
    }

    let output = run(&["observe-surface", "0"], "");
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let value = error(&output);
    assert!(value["ok"].is_boolean());
    if output.status.code() == Some(3) {
        assert_eq!(value["error"]["code"], "observation_error");
    }
}
