use std::io::Write;
use std::process::{Command, Stdio};

fn run(arguments: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_praefectus"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
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
fn success_uses_the_stable_json_envelope() {
    let output = run(&["capabilities"], "");
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON success envelope");
    assert_eq!(value["ok"], true);
    assert!(value["data"].is_object());
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
