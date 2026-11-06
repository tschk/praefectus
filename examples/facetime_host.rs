//! Operator-supervised FaceTime acceptance host, not a general execution bridge.
//! Supply the comma-separated allowlist through PRAEFECTUS_APPROVED_DESTINATIONS.
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use praefectus::{
    AckState, Action, ActionRequest, ApplicationOperation, AuthorityGrant, CancellationToken,
    Ed25519AuthorityVerifier, Engine, Executor, InteractionMode, NativeExecutor, PROTOCOL_VERSION,
    SafetyClass, SignedAuthority, SurfaceRef, TargetRef, Terminal, VerificationPolicy,
    canonical_authority_bytes, normalized_action_hash,
};
use sha2::{Digest, Sha256};

const FACETIME: &str = "/System/Applications/FaceTime.app/Contents/MacOS/FaceTime";
const FACETIME_NOTIFICATION: &str = "/System/Library/ExtensionKit/Extensions/FaceTimeNotificationExtension.appex/Contents/MacOS/FaceTimeNotificationExtension";
const FACETIME_NOTIFICATION_BRIDGE: &str = "/System/Library/PrivateFrameworks/FaceTimeNotificationViewBridge.framework/Versions/A/XPCServices/FaceTimeNotificationViewBridgeService.xpc/Contents/MacOS/FaceTimeNotificationViewBridgeService";

fn destination_input(command: &str, value: String) -> (Action, VerificationPolicy) {
    if command == "set-destination" {
        let sha256 = hex::encode(Sha256::digest(value.as_bytes()));
        (
            Action::SetValue { value },
            VerificationPolicy::TargetValueHash { sha256 },
        )
    } else {
        (
            Action::TypeText {
                text: value,
                clear: true,
                press_return: false,
                delay_ms: None,
            },
            VerificationPolicy::None,
        )
    }
}

fn destination_matches(state: &serde_json::Value, destination: &str) -> bool {
    state.get("value_hash").and_then(serde_json::Value::as_str)
        == Some(hex::encode(Sha256::digest(destination.as_bytes())).as_str())
}

fn approve_destination(configured: Option<&str>, destination: &str) -> Result<(), &'static str> {
    let approved: Vec<_> = configured
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    if approved.is_empty() {
        return Err("no approved destinations are configured");
    }
    if !approved.contains(&destination) {
        return Err("destination is not explicitly approved");
    }
    Ok(())
}

fn now_ms() -> Result<i64, Box<dyn std::error::Error>> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn is_facetime(pid: u32) -> Result<bool, Box<dyn std::error::Error>> {
    let process = std::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()?;
    Ok(process.status.success()
        && matches!(
            String::from_utf8(process.stdout)?.trim(),
            FACETIME | FACETIME_NOTIFICATION | FACETIME_NOTIFICATION_BRIDGE
        ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("--approved-facetime") {
        return Err("requires --approved-facetime; commands: permissions, observe, activate, invoke SURFACE TAG NAME ROLE, set-destination SURFACE TAG NAME ROLE HANDLE, type-destination SURFACE TAG NAME ROLE HANDLE, read-destination SURFACE TAG NAME ROLE HANDLE, commit-destination SURFACE TAG NAME ROLE HANDLE".into());
    }
    let Some(command) = args.get(1).map(String::as_str) else {
        return Err("missing command".into());
    };
    let expected = match command {
        "permissions" | "observe" | "activate" => 2,
        "invoke" => 6,
        "set-destination" | "type-destination" | "read-destination" | "commit-destination" => 7,
        _ => return Err("unsupported command; no effect dispatched".into()),
    };
    if args.len() != expected {
        return Err("incorrect argument count; no effect dispatched".into());
    }
    if expected == 7 {
        let configured = std::env::var("PRAEFECTUS_APPROVED_DESTINATIONS").ok();
        approve_destination(configured.as_deref(), &args[6])?;
    }

    let cancellation = CancellationToken::default();
    let executor = NativeExecutor::default();
    let mut seed = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let key = SigningKey::from_bytes(&seed);
    let authority = Ed25519AuthorityVerifier::new([(
        "facetime-acceptance-host".into(),
        "ephemeral".into(),
        "supervised-facetime-v1".into(),
        key.verifying_key(),
    )])?;
    let ledger = praefectus::default_ledger_path().with_file_name("facetime-host-operations.jsonl");
    let engine = Engine::new(NativeExecutor::default(), ledger, authority);
    let capabilities = engine.capabilities()?;
    println!(
        "{}",
        serde_json::json!({"kind":"permissions", "capabilities":capabilities})
    );
    if command == "permissions" {
        return Ok(());
    }
    if capabilities.permissions.get("accessibility") != Some(&true) {
        return Err("AXIsProcessTrusted is false; no action dispatched".into());
    }

    let (action, target, verification, mode, safety) = if command == "activate" {
        // Activation is an explicitly signed host auxiliary action, not a fenced AX invoke.
        (
            Action::Application {
                operation: ApplicationOperation::Switch,
                name: "FaceTime".into(),
            },
            TargetRef::None,
            VerificationPolicy::None,
            InteractionMode::Interactive,
            SafetyClass::Reversible,
        )
    } else if command == "observe" {
        let deadline = now_ms()? + 20_000;
        let surfaces = executor.list_surfaces(&cancellation, deadline)?;
        let mut count = 0;
        for surface in surfaces {
            if !is_facetime(surface.process_id)? {
                continue;
            }
            let observation =
                executor.observe_surface(&surface.surface, &cancellation, deadline)?;
            if !is_facetime(observation.provenance.process_id)? {
                return Err("observed process is no longer FaceTime".into());
            }
            let elements: Vec<_> = observation
                .elements
                .iter()
                .map(|element| {
                    serde_json::json!({"tag": element.tag, "role": element.role,
                    "actionability": element.actionability})
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({"kind":"observation", "surface":surface.surface,
                    "truncated": observation.truncated, "elements": elements})
            );
            count += 1;
        }
        if count == 0 {
            return Err("no observable FaceTime surface; no action dispatched".into());
        }
        return Ok(());
    } else {
        let observation = executor.observe_surface(
            &SurfaceRef {
                id: args[2].clone(),
            },
            &cancellation,
            now_ms()? + 20_000,
        )?;
        if !is_facetime(observation.provenance.process_id)? || observation.truncated {
            return Err("refusing non-FaceTime or truncated observation".into());
        }
        let matches: Vec<_> = observation
            .elements
            .iter()
            .filter(|element| {
                element.name.as_deref().unwrap_or("") == args[4] && element.role == args[5]
            })
            .collect();
        if matches.len() != 1 || matches[0].tag != args[3] {
            return Err(
                "target changed or is ambiguous; observe again, no action dispatched".into(),
            );
        }
        let element = matches[0];
        let actionable = element.actionability;
        if !actionable.visible || !actionable.enabled {
            return Err("target is not visible and enabled; no action dispatched".into());
        }
        let target = TargetRef::Element {
            target: observation.target(&element.tag)?,
        };
        println!(
            "{}",
            serde_json::json!({"kind":"selected_target", "surface":args[2], "tag": element.tag, "role": element.role})
        );
        if matches!(command, "read-destination" | "commit-destination") {
            let readback =
                executor.observe_with_boundary(&target, &cancellation, now_ms()? + 15_000)?;
            let matches = destination_matches(&readback.state, &args[6]);
            println!(
                "{}",
                serde_json::json!({"kind":"destination_readback", "matches_approved_destination":matches})
            );
            if !matches {
                return Err(
                    "destination readback is missing or does not match; do not dial".into(),
                );
            }
            if command == "read-destination" {
                return Ok(());
            }
        }
        let (action, verification) = match command {
            "invoke" if actionable.invokable => (Action::Invoke, VerificationPolicy::None),
            "set-destination" | "type-destination" if actionable.editable => {
                destination_input(command, args[6].clone())
            }
            "commit-destination" if actionable.editable => (
                Action::Press {
                    key: "return".into(),
                    count: 1,
                    delay_ms: None,
                },
                VerificationPolicy::None,
            ),
            _ => return Err("target does not support the requested action".into()),
        };
        let mode = if matches!(&action, Action::TypeText { .. } | Action::Press { .. }) {
            InteractionMode::Interactive
        } else {
            InteractionMode::BackgroundOnly
        };
        (action, target, verification, mode, SafetyClass::External)
    };
    let now = now_ms()?;
    let operation_id = format!(
        "facetime-{}-{now}-{}",
        std::process::id(),
        hex::encode(&seed[..8])
    );
    let deadline = now + 15_000;
    let mut request = ActionRequest {
        protocol_version: PROTOCOL_VERSION,
        action_version: PROTOCOL_VERSION,
        target_version: PROTOCOL_VERSION,
        verification_version: PROTOCOL_VERSION,
        operation_id: operation_id.clone(),
        subject: "device-acceptance".into(),
        session_id: "supervised-facetime".into(),
        authority: SignedAuthority {
            grant: AuthorityGrant {
                protocol_version: PROTOCOL_VERSION,
                issuer: "facetime-acceptance-host".into(),
                key_id: "ephemeral".into(),
                operation_id,
                subject: "device-acceptance".into(),
                session_id: "supervised-facetime".into(),
                risk: safety,
                expires_at_ms: deadline,
                policy_generation: "supervised-facetime-v1".into(),
                action_hash: String::new(),
            },
            signature: String::new(),
        },
        action,
        target,
        interaction_mode: mode,
        deadline_at_ms: deadline,
        verification,
        safety,
    };
    request.authority.grant.action_hash = normalized_action_hash(&request)?;
    request.authority.signature = hex::encode(
        key.sign(&canonical_authority_bytes(&request.authority.grant)?)
            .to_bytes(),
    );
    let report = engine.execute(&request, &cancellation)?;
    println!("{}", serde_json::json!({"kind":"report", "report":report}));
    if !matches!(
        report.acknowledgements.last().map(|ack| &ack.state),
        Some(AckState::Terminal { terminal }) if matches!(terminal.as_ref(), Terminal::Succeeded { .. })
    ) {
        return Err(
            "action did not succeed; stop and reconcile, do not automatically retry".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_input_passes_request_validation_without_authorizing_dispatch() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Engine::new(
            NativeExecutor::default(),
            directory.path().join("ledger"),
            praefectus::DenyAuthority,
        );
        for command in ["set-destination", "type-destination"] {
            let (action, verification) = destination_input(command, "test-destination".into());
            let mut request: ActionRequest = serde_json::from_value(serde_json::json!({
                "protocol_version": PROTOCOL_VERSION, "action_version": PROTOCOL_VERSION,
                "target_version": PROTOCOL_VERSION, "verification_version": PROTOCOL_VERSION,
                "operation_id": "input-test", "subject": "test", "session_id": "test",
                "authority": {"grant": {"protocol_version": PROTOCOL_VERSION, "issuer": "test",
                    "key_id": "test", "operation_id": "input-test", "subject": "test", "session_id": "test",
                    "risk": "external", "expires_at_ms": i64::MAX, "policy_generation": "test", "action_hash": ""},
                    "signature": "0".repeat(128)},
                "action": action, "verification": verification,
                "target": {"kind": "element", "target": {"observation_id": "0".repeat(64), "generation": 1,
                    "provenance_hash": "1".repeat(64), "element_id": "2".repeat(64), "fingerprint_hash": "3".repeat(64)}},
                "interaction_mode": "interactive", "deadline_at_ms": i64::MAX, "safety": "external"
            })).unwrap();
            assert!(
                matches!(
                    engine.execute(&request, &CancellationToken::default()),
                    Err(praefectus::ProtocolError::AuthorityDenied)
                ),
                "{command}"
            );
            request.verification = match request.action {
                Action::SetValue { .. } => VerificationPolicy::None,
                _ => VerificationPolicy::TargetValueHash {
                    sha256: hex::encode(Sha256::digest(b"test-destination")),
                },
            };
            assert!(matches!(
                engine.execute(&request, &CancellationToken::default()),
                Err(praefectus::ProtocolError::InvalidRequest(_))
            ));
        }
    }

    #[test]
    fn destination_readback_requires_the_exact_value_hash() {
        let state = serde_json::json!({"value_hash": hex::encode(Sha256::digest(b"approved"))});
        assert!(destination_matches(&state, "approved"));
        assert!(!destination_matches(&state, "other"));
        for missing in [
            serde_json::json!({}),
            serde_json::json!({"value_hash": null}),
            serde_json::json!({"value_hash": ""}),
        ] {
            assert!(!destination_matches(&missing, "approved"));
        }
    }

    #[test]
    fn destination_requires_an_explicit_nonempty_allowlist_and_exact_match() {
        for configured in [None, Some(""), Some(" , , ")] {
            assert_eq!(
                approve_destination(configured, "first"),
                Err("no approved destinations are configured")
            );
        }
        assert_eq!(approve_destination(Some("first, second"), "second"), Ok(()));
        for destination in ["", "third", "First", "first-suffix"] {
            assert_eq!(
                approve_destination(Some("first, second"), destination),
                Err("destination is not explicitly approved")
            );
        }
    }
}
