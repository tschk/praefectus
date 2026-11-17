//! Reference phone host bridge. The Swift host owns approval and the signing key.
use std::ffi::{CStr, CString, c_char};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use praefectus::iphone::{IphoneConfig, IphoneExecutor};
use praefectus::{
    Action, ActionRequest, AuthorityGrant, CancellationToken, Ed25519AuthorityVerifier, Engine,
    Executor, InteractionMode, PROTOCOL_VERSION, SafetyClass, SignedAuthority, TargetRef,
    VerificationPolicy, canonical_authority_bytes, normalized_action_hash,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

struct Host {
    executor: IphoneExecutor,
    engine: Engine<IphoneExecutor>,
    screenshot: PathBuf,
    session_id: String,
}
static HOST: Mutex<Option<Host>> = Mutex::new(None);
static CANCELLATION: OnceLock<Mutex<CancellationToken>> = OnceLock::new();

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Connect {
        port: u16,
        pairing_plist: String,
        public_key: String,
        directory: PathBuf,
    },
    Disconnect,
    Observe,
    Discover,
    Prepare {
        action: Action,
        target: TargetRef,
        not_after_ms: i64,
    },
    Execute {
        request: Box<ActionRequest>,
    },
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn prepare(
    action: Action,
    target: TargetRef,
    session_id: &str,
    not_after_ms: i64,
) -> Result<Value, ()> {
    let deadline = (now() + 15_000).min(not_after_ms);
    if deadline <= now() {
        return Err(());
    }
    let operation_id = Uuid::new_v4().to_string();
    let mut request = ActionRequest {
        protocol_version: PROTOCOL_VERSION,
        action_version: PROTOCOL_VERSION,
        target_version: PROTOCOL_VERSION,
        verification_version: PROTOCOL_VERSION,
        operation_id: operation_id.clone(),
        subject: "phone-owner".into(),
        session_id: session_id.into(),
        authority: SignedAuthority {
            grant: AuthorityGrant {
                protocol_version: PROTOCOL_VERSION,
                issuer: "phone-host".into(),
                key_id: "owner".into(),
                operation_id,
                subject: "phone-owner".into(),
                session_id: session_id.into(),
                risk: SafetyClass::External,
                expires_at_ms: deadline,
                policy_generation: "1".into(),
                action_hash: String::new(),
            },
            signature: String::new(),
        },
        action,
        target,
        interaction_mode: InteractionMode::Interactive,
        deadline_at_ms: deadline,
        verification: VerificationPolicy::None,
        safety: SafetyClass::External,
    };
    request.authority.grant.action_hash = normalized_action_hash(&request).map_err(|_| ())?;
    let bytes = canonical_authority_bytes(&request.authority.grant).map_err(|_| ())?;
    Ok(json!({ "request": request, "signing_bytes": hex::encode(bytes) }))
}

fn call(command: Command) -> Result<Value, ()> {
    let mut host = HOST.lock().map_err(|_| ())?;
    match command {
        Command::Connect {
            port,
            pairing_plist,
            public_key,
            directory,
        } => {
            // A reconnect discards all old observations and the previous session.
            *host = None;
            if !directory.is_absolute() || !directory.is_dir() {
                return Err(());
            }
            let key: [u8; 32] = hex::decode(public_key)
                .map_err(|_| ())?
                .try_into()
                .map_err(|_| ())?;
            let key = VerifyingKey::from_bytes(&key).map_err(|_| ())?;
            let verifier = Ed25519AuthorityVerifier::new([(
                "phone-host".into(),
                "owner".into(),
                "1".into(),
                key,
            )])
            .map_err(|_| ())?;
            let executor = IphoneExecutor::connect(
                IphoneConfig::on_phone(port, pairing_plist.as_bytes()).map_err(|_| ())?,
            )
            .map_err(|_| ())?;
            let session = serde_json::to_value(executor.session()).map_err(|_| ())?;
            let engine = Engine::new(
                executor.clone(),
                directory.join("operations.jsonl"),
                verifier,
            );
            *host = Some(Host {
                executor,
                engine,
                screenshot: directory.join("screen.png"),
                session_id: Uuid::new_v4().to_string(),
            });
            Ok(session)
        }
        Command::Disconnect => {
            *host = None;
            Ok(json!({}))
        }
        command => {
            let host = host.as_ref().ok_or(())?;
            let token = CANCELLATION
                .get_or_init(Mutex::default)
                .lock()
                .map_err(|_| ())?
                .clone();
            if token.is_cancelled() && !matches!(command, Command::Execute { .. }) {
                return Err(());
            }
            match command {
                Command::Observe => {
                    let screen = host
                        .executor
                        .observe_screen(&token, now() + 15_000)
                        .map_err(|_| ())?;
                    let mut options = std::fs::OpenOptions::new();
                    options.write(true).create(true).truncate(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    // The directory is app-private and not a model parameter.
                    let mut file = options.open(&host.screenshot).map_err(|_| ())?;
                    file.write_all(screen.png()).map_err(|_| ())?;
                    serde_json::to_value(screen.coordinates()).map_err(|_| ())
                }
                Command::Discover => Ok(json!({ "session": host.executor.session(),
                    "capabilities": host.executor.capabilities().map_err(|_| ())?,
                    "applications": host.executor.applications(&token, now() + 15_000).map_err(|_| ())? })),
                Command::Prepare {
                    action,
                    target,
                    not_after_ms,
                } => prepare(action, target, &host.session_id, not_after_ms),
                Command::Execute { request } => {
                    if request.session_id != host.session_id {
                        return Err(());
                    }
                    serde_json::to_value(host.engine.execute(&request, &token).map_err(|_| ())?)
                        .map_err(|_| ())
                }
                _ => Err(()),
            }
        }
    }
}

/// # Safety
/// `input` must be a valid, NUL-terminated UTF-8 string for this call's duration.
/// Free the returned allocation exactly once with `praefectus_iphone_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn praefectus_iphone_call(input: *const c_char) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        if input.is_null() {
            return Err(());
        }
        let bytes = unsafe { CStr::from_ptr(input) }.to_bytes();
        if bytes.len() > 256 * 1024 {
            return Err(());
        }
        let command = serde_json::from_slice(bytes).map_err(|_| ())?;
        call(command)
    });
    let envelope = match result {
        Ok(Ok(data)) => json!({"ok":true,"data":data}),
        _ => {
            json!({"ok":false,"error":"iPhone operation unavailable; reconnect after transport failure"})
        }
    };
    CString::new(envelope.to_string())
        .expect("JSON contains no NUL bytes")
        .into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn praefectus_iphone_cancel() {
    if let Ok(token) = CANCELLATION.get_or_init(Mutex::default).lock() {
        token.cancel();
    }
}

/// Start a new host operation only after the previous operation has returned.
#[unsafe(no_mangle)]
pub extern "C" fn praefectus_iphone_begin() {
    if let Ok(mut token) = CANCELLATION.get_or_init(Mutex::default).lock() {
        *token = CancellationToken::default();
    }
}

/// # Safety
/// `output` must be a live pointer returned by `praefectus_iphone_call`, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn praefectus_iphone_free(output: *mut c_char) {
    if !output.is_null() {
        drop(unsafe { CString::from_raw(output) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use praefectus::AuthorityVerifier;

    #[test]
    fn phone_host_signs_exact_proposal_without_giving_rust_a_private_key() {
        let prepared = prepare(
            Action::Press {
                key: "home".into(),
                count: 1,
                delay_ms: None,
            },
            TargetRef::Coordinates {
                x: 75,
                y: 450,
                display_id: "iphone-primary".into(),
                display_geometry_hash: "a".repeat(64),
                snapshot_id: "b".repeat(64),
                snapshot_content_hash: "c".repeat(64),
            },
            "test-session",
            now() + 60_000,
        )
        .unwrap();
        let mut request: ActionRequest =
            serde_json::from_value(prepared["request"].clone()).unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        let bytes = hex::decode(prepared["signing_bytes"].as_str().unwrap()).unwrap();
        request.authority.signature = hex::encode(key.sign(&bytes).to_bytes());
        let verifier = Ed25519AuthorityVerifier::new([(
            "phone-host".into(),
            "owner".into(),
            "1".into(),
            key.verifying_key(),
        )])
        .unwrap();
        assert!(
            verifier
                .verify(&request, &normalized_action_hash(&request).unwrap())
                .is_ok()
        );
        request.action = Action::Press {
            key: "return".into(),
            count: 1,
            delay_ms: None,
        };
        assert!(
            verifier
                .verify(&request, &normalized_action_hash(&request).unwrap())
                .is_err()
        );
    }

    #[test]
    fn session_lease_bounds_every_signed_grant_and_refuses_expired_leases() {
        let action = Action::Application {
            operation: praefectus::ApplicationOperation::Launch,
            name: "com.example.app".into(),
        };
        let lease = now() + 5_000;
        let prepared = prepare(action.clone(), TargetRef::None, "current-session", lease).unwrap();
        let request: ActionRequest = serde_json::from_value(prepared["request"].clone()).unwrap();
        assert_eq!(request.deadline_at_ms, lease);
        assert_eq!(request.authority.grant.expires_at_ms, lease);
        assert_eq!(request.session_id, "current-session");
        assert_eq!(request.authority.grant.session_id, "current-session");
        assert!(prepare(action, TargetRef::None, "current-session", now() - 1).is_err());
    }

    #[test]
    fn command_schema_refuses_model_supplied_authority_configuration() {
        assert!(
            serde_json::from_value::<Command>(
                json!({"command":"prepare", "action":{"kind":"invoke"},
            "target":{"kind":"none"}, "public_key":"attacker"})
            )
            .is_err()
        );
        let output = unsafe { praefectus_iphone_call(std::ptr::null()) };
        let value: Value =
            serde_json::from_slice(unsafe { CStr::from_ptr(output) }.to_bytes()).unwrap();
        assert_eq!(value["ok"], false);
        unsafe {
            praefectus_iphone_free(output);
        }
    }
}
