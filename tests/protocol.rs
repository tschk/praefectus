#![cfg(not(windows))]

use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use praefectus::{
    AckState, Action, ActionRequest, AuthorityGrant, CancellationToken, Capabilities, Direction,
    DispatchError, DispatchReceipt, Ed25519AuthorityVerifier, Effect, EffectKnowledge, Engine,
    Evidence, Executor, FailureCode, MouseButton, NativeBounds, NativeElement, NativeExecutor,
    NativePoint, Observation, PROTOCOL_VERSION, ProtocolError, Rect, ResolvedTarget, SafetyClass,
    SignedAuthority, TargetRef, Terminal, VerificationPolicy, element_fingerprint_hash,
    normalized_action_hash,
};

#[derive(Clone, Copy)]
enum Behavior {
    Success,
    Ambiguous,
    NoEffect,
    CancelAfterSuccess,
    CancelBeforeEffect,
}

#[derive(Clone)]
struct MockExecutor {
    dispatches: Arc<AtomicUsize>,
    observations: Arc<AtomicUsize>,
    stale: Arc<AtomicBool>,
    behavior: Arc<Mutex<Behavior>>,
    frozen_observation: Arc<AtomicBool>,
    changed_fingerprint: Arc<AtomicBool>,
    wrong_fingerprint: Arc<AtomicBool>,
}

impl MockExecutor {
    fn new() -> Self {
        Self {
            dispatches: Arc::new(AtomicUsize::new(0)),
            observations: Arc::new(AtomicUsize::new(0)),
            stale: Arc::new(AtomicBool::new(false)),
            behavior: Arc::new(Mutex::new(Behavior::Success)),
            frozen_observation: Arc::new(AtomicBool::new(false)),
            changed_fingerprint: Arc::new(AtomicBool::new(false)),
            wrong_fingerprint: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Executor for MockExecutor {
    fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
        Ok(Capabilities {
            platform: "test".to_string(),
            backend: "mock".to_string(),
            supported_actions: vec!["scroll".to_string()],
            permissions: BTreeMap::new(),
            display_geometry_hash: "display".to_string(),
        })
    }

    fn observe(&self, target: &TargetRef) -> Result<Observation, ProtocolError> {
        let count = self.observations.fetch_add(1, Ordering::SeqCst);
        let count = if self.frozen_observation.load(Ordering::SeqCst) {
            0
        } else {
            count
        };
        let target_fingerprint_hash = if self.wrong_fingerprint.load(Ordering::SeqCst) {
            "wrong-fingerprint".to_string()
        } else {
            match target {
                TargetRef::Element {
                    element_fingerprint,
                    ..
                } => element_fingerprint_hash(element_fingerprint)?,
                _ => String::new(),
            }
        };
        Ok(Observation {
            evidence: Evidence {
                observation_hash: format!("observation-{count}"),
                target_fingerprint_hash: Some(
                    if self.changed_fingerprint.load(Ordering::SeqCst) && count > 0 {
                        "changed-fingerprint".to_string()
                    } else {
                        target_fingerprint_hash
                    },
                ),
                display_geometry_hash: "display".to_string(),
                observed_at_ms: 1,
            },
            element: None,
            state: serde_json::json!({ "count": count }),
        })
    }

    fn resolve(&self, _target: &TargetRef) -> Result<ResolvedTarget, ProtocolError> {
        if self.stale.load(Ordering::SeqCst) {
            Err(ProtocolError::StaleTarget("changed".to_string()))
        } else {
            Ok(ResolvedTarget::None)
        }
    }

    fn dispatch(
        &self,
        _action: &Action,
        _target: &ResolvedTarget,
        _verification: &VerificationPolicy,
        cancellation: &CancellationToken,
        _deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        match *self.behavior.lock().expect("behavior lock") {
            Behavior::Success => Ok(DispatchReceipt {
                backend: "mock".to_string(),
                fallback_chain: Vec::new(),
            }),
            Behavior::Ambiguous => Err(DispatchError {
                message: "connection lost after dispatch".to_string(),
                effect: EffectKnowledge::Unknown,
                code: FailureCode::DispatchFailed,
            }),
            Behavior::NoEffect => Err(DispatchError {
                message: "rejected before dispatch".to_string(),
                effect: EffectKnowledge::NoEffect,
                code: FailureCode::DispatchFailed,
            }),
            Behavior::CancelAfterSuccess => {
                cancellation.cancel();
                Ok(DispatchReceipt {
                    backend: "mock".to_string(),
                    fallback_chain: Vec::new(),
                })
            }
            Behavior::CancelBeforeEffect => {
                cancellation.cancel();
                Err(DispatchError {
                    message: "cancelled before dispatch".to_string(),
                    effect: EffectKnowledge::CancelledBeforeEffect,
                    code: FailureCode::DispatchFailed,
                })
            }
        }
    }
}

fn request(operation_id: &str) -> ActionRequest {
    let mut request = ActionRequest {
        protocol_version: PROTOCOL_VERSION,
        action_version: PROTOCOL_VERSION,
        target_version: PROTOCOL_VERSION,
        verification_version: PROTOCOL_VERSION,
        operation_id: operation_id.to_string(),
        subject: "subject-1".to_string(),
        session_id: "session-1".to_string(),
        authority: SignedAuthority {
            grant: AuthorityGrant {
                protocol_version: PROTOCOL_VERSION,
                issuer: "host-1".to_string(),
                key_id: "key-1".to_string(),
                operation_id: operation_id.to_string(),
                subject: "subject-1".to_string(),
                session_id: "session-1".to_string(),
                risk: SafetyClass::Reversible,
                expires_at_ms: i64::MAX,
                policy_generation: "generation-1".to_string(),
                action_hash: String::new(),
            },
            signature: String::new(),
        },
        action: Action::Scroll {
            direction: Direction::Down,
            amount: 1,
        },
        target: TargetRef::Element {
            selector: "provider-selector".to_string(),
            snapshot_id: "provider-snapshot-1".to_string(),
            element_fingerprint: praefectus::ElementFingerprint {
                backend: "provider".to_string(),
                id: "element-1".to_string(),
                app: "provider-app".to_string(),
                process_id: 42,
                window: "window-1".to_string(),
                role: "button".to_string(),
                label: "Submit".to_string(),
                bounds: Some(Rect {
                    x: 0,
                    y: 0,
                    width: 10,
                    height: 10,
                }),
            },
        },
        deadline_at_ms: i64::MAX,
        verification: VerificationPolicy::TargetState {
            expected: serde_json::json!({ "count": 1 }),
        },
        safety: SafetyClass::Reversible,
    };
    sign_request(&mut request);
    request
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn sign_request(request: &mut ActionRequest) {
    request.authority.grant.operation_id = request.operation_id.clone();
    request.authority.grant.subject = request.subject.clone();
    request.authority.grant.session_id = request.session_id.clone();
    request.authority.grant.risk = request.safety;
    request.authority.grant.action_hash = normalized_action_hash(request).expect("action hash");
    request.authority.signature = hex::encode(
        signing_key()
            .sign(
                &praefectus::canonical_authority_bytes(&request.authority.grant)
                    .expect("grant JSON"),
            )
            .to_bytes(),
    );
}

fn authority() -> Ed25519AuthorityVerifier {
    Ed25519AuthorityVerifier::new([(
        "host-1".to_string(),
        "key-1".to_string(),
        "generation-1".to_string(),
        signing_key().verifying_key(),
    )])
}

fn terminal(report: &praefectus::ExecuteReport) -> &Terminal {
    match &report.acknowledgements.last().expect("terminal ack").state {
        AckState::Terminal { terminal } => terminal,
        _ => panic!("expected terminal"),
    }
}

#[test]
fn terminal_replay_does_not_dispatch_twice() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    let engine = Engine::new(
        executor.clone(),
        directory.path().join("ledger.jsonl"),
        authority(),
    );
    let first = engine
        .execute(&request("replay"), &CancellationToken::default())
        .expect("first execution");
    let second = engine
        .execute(&request("replay"), &CancellationToken::default())
        .expect("replay");

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
    assert!(matches!(terminal(&first), Terminal::Succeeded { .. }));
    assert_eq!(second.acknowledgements.len(), 1);
    assert!(second.acknowledgements[0].replayed);
}

#[test]
fn concurrent_engines_dispatch_an_operation_once() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = directory.path().join("ledger.jsonl");
    let executor = MockExecutor::new();
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|_| {
            let barrier = barrier.clone();
            let executor = executor.clone();
            let ledger = ledger.clone();
            std::thread::spawn(move || {
                let engine = Engine::new(executor, ledger, authority());
                barrier.wait();
                engine
                    .execute(&request("concurrent"), &CancellationToken::default())
                    .expect("execution")
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for handle in handles {
        handle.join().expect("thread");
    }

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
}

#[test]
fn same_id_with_changed_action_conflicts() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    let engine = Engine::new(executor, directory.path().join("ledger.jsonl"), authority());
    engine
        .execute(&request("conflict"), &CancellationToken::default())
        .expect("first execution");
    let mut changed = request("conflict");
    changed.action = Action::Scroll {
        direction: Direction::Up,
        amount: 2,
    };
    sign_request(&mut changed);

    assert!(matches!(
        engine.execute(&changed, &CancellationToken::default()),
        Err(ProtocolError::Conflict)
    ));
}

#[test]
fn stale_target_fails_before_dispatch() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    executor.stale.store(true, Ordering::SeqCst);
    let engine = Engine::new(
        executor.clone(),
        directory.path().join("ledger.jsonl"),
        authority(),
    );
    let report = engine
        .execute(&request("stale"), &CancellationToken::default())
        .expect("typed failure");

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0);
    assert!(matches!(
        terminal(&report),
        Terminal::Rejected {
            code: FailureCode::StaleTarget,
            ..
        }
    ));
}

#[test]
fn cancellation_and_timeout_stop_before_effect() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    let engine = Engine::new(
        executor.clone(),
        directory.path().join("ledger.jsonl"),
        authority(),
    );
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let cancelled = engine
        .execute(&request("cancelled"), &cancellation)
        .expect("cancelled result");
    let mut expired_request = request("expired");
    expired_request.deadline_at_ms = 1;
    sign_request(&mut expired_request);
    let expired = engine
        .execute(&expired_request, &CancellationToken::default())
        .expect("expired result");

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0);
    assert!(matches!(
        terminal(&cancelled),
        Terminal::CancelledBeforeEffect
    ));
    assert!(matches!(terminal(&expired), Terminal::ExpiredBeforeEffect));
}

#[test]
fn ambiguous_dispatch_is_outcome_unknown_and_replayable() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    *executor.behavior.lock().expect("behavior lock") = Behavior::Ambiguous;
    let engine = Engine::new(
        executor.clone(),
        directory.path().join("ledger.jsonl"),
        authority(),
    );
    let first = engine
        .execute(&request("ambiguous"), &CancellationToken::default())
        .expect("ambiguous result");
    let replay = engine
        .execute(&request("ambiguous"), &CancellationToken::default())
        .expect("ambiguous replay");

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
    assert!(matches!(terminal(&first), Terminal::OutcomeUnknown { .. }));
    assert!(replay.acknowledgements[0].replayed);
}

#[test]
fn changed_post_action_observation_is_not_effect_verification() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    let engine = Engine::new(executor, directory.path().join("ledger.jsonl"), authority());
    let mut request = request("snapshot-changed");
    request.verification = VerificationPolicy::SnapshotChanged;
    sign_request(&mut request);
    let report = engine
        .execute(&request, &CancellationToken::default())
        .expect("typed execution");

    match terminal(&report) {
        Terminal::OutcomeUnknown { receipt, .. } => {
            assert!(matches!(receipt.effect, Effect::ExecutedUnverified));
            assert!(
                receipt
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("does not verify"))
            );
        }
        _ => panic!("expected unknown outcome"),
    }
}

#[test]
fn matching_state_on_a_replaced_target_is_not_verified() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    executor.changed_fingerprint.store(true, Ordering::SeqCst);
    let engine = Engine::new(executor, directory.path().join("ledger.jsonl"), authority());
    let report = engine
        .execute(&request("replaced-target"), &CancellationToken::default())
        .expect("typed execution");

    assert!(matches!(terminal(&report), Terminal::OutcomeUnknown { .. }));
}

#[test]
fn matching_state_on_an_unrequested_target_is_not_verified() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    executor.wrong_fingerprint.store(true, Ordering::SeqCst);
    let engine = Engine::new(executor, directory.path().join("ledger.jsonl"), authority());
    let report = engine
        .execute(
            &request("unrequested-target"),
            &CancellationToken::default(),
        )
        .expect("typed execution");

    assert!(matches!(terminal(&report), Terminal::OutcomeUnknown { .. }));
}

#[test]
fn known_no_effect_dispatch_failure_is_not_ambiguous() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    *executor.behavior.lock().expect("behavior lock") = Behavior::NoEffect;
    let engine = Engine::new(executor, directory.path().join("ledger.jsonl"), authority());
    let report = engine
        .execute(&request("no-effect"), &CancellationToken::default())
        .expect("typed failure");

    assert!(matches!(terminal(&report), Terminal::Rejected { .. }));
}

#[test]
fn cancellation_after_dispatch_is_outcome_unknown() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    *executor.behavior.lock().expect("behavior lock") = Behavior::CancelAfterSuccess;
    let engine = Engine::new(executor, directory.path().join("ledger.jsonl"), authority());
    let cancellation = CancellationToken::default();
    let report = engine
        .execute(&request("cancel-after-dispatch"), &cancellation)
        .expect("typed result");

    assert!(matches!(terminal(&report), Terminal::OutcomeUnknown { .. }));
}

#[test]
fn executor_certified_pre_effect_cancellation_stays_cancelled() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    *executor.behavior.lock().expect("behavior lock") = Behavior::CancelBeforeEffect;
    let engine = Engine::new(executor, directory.path().join("ledger.jsonl"), authority());
    let report = engine
        .execute(
            &request("cancel-before-dispatch"),
            &CancellationToken::default(),
        )
        .expect("typed result");

    assert!(matches!(terminal(&report), Terminal::CancelledBeforeEffect));
}

#[test]
fn invalid_actions_and_unfenced_effects_are_rejected_before_claim() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = directory.path().join("ledger.jsonl");
    let executor = MockExecutor::new();
    let engine = Engine::new(executor.clone(), &ledger, authority());
    let invalid_actions = vec![
        Action::Click {
            button: MouseButton::Left,
            count: 0,
            allow_coordinate_fallback: false,
        },
        Action::Click {
            button: MouseButton::Left,
            count: 4,
            allow_coordinate_fallback: false,
        },
        Action::TypeText {
            text: String::new(),
            clear: false,
            press_return: false,
            delay_ms: None,
        },
        Action::TypeText {
            text: "x".repeat(16 * 1024 + 1),
            clear: false,
            press_return: false,
            delay_ms: None,
        },
        Action::TypeText {
            text: "x".to_string(),
            clear: false,
            press_return: false,
            delay_ms: Some(1_001),
        },
        Action::Press {
            key: String::new(),
            count: 1,
            delay_ms: None,
        },
        Action::Press {
            key: "x".repeat(65),
            count: 1,
            delay_ms: None,
        },
        Action::Press {
            key: "x".to_string(),
            count: 0,
            delay_ms: None,
        },
        Action::Press {
            key: "x".to_string(),
            count: 101,
            delay_ms: None,
        },
        Action::Press {
            key: "x".to_string(),
            count: 1,
            delay_ms: Some(1_001),
        },
        Action::Paste {
            text: String::new(),
        },
        Action::Paste {
            text: "x".repeat(16 * 1024 + 1),
        },
        Action::Hotkey { keys: Vec::new() },
        Action::Hotkey {
            keys: vec!["x".to_string(); 9],
        },
        Action::Hotkey {
            keys: vec![String::new()],
        },
        Action::Hotkey {
            keys: vec!["x".repeat(65)],
        },
        Action::Scroll {
            direction: Direction::Down,
            amount: 0,
        },
        Action::Scroll {
            direction: Direction::Down,
            amount: 101,
        },
        Action::SetValue {
            value: "x".repeat(16 * 1024 + 1),
        },
    ];
    for (index, action) in invalid_actions.into_iter().enumerate() {
        let mut invalid = request(&format!("invalid-action-{index}"));
        invalid.action = action;
        sign_request(&mut invalid);
        assert!(matches!(
            engine.execute(&invalid, &CancellationToken::default()),
            Err(ProtocolError::InvalidRequest(_))
        ));
    }
    let unfenced_actions = vec![
        Action::Click {
            button: MouseButton::Left,
            count: 1,
            allow_coordinate_fallback: false,
        },
        Action::TypeText {
            text: "x".to_string(),
            clear: false,
            press_return: false,
            delay_ms: None,
        },
        Action::Press {
            key: "enter".to_string(),
            count: 1,
            delay_ms: None,
        },
        Action::Paste {
            text: "x".to_string(),
        },
        Action::Hotkey {
            keys: vec!["ctrl".to_string(), "a".to_string()],
        },
        Action::Scroll {
            direction: Direction::Down,
            amount: 1,
        },
        Action::Move,
        Action::SetValue {
            value: "x".to_string(),
        },
    ];
    for (index, action) in unfenced_actions.into_iter().enumerate() {
        let mut invalid = request(&format!("unfenced-action-{index}"));
        invalid.action = action;
        invalid.target = TargetRef::None;
        sign_request(&mut invalid);
        assert!(matches!(
            engine.execute(&invalid, &CancellationToken::default()),
            Err(ProtocolError::InvalidRequest(_))
        ));
    }
    let mut coordinate = request("unfenced-coordinate");
    coordinate.target = TargetRef::Coordinates {
        x: 1,
        y: 1,
        display_id: "display-1".to_string(),
        display_geometry_hash: "0".repeat(64),
        snapshot_id: "snapshot-1".to_string(),
        snapshot_content_hash: "0".repeat(64),
    };
    sign_request(&mut coordinate);
    assert!(matches!(
        engine.execute(&coordinate, &CancellationToken::default()),
        Err(ProtocolError::InvalidRequest(_))
    ));
    let mut oversized_fingerprint = request("oversized-fingerprint");
    if let TargetRef::Element {
        element_fingerprint,
        ..
    } = &mut oversized_fingerprint.target
    {
        element_fingerprint.label = "x".repeat(1025);
    }
    sign_request(&mut oversized_fingerprint);
    assert!(matches!(
        engine.execute(&oversized_fingerprint, &CancellationToken::default()),
        Err(ProtocolError::InvalidRequest(_))
    ));
    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0);
    assert!(!ledger.exists());
}

#[test]
fn native_executor_rejects_coordinate_effects() {
    let executor = NativeExecutor::default();
    let capabilities = executor.capabilities().expect("capabilities");
    assert!(
        !capabilities
            .supported_actions
            .iter()
            .any(|action| action == "move")
    );
    assert_eq!(
        capabilities.permissions.get("coordinate_capture"),
        Some(&false)
    );
    let error = executor
        .dispatch(
            &Action::Move,
            &ResolvedTarget::Point(NativePoint { x: 1, y: 1 }),
            &VerificationPolicy::None,
            &CancellationToken::default(),
            i64::MAX,
        )
        .expect_err("coordinate effect");
    assert_eq!(error.effect, EffectKnowledge::NoEffect);
    assert!(matches!(error.code, FailureCode::Unsupported));
}

#[test]
fn native_executor_rejects_disabled_element_before_effect() {
    let executor = NativeExecutor::default();
    let target = ResolvedTarget::Element(Box::new(NativeElement {
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
        enabled: Some(false),
    }));
    let error = executor
        .dispatch(
            &Action::Click {
                button: MouseButton::Left,
                count: 1,
                allow_coordinate_fallback: false,
            },
            &target,
            &VerificationPolicy::None,
            &CancellationToken::default(),
            i64::MAX,
        )
        .expect_err("disabled target");

    assert_eq!(error.effect, EffectKnowledge::NoEffect);
}

#[test]
fn nested_protocol_versions_are_strict() {
    let directory = tempfile::tempdir().expect("temp directory");
    let engine = Engine::new(
        MockExecutor::new(),
        directory.path().join("ledger.jsonl"),
        authority(),
    );
    let mut invalid = request("invalid-version");
    invalid.action_version += 1;

    assert!(matches!(
        engine.execute(&invalid, &CancellationToken::default()),
        Err(ProtocolError::InvalidRequest(_))
    ));
    let mut invalid = request("invalid-verification-version");
    invalid.verification_version += 1;

    assert!(matches!(
        engine.execute(&invalid, &CancellationToken::default()),
        Err(ProtocolError::InvalidRequest(_))
    ));
}

#[test]
fn provider_snapshot_ids_are_not_native_runtime_ids() {
    let directory = tempfile::tempdir().expect("temp directory");
    let engine = Engine::new(
        MockExecutor::new(),
        directory.path().join("ledger.jsonl"),
        authority(),
    );
    let mut custom = request("provider-snapshot");
    custom.target = TargetRef::Element {
        selector: "provider-selector".to_string(),
        snapshot_id: "provider/session snapshot".to_string(),
        element_fingerprint: praefectus::ElementFingerprint {
            backend: "provider".to_string(),
            id: "element-1".to_string(),
            app: "provider-app".to_string(),
            process_id: 42,
            window: "window-1".to_string(),
            role: "button".to_string(),
            label: "Submit".to_string(),
            bounds: Some(Rect {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            }),
        },
    };
    sign_request(&mut custom);

    assert!(
        engine
            .execute(&custom, &CancellationToken::default())
            .is_ok()
    );
}

#[cfg(unix)]
#[test]
fn newly_created_ledger_directory_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temp directory");
    let state = directory.path().join("private/state");
    let engine = Engine::new(MockExecutor::new(), state.join("ledger.jsonl"), authority());
    engine
        .execute(&request("private-directory"), &CancellationToken::default())
        .expect("execution");

    assert_eq!(
        fs::metadata(state)
            .expect("state metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn incomplete_durable_claim_recovers_as_unknown_without_dispatch() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = directory.path().join("ledger.jsonl");
    let executor = MockExecutor::new();
    let engine = Engine::new(executor.clone(), &ledger, authority());
    engine
        .execute(&request("recovery"), &CancellationToken::default())
        .expect("initial execution");
    let contents = fs::read_to_string(&ledger).expect("ledger");
    let claim = contents.lines().next().expect("claim");
    fs::write(&ledger, format!("{claim}\n")).expect("incomplete ledger");

    let recovered = engine
        .status("recovery")
        .expect("status recovery")
        .expect("recovered status");
    let replayed = engine
        .execute(&request("recovery"), &CancellationToken::default())
        .expect("replay");

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
    assert!(matches!(
        recovered.state,
        AckState::Terminal { terminal }
            if matches!(*terminal, Terminal::OutcomeUnknown { .. })
    ));
    assert!(replayed.acknowledgements[0].replayed);
}

#[test]
fn trajectory_redacts_identifiers_and_action_payloads() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = directory.path().join("ledger.jsonl");
    let engine = Engine::new(MockExecutor::new(), &ledger, authority());
    let mut sensitive = request("private-operation");
    sensitive.action = Action::TypeText {
        text: "private-text".to_string(),
        clear: false,
        press_return: false,
        delay_ms: None,
    };
    sign_request(&mut sensitive);
    engine
        .execute(&sensitive, &CancellationToken::default())
        .expect("execution");

    let trajectory =
        fs::read_to_string(ledger.with_extension("trajectory.jsonl")).expect("trajectory");
    assert!(!trajectory.contains("private-operation"));
    assert!(!trajectory.contains("private-text"));
    assert!(!trajectory.contains("authority-1"));
}

#[test]
fn untrusted_authority_is_denied_before_claim() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = directory.path().join("ledger.jsonl");
    let engine = Engine::new(
        MockExecutor::new(),
        &ledger,
        Ed25519AuthorityVerifier::new([]),
    );

    assert!(matches!(
        engine.execute(&request("denied"), &CancellationToken::default()),
        Err(ProtocolError::AuthorityDenied)
    ));
    assert!(!ledger.exists());
}

#[test]
fn signed_authority_rejects_tampered_bindings_before_claim() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = directory.path().join("ledger.jsonl");
    let engine = Engine::new(MockExecutor::new(), &ledger, authority());
    let mut request = request("tampered");
    request.subject = "other-subject".to_string();

    assert!(matches!(
        engine.execute(&request, &CancellationToken::default()),
        Err(ProtocolError::AuthorityDenied)
    ));
    assert!(!ledger.exists());
}

#[test]
fn expired_signed_authority_is_terminal_before_effect() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    let engine = Engine::new(
        executor.clone(),
        directory.path().join("ledger.jsonl"),
        authority(),
    );
    let mut request = request("expired-authority");
    request.authority.grant.expires_at_ms = 1;
    sign_request(&mut request);

    let report = engine
        .execute(&request, &CancellationToken::default())
        .expect("expired result");

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0);
    assert!(matches!(terminal(&report), Terminal::ExpiredBeforeEffect));
}

#[test]
fn failed_requested_verification_is_outcome_unknown() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    executor.frozen_observation.store(true, Ordering::SeqCst);
    let engine = Engine::new(executor, directory.path().join("ledger.jsonl"), authority());
    let report = engine
        .execute(&request("unverified"), &CancellationToken::default())
        .expect("typed result");

    assert!(matches!(terminal(&report), Terminal::OutcomeUnknown { .. }));
}

#[test]
fn torn_terminal_is_repaired_then_recovered_and_replayed() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = directory.path().join("ledger.jsonl");
    let executor = MockExecutor::new();
    let engine = Engine::new(executor.clone(), &ledger, authority());
    engine
        .execute(&request("torn"), &CancellationToken::default())
        .expect("execution");
    let contents = fs::read_to_string(&ledger).expect("ledger");
    let claim = contents.lines().next().expect("claim");
    fs::write(&ledger, format!("{claim}\n")).expect("claim only");
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&ledger)
        .expect("ledger");
    use std::io::Write;
    file.write_all(b"{\"kind\":\"claim").expect("torn write");

    let recovered = engine
        .execute(&request("torn"), &CancellationToken::default())
        .expect("recover");
    let replayed = engine
        .execute(&request("torn"), &CancellationToken::default())
        .expect("replay");

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
    assert!(matches!(
        terminal(&recovered),
        Terminal::OutcomeUnknown { .. }
    ));
    assert!(replayed.acknowledgements[0].replayed);
    assert!(engine.status("torn").expect("status").is_some());
}
