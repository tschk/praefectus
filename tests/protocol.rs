use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use praefectus::{
    AckState, Action, ActionRequest, AuthorityGrant, CancellationToken, Capabilities, Direction,
    DispatchError, DispatchReceipt, Ed25519AuthorityVerifier, Effect, EffectKnowledge, Engine,
    Evidence, Executor, FailureCode, Observation, PROTOCOL_VERSION, ProtocolError, ResolvedTarget,
    SafetyClass, SignedAuthority, TargetRef, Terminal, VerificationPolicy, normalized_action_hash,
};

#[derive(Clone, Copy)]
enum Behavior {
    Success,
    Ambiguous,
    NoEffect,
}

#[derive(Clone)]
struct MockExecutor {
    dispatches: Arc<AtomicUsize>,
    observations: Arc<AtomicUsize>,
    stale: Arc<AtomicBool>,
    behavior: Arc<Mutex<Behavior>>,
    frozen_observation: Arc<AtomicBool>,
}

impl MockExecutor {
    fn new() -> Self {
        Self {
            dispatches: Arc::new(AtomicUsize::new(0)),
            observations: Arc::new(AtomicUsize::new(0)),
            stale: Arc::new(AtomicBool::new(false)),
            behavior: Arc::new(Mutex::new(Behavior::Success)),
            frozen_observation: Arc::new(AtomicBool::new(false)),
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

    fn observe(&self, _target: &TargetRef) -> Result<Observation, ProtocolError> {
        let count = self.observations.fetch_add(1, Ordering::SeqCst);
        let count = if self.frozen_observation.load(Ordering::SeqCst) {
            0
        } else {
            count
        };
        Ok(Observation {
            evidence: Evidence {
                observation_hash: format!("observation-{count}"),
                target_fingerprint_hash: None,
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
        _cancellation: &CancellationToken,
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
        }
    }
}

fn request(operation_id: &str) -> ActionRequest {
    let mut request = ActionRequest {
        protocol_version: PROTOCOL_VERSION,
        action_version: PROTOCOL_VERSION,
        target_version: PROTOCOL_VERSION,
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
        target: TargetRef::None,
        deadline_at_ms: i64::MAX,
        verification: VerificationPolicy::SnapshotChanged,
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
            .sign(&serde_json::to_vec(&request.authority.grant).expect("grant JSON"))
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
        Terminal::Failed {
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
fn changed_post_action_observation_verifies_success() {
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = MockExecutor::new();
    let engine = Engine::new(executor, directory.path().join("ledger.jsonl"), authority());
    let report = engine
        .execute(&request("verified"), &CancellationToken::default())
        .expect("verified execution");

    match terminal(&report) {
        Terminal::Succeeded { receipt } => assert!(matches!(receipt.effect, Effect::Verified)),
        _ => panic!("expected success"),
    }
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

    assert!(matches!(terminal(&report), Terminal::Failed { .. }));
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
        .execute(&request("recovery"), &CancellationToken::default())
        .expect("recovery");

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
    assert!(matches!(
        terminal(&recovered),
        Terminal::OutcomeUnknown { .. }
    ));
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
