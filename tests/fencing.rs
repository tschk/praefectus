use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use praefectus::semantic::{
    Actionability, SemanticBackend, SemanticElement, SemanticObservation, SemanticProvenance,
    SemanticTargetRef, semantic_fingerprint, semantic_tag,
};
use praefectus::{
    AckState, Action, ActionCapability, ActionRequest, AuthorityGrant, BackgroundSupport,
    CancellationToken, Capabilities, DeliveryRoute, DispatchError, DispatchReceipt,
    Ed25519AuthorityVerifier, Effect, EffectKnowledge, Engine, Evidence, ExecuteReport, Executor,
    FailureCode, InteractionMode, MouseButton, Observation, PROTOCOL_VERSION, ProtocolError, Rect,
    ResolvedTarget, SafetyClass, SessionIsolation, SignedAuthority, TargetRef, Terminal,
    VerificationPolicy, normalized_action_hash,
};

type ObservationAttack = (&'static str, fn(&mut SemanticObservation));
type TargetAttack = (&'static str, fn(&mut SemanticTargetRef));
type RequestAttack = (&'static str, fn(&mut ActionRequest));

const NOW_MS: i64 = 1_700_000_000_000;
const COORDINATE_AGE_LIMIT_MS: i64 = 30_000;
const SELECT_TEXT_RANGE_LIMIT: u32 = 1_048_576;
use praefectus::SECONDARY_ACTIONS as ALLOWED_SECONDARY_ACTIONS;

#[derive(Clone)]
struct CoordinateFence {
    snapshot_id: String,
    snapshot_content_hash: String,
    display_geometry_hash: String,
    display_id: String,
    observed_at_ms: i64,
    bounds: Rect,
}

impl CoordinateFence {
    fn recorded() -> Self {
        Self {
            snapshot_id: "a".repeat(64),
            snapshot_content_hash: "b".repeat(64),
            display_geometry_hash: "c".repeat(64),
            display_id: "display-1".to_string(),
            observed_at_ms: NOW_MS - 1_000,
            bounds: Rect {
                x: 0,
                y: 0,
                width: 1_000,
                height: 800,
            },
        }
    }

    fn admits(&self, target: &TargetRef) -> Result<ResolvedTarget, ProtocolError> {
        let TargetRef::Coordinates {
            x,
            y,
            display_id,
            display_geometry_hash,
            snapshot_id,
            snapshot_content_hash,
        } = target
        else {
            return Err(ProtocolError::StaleTarget(
                "coordinate fence is required".to_string(),
            ));
        };
        if *snapshot_id != self.snapshot_id
            || *snapshot_content_hash != self.snapshot_content_hash
            || *display_geometry_hash != self.display_geometry_hash
            || self.observed_at_ms > NOW_MS
            || NOW_MS.saturating_sub(self.observed_at_ms) > COORDINATE_AGE_LIMIT_MS
        {
            return Err(ProtocolError::StaleTarget(
                "coordinate observation provenance does not match".to_string(),
            ));
        }
        let on_display = *display_id == self.display_id
            && *x >= self.bounds.x
            && *y >= self.bounds.y
            && *x < self.bounds.x.saturating_add(self.bounds.width)
            && *y < self.bounds.y.saturating_add(self.bounds.height);
        if !on_display {
            return Err(ProtocolError::StaleTarget(
                "coordinate is outside its named display".to_string(),
            ));
        }
        Ok(ResolvedTarget::Point(praefectus::NativePoint {
            x: *x,
            y: *y,
        }))
    }
}

#[derive(Clone)]
struct FenceExecutor {
    dispatches: Arc<AtomicUsize>,
    effects: Arc<AtomicUsize>,
    coordinates: Arc<Mutex<CoordinateFence>>,
    elements: Arc<Mutex<SemanticObservation>>,
    cancel_on_resolve: Arc<Mutex<Option<CancellationToken>>>,
    cancel_between_chunks: Arc<Mutex<Option<CancellationToken>>>,
    chunked: Arc<AtomicBool>,
}

impl FenceExecutor {
    fn new() -> Self {
        Self {
            dispatches: Arc::new(AtomicUsize::new(0)),
            effects: Arc::new(AtomicUsize::new(0)),
            coordinates: Arc::new(Mutex::new(CoordinateFence::recorded())),
            elements: Arc::new(Mutex::new(recorded_observation())),
            cancel_on_resolve: Arc::new(Mutex::new(None)),
            cancel_between_chunks: Arc::new(Mutex::new(None)),
            chunked: Arc::new(AtomicBool::new(false)),
        }
    }

    fn coordinate_fence(&self) -> CoordinateFence {
        self.coordinates.lock().expect("coordinate fence").clone()
    }
}

impl Executor for FenceExecutor {
    fn session_isolation(&self) -> SessionIsolation {
        SessionIsolation::SharedDesktop
    }

    fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
        let declarations = [
            (
                "invoke",
                DeliveryRoute::TargetAddressed,
                BackgroundSupport::Guarded,
            ),
            (
                "select_text",
                DeliveryRoute::TargetAddressed,
                BackgroundSupport::Guarded,
            ),
            (
                "perform_secondary_action",
                DeliveryRoute::TargetAddressed,
                BackgroundSupport::Guarded,
            ),
            (
                "click",
                DeliveryRoute::Pointer,
                BackgroundSupport::Unavailable,
            ),
            (
                "move",
                DeliveryRoute::Pointer,
                BackgroundSupport::Unavailable,
            ),
            (
                "drag",
                DeliveryRoute::Pointer,
                BackgroundSupport::Unavailable,
            ),
        ];
        Ok(Capabilities {
            platform: "fencing".to_string(),
            backend: "fence".to_string(),
            session_isolation: self.session_isolation(),
            supported_actions: declarations
                .iter()
                .map(|(action, _, _)| (*action).to_string())
                .collect(),
            action_capabilities: declarations
                .iter()
                .map(|(action, route, support)| ActionCapability {
                    action: (*action).to_string(),
                    delivery_route: *route,
                    background_support: *support,
                })
                .collect(),
            permissions: BTreeMap::new(),
            display_geometry_hash: "c".repeat(64),
        })
    }

    fn shared_desktop_context_hash(&self) -> Result<String, ProtocolError> {
        Ok("preserved-context".to_string())
    }

    fn observe(&self, target: &TargetRef) -> Result<Observation, ProtocolError> {
        let count = self.effects.load(Ordering::SeqCst);
        let target_fingerprint_hash = match target {
            TargetRef::Element { target } => target.fingerprint_hash.clone(),
            _ => String::new(),
        };
        Ok(Observation {
            evidence: Evidence {
                observation_hash: format!("observation-{count}"),
                target_fingerprint_hash: Some(target_fingerprint_hash),
                display_geometry_hash: "c".repeat(64),
                observed_at_ms: 1,
            },
            element: None,
            state: serde_json::json!({ "count": count }),
        })
    }

    fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, ProtocolError> {
        if let Some(cancellation) = self
            .cancel_on_resolve
            .lock()
            .expect("resolve cancellation")
            .take()
        {
            cancellation.cancel();
        }
        match target {
            TargetRef::Coordinates { .. } => self.coordinate_fence().admits(target),
            TargetRef::Element { target } => {
                self.elements
                    .lock()
                    .expect("element fence")
                    .resolve(target, NOW_MS)
                    .map_err(|error| ProtocolError::StaleTarget(error.to_string()))?;
                Ok(ResolvedTarget::Semantic(target.clone()))
            }
            TargetRef::None => Ok(ResolvedTarget::None),
        }
    }

    fn dispatch(
        &self,
        action: &Action,
        _target: &ResolvedTarget,
        _verification: &VerificationPolicy,
        cancellation: &CancellationToken,
        _deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        if cancellation.is_cancelled() {
            return Err(DispatchError {
                message: "cancelled before dispatch".to_string(),
                effect: EffectKnowledge::CancelledBeforeEffect,
                code: FailureCode::DispatchFailed,
            });
        }
        if let Action::Drag { to, .. } = action {
            self.coordinate_fence()
                .admits(to)
                .map_err(|_| DispatchError {
                    message: "drag destination is not fenced".to_string(),
                    effect: EffectKnowledge::NoEffect,
                    code: FailureCode::StaleTarget,
                })?;
        }
        if self.chunked.load(Ordering::SeqCst) {
            self.effects.fetch_add(1, Ordering::SeqCst);
            if let Some(cancellation) = self
                .cancel_between_chunks
                .lock()
                .expect("chunk cancellation")
                .take()
            {
                cancellation.cancel();
            }
            if cancellation.is_cancelled() {
                return Err(DispatchError {
                    message: "cancelled between chunks after a partial effect".to_string(),
                    effect: EffectKnowledge::Unknown,
                    code: FailureCode::DispatchFailed,
                });
            }
        }
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(DispatchReceipt {
            backend: "fence".to_string(),
            fallback_chain: Vec::new(),
        })
    }
}

fn recorded_provenance() -> SemanticProvenance {
    SemanticProvenance {
        backend: SemanticBackend::Accessibility,
        backend_name: "fence-accessibility".to_string(),
        process_id: 4_242,
        process_generation: "process-1".to_string(),
        window_id: "window-1".to_string(),
        document_id: None,
        display_geometry_hash: "c".repeat(64),
    }
}

fn recorded_observation() -> SemanticObservation {
    let observation_id = "d".repeat(64);
    SemanticObservation {
        protocol_version: PROTOCOL_VERSION,
        observation_id: observation_id.clone(),
        generation: 9,
        provenance: recorded_provenance(),
        observed_at_ms: NOW_MS - 1_000,
        expires_at_ms: NOW_MS + 20_000,
        truncated: false,
        elements: vec![SemanticElement {
            tag: semantic_tag(0).expect("tag"),
            element_id: praefectus::semantic::opaque_element_id(&observation_id, "fenced-node")
                .expect("element id"),
            parent_id: None,
            fingerprint_hash: semantic_fingerprint(&("button", "Send", 1)).expect("fingerprint"),
            role: "button".to_string(),
            name: Some("Send".to_string()),
            bounds: Some(Rect {
                x: 10,
                y: 20,
                width: 100,
                height: 30,
            }),
            actionability: Actionability {
                visible: true,
                enabled: true,
                unambiguous: true,
                stable: true,
                receives_events: true,
                invokable: true,
                editable: true,
            },
        }],
    }
}

fn element_target() -> TargetRef {
    let observation = recorded_observation();
    TargetRef::Element {
        target: observation
            .target(&observation.elements[0].tag)
            .expect("fenced element target"),
    }
}

fn semantic_target() -> SemanticTargetRef {
    match element_target() {
        TargetRef::Element { target } => target,
        _ => unreachable!(),
    }
}

fn coordinate_target() -> TargetRef {
    let fence = CoordinateFence::recorded();
    TargetRef::Coordinates {
        x: 120,
        y: 240,
        display_id: fence.display_id,
        display_geometry_hash: fence.display_geometry_hash,
        snapshot_id: fence.snapshot_id,
        snapshot_content_hash: fence.snapshot_content_hash,
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn authority() -> Ed25519AuthorityVerifier {
    Ed25519AuthorityVerifier::new([(
        "host-1".to_string(),
        "key-1".to_string(),
        "generation-1".to_string(),
        signing_key().verifying_key(),
    )])
    .expect("valid authority keyring")
}

fn sign_request(request: &mut ActionRequest) {
    request.authority.grant.operation_id = request.operation_id.clone();
    request.authority.grant.subject = request.subject.clone();
    request.authority.grant.session_id = request.session_id.clone();
    request.authority.grant.risk = request.safety;
    request.authority.grant.action_hash = normalized_action_hash(request).expect("action hash");
    seal(request);
}

fn seal(request: &mut ActionRequest) {
    request.authority.signature = hex::encode(
        signing_key()
            .sign(
                &praefectus::canonical_authority_bytes(&request.authority.grant)
                    .expect("grant JSON"),
            )
            .to_bytes(),
    );
}

fn request(operation_id: &str, action: Action, target: TargetRef) -> ActionRequest {
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
        action,
        target,
        interaction_mode: InteractionMode::Interactive,
        deadline_at_ms: i64::MAX,
        verification: VerificationPolicy::None,
        safety: SafetyClass::Reversible,
    };
    sign_request(&mut request);
    request
}

fn invoke_request(operation_id: &str) -> ActionRequest {
    request(operation_id, Action::Invoke, element_target())
}

fn click_request(operation_id: &str, target: TargetRef) -> ActionRequest {
    request(
        operation_id,
        Action::Click {
            button: MouseButton::Left,
            count: 1,
            allow_coordinate_fallback: false,
        },
        target,
    )
}

fn ledger_path(directory: &tempfile::TempDir) -> std::path::PathBuf {
    directory.path().join("state").join("ledger.jsonl")
}

fn terminal(report: &ExecuteReport) -> &Terminal {
    match &report.acknowledgements.last().expect("terminal ack").state {
        AckState::Terminal { terminal } => terminal,
        _ => panic!("expected terminal acknowledgement"),
    }
}

fn harness(directory: &tempfile::TempDir) -> (FenceExecutor, Engine<FenceExecutor>) {
    let executor = FenceExecutor::new();
    let engine = Engine::new(executor.clone(), ledger_path(directory), authority());
    (executor, engine)
}

fn assert_refused_before_effect(
    executor: &FenceExecutor,
    engine: &Engine<FenceExecutor>,
    request: &ActionRequest,
    label: &str,
) {
    let report = engine
        .execute(request, &CancellationToken::default())
        .unwrap_or_else(|error| panic!("{label} must be durably refused, got {error:?}"));
    assert!(
        matches!(
            terminal(&report),
            Terminal::Rejected {
                code: FailureCode::StaleTarget,
                ..
            }
        ),
        "{label}"
    );
    assert_eq!(executor.effects.load(Ordering::SeqCst), 0, "{label}");
    assert!(
        engine
            .status(&request.operation_id)
            .expect("status")
            .is_some(),
        "{label}"
    );
}

#[test]
fn stale_or_forged_coordinate_fences_are_refused_before_any_effect() {
    let recorded = CoordinateFence::recorded();
    let attacks: Vec<(&str, TargetRef, Option<CoordinateFence>)> = vec![
        (
            "forged-snapshot-id",
            TargetRef::Coordinates {
                x: 120,
                y: 240,
                display_id: recorded.display_id.clone(),
                display_geometry_hash: recorded.display_geometry_hash.clone(),
                snapshot_id: "e".repeat(64),
                snapshot_content_hash: recorded.snapshot_content_hash.clone(),
            },
            None,
        ),
        (
            "forged-snapshot-content-hash",
            TargetRef::Coordinates {
                x: 120,
                y: 240,
                display_id: recorded.display_id.clone(),
                display_geometry_hash: recorded.display_geometry_hash.clone(),
                snapshot_id: recorded.snapshot_id.clone(),
                snapshot_content_hash: "e".repeat(64),
            },
            None,
        ),
        (
            "forged-display-geometry-hash",
            TargetRef::Coordinates {
                x: 120,
                y: 240,
                display_id: recorded.display_id.clone(),
                display_geometry_hash: "e".repeat(64),
                snapshot_id: recorded.snapshot_id.clone(),
                snapshot_content_hash: recorded.snapshot_content_hash.clone(),
            },
            None,
        ),
        (
            "coordinate-outside-named-display",
            TargetRef::Coordinates {
                x: recorded.bounds.width,
                y: 240,
                display_id: recorded.display_id.clone(),
                display_geometry_hash: recorded.display_geometry_hash.clone(),
                snapshot_id: recorded.snapshot_id.clone(),
                snapshot_content_hash: recorded.snapshot_content_hash.clone(),
            },
            None,
        ),
        (
            "coordinate-on-a-different-display",
            TargetRef::Coordinates {
                x: 120,
                y: 240,
                display_id: "display-2".to_string(),
                display_geometry_hash: recorded.display_geometry_hash.clone(),
                snapshot_id: recorded.snapshot_id.clone(),
                snapshot_content_hash: recorded.snapshot_content_hash.clone(),
            },
            None,
        ),
        (
            "observation-older-than-the-age-limit",
            coordinate_target(),
            Some(CoordinateFence {
                observed_at_ms: NOW_MS - COORDINATE_AGE_LIMIT_MS - 1,
                ..CoordinateFence::recorded()
            }),
        ),
        (
            "observation-from-the-future",
            coordinate_target(),
            Some(CoordinateFence {
                observed_at_ms: NOW_MS + 1,
                ..CoordinateFence::recorded()
            }),
        ),
    ];
    for (label, target, fence) in attacks {
        let directory = tempfile::tempdir().expect("temp directory");
        let (executor, engine) = harness(&directory);
        if let Some(fence) = fence {
            *executor.coordinates.lock().expect("coordinate fence") = fence;
        }
        let request = click_request(label, target);
        assert_refused_before_effect(&executor, &engine, &request, label);
    }
}

#[test]
fn coordinate_fence_at_the_age_limit_still_reaches_a_fenced_effect() {
    let directory = tempfile::tempdir().expect("temp directory");
    let (executor, engine) = harness(&directory);
    *executor.coordinates.lock().expect("coordinate fence") = CoordinateFence {
        observed_at_ms: NOW_MS - COORDINATE_AGE_LIMIT_MS,
        ..CoordinateFence::recorded()
    };
    let report = engine
        .execute(
            &click_request("coordinate-age-boundary", coordinate_target()),
            &CancellationToken::default(),
        )
        .expect("boundary result");

    assert!(matches!(
        terminal(&report),
        Terminal::Succeeded { receipt } if receipt.effect == Effect::ExecutedUnverified
    ));
    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
}

#[test]
fn changed_element_provenance_is_refused_before_any_effect() {
    let mutations: Vec<ObservationAttack> = vec![
        ("changed-process-id", |observation| {
            observation.provenance.process_id = 5_555;
        }),
        ("changed-process-generation", |observation| {
            observation.provenance.process_generation = "process-2".to_string();
        }),
        ("changed-window-identity", |observation| {
            observation.provenance.window_id = "window-2".to_string();
        }),
        ("changed-observation-generation", |observation| {
            observation.generation += 1;
        }),
        ("changed-backend-provenance", |observation| {
            observation.provenance.backend_name = "other-backend".to_string();
        }),
        ("changed-display-geometry", |observation| {
            observation.provenance.display_geometry_hash = "e".repeat(64);
        }),
        ("changed-element-fingerprint", |observation| {
            observation.elements[0].fingerprint_hash =
                semantic_fingerprint(&("button", "Send", 2)).expect("fingerprint");
        }),
        ("changed-observation-identity", |observation| {
            observation.observation_id = "f".repeat(64);
        }),
        ("element-removed-from-the-observation", |observation| {
            observation.elements.clear();
        }),
    ];
    for (label, mutate) in mutations {
        let directory = tempfile::tempdir().expect("temp directory");
        let (executor, engine) = harness(&directory);
        {
            let mut observation = executor.elements.lock().expect("element fence");
            mutate(&mut observation);
        }
        let request = invoke_request(label);
        assert_refused_before_effect(&executor, &engine, &request, label);
    }
}

#[test]
fn forged_element_target_bindings_are_refused_before_any_effect() {
    let mutations: Vec<TargetAttack> = vec![
        ("forged-target-generation", |target| {
            target.generation += 1;
        }),
        ("forged-target-provenance-hash", |target| {
            target.provenance_hash = "e".repeat(64);
        }),
        ("forged-target-fingerprint-hash", |target| {
            target.fingerprint_hash = "e".repeat(64);
        }),
        ("forged-target-element-id", |target| {
            target.element_id = "e".repeat(64);
        }),
        ("forged-target-observation-id", |target| {
            target.observation_id = "e".repeat(64);
        }),
    ];
    for (label, mutate) in mutations {
        let directory = tempfile::tempdir().expect("temp directory");
        let (executor, engine) = harness(&directory);
        let mut target = semantic_target();
        mutate(&mut target);
        let mut forged = request(label, Action::Invoke, TargetRef::Element { target });
        sign_request(&mut forged);
        assert_refused_before_effect(&executor, &engine, &forged, label);
    }
}

#[test]
fn unpinned_and_misbound_authority_is_denied_before_the_ledger_exists() {
    let attacks: Vec<RequestAttack> = vec![
        ("issuer-not-host-pinned", |request| {
            request.authority.grant.issuer = "host-2".to_string();
            seal(request);
        }),
        ("key-not-host-pinned", |request| {
            request.authority.grant.key_id = "key-2".to_string();
            seal(request);
        }),
        ("policy-generation-rotated", |request| {
            request.authority.grant.policy_generation = "generation-2".to_string();
            seal(request);
        }),
        ("grant-bound-to-another-operation", |request| {
            request.authority.grant.operation_id = "other-operation".to_string();
            seal(request);
        }),
        ("grant-bound-to-another-subject", |request| {
            request.authority.grant.subject = "other-subject".to_string();
            seal(request);
        }),
        ("grant-bound-to-another-session", |request| {
            request.authority.grant.session_id = "other-session".to_string();
            seal(request);
        }),
        ("grant-bound-to-another-safety-class", |request| {
            request.authority.grant.risk = SafetyClass::Destructive;
            seal(request);
        }),
        ("signature-over-a-different-action", |request| {
            request.action = Action::SelectText {
                start: 0,
                length: 4,
            };
        }),
        ("signature-over-a-different-target", |request| {
            request.target = TargetRef::Element {
                target: SemanticTargetRef {
                    element_id: "e".repeat(64),
                    ..semantic_target()
                },
            };
        }),
        ("signature-over-a-different-verification", |request| {
            request.verification = VerificationPolicy::SnapshotChanged;
        }),
        ("unsigned-grant", |request| {
            request.authority.signature = "0".repeat(128);
        }),
    ];
    for (label, tamper) in attacks {
        let directory = tempfile::tempdir().expect("temp directory");
        let ledger = ledger_path(&directory);
        let executor = FenceExecutor::new();
        let engine = Engine::new(executor.clone(), &ledger, authority());
        let mut attacked = invoke_request(label);
        tamper(&mut attacked);
        assert!(
            matches!(
                engine.execute(&attacked, &CancellationToken::default()),
                Err(ProtocolError::AuthorityDenied)
            ),
            "{label}"
        );
        assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0, "{label}");
        assert!(!ledger.exists(), "{label}");
    }
}

#[test]
fn an_expired_grant_bounds_an_unbounded_request_deadline_and_is_never_retried() {
    let directory = tempfile::tempdir().expect("temp directory");
    let (executor, engine) = harness(&directory);
    let mut expired = invoke_request("expired-grant");
    expired.deadline_at_ms = i64::MAX;
    expired.authority.grant.expires_at_ms = 1;
    seal(&mut expired);

    let report = engine
        .execute(&expired, &CancellationToken::default())
        .expect("expired result");
    let replay = engine
        .execute(&expired, &CancellationToken::default())
        .expect("expired replay");

    assert!(matches!(terminal(&report), Terminal::ExpiredBeforeEffect));
    assert!(replay.acknowledgements[0].replayed);
    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0);
}

#[test]
fn a_reused_operation_id_with_a_new_action_hash_conflicts_without_a_second_effect() {
    let directory = tempfile::tempdir().expect("temp directory");
    let (executor, engine) = harness(&directory);
    engine
        .execute(
            &request(
                "fence-conflict",
                Action::SelectText {
                    start: 0,
                    length: 4,
                },
                element_target(),
            ),
            &CancellationToken::default(),
        )
        .expect("first execution");

    for action in [
        Action::SelectText {
            start: 0,
            length: 5,
        },
        Action::PerformSecondaryAction {
            name: "AXShowMenu".to_string(),
        },
        Action::Invoke,
    ] {
        let conflicting = request("fence-conflict", action, element_target());
        assert!(matches!(
            engine.execute(&conflicting, &CancellationToken::default()),
            Err(ProtocolError::Conflict)
        ));
    }
    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
}

#[test]
fn a_durable_claim_without_a_terminal_result_recovers_as_outcome_unknown() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = ledger_path(&directory);
    let executor = FenceExecutor::new();
    let engine = Engine::new(executor.clone(), &ledger, authority());
    let original = request(
        "fence-recovery",
        Action::PerformSecondaryAction {
            name: "AXShowMenu".to_string(),
        },
        element_target(),
    );
    engine
        .execute(&original, &CancellationToken::default())
        .expect("first execution");
    let contents = fs::read_to_string(&ledger).expect("ledger");
    let claim = contents.lines().next().expect("claim");
    fs::write(&ledger, format!("{claim}\n")).expect("truncated ledger");

    let recovered = engine
        .execute(&original, &CancellationToken::default())
        .expect("recovery");
    let replay = engine
        .execute(&original, &CancellationToken::default())
        .expect("replay");

    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
    assert!(matches!(
        terminal(&recovered),
        Terminal::OutcomeUnknown { receipt, .. } if receipt.effect == Effect::Unknown
    ));
    let encoded = serde_json::to_string(terminal(&recovered)).expect("terminal JSON");
    assert!(encoded.contains("\"kind\":\"outcome_unknown\""));
    assert!(replay.acknowledgements[0].replayed);
    assert!(!matches!(
        terminal(&recovered),
        Terminal::CancelledBeforeEffect | Terminal::ExpiredBeforeEffect
    ));
}

#[test]
fn cancellation_at_the_resolve_boundary_stops_before_the_effect() {
    let directory = tempfile::tempdir().expect("temp directory");
    let (executor, engine) = harness(&directory);
    let cancellation = CancellationToken::default();
    *executor
        .cancel_on_resolve
        .lock()
        .expect("resolve cancellation") = Some(cancellation.clone());
    let report = engine
        .execute(&invoke_request("cancel-at-resolve"), &cancellation)
        .expect("cancelled result");

    assert!(matches!(terminal(&report), Terminal::CancelledBeforeEffect));
    assert_eq!(executor.effects.load(Ordering::SeqCst), 0);
}

#[test]
fn an_expired_deadline_stops_before_the_effect_without_consuming_the_target() {
    let directory = tempfile::tempdir().expect("temp directory");
    let (executor, engine) = harness(&directory);
    let mut expired = click_request("deadline-before-effect", coordinate_target());
    expired.deadline_at_ms = 1;
    sign_request(&mut expired);
    let report = engine
        .execute(&expired, &CancellationToken::default())
        .expect("expired result");

    assert!(matches!(terminal(&report), Terminal::ExpiredBeforeEffect));
    assert_eq!(executor.effects.load(Ordering::SeqCst), 0);
}

#[test]
fn cancellation_between_chunks_after_a_partial_effect_is_outcome_unknown() {
    let directory = tempfile::tempdir().expect("temp directory");
    let (executor, engine) = harness(&directory);
    executor.chunked.store(true, Ordering::SeqCst);
    let cancellation = CancellationToken::default();
    *executor
        .cancel_between_chunks
        .lock()
        .expect("chunk cancellation") = Some(cancellation.clone());
    let report = engine
        .execute(
            &request(
                "cancel-between-chunks",
                Action::Drag {
                    to: coordinate_target(),
                    button: MouseButton::Left,
                },
                coordinate_target(),
            ),
            &cancellation,
        )
        .expect("chunked result");

    assert!(matches!(
        terminal(&report),
        Terminal::OutcomeUnknown { receipt, .. } if receipt.effect == Effect::Unknown
    ));
    assert_eq!(executor.effects.load(Ordering::SeqCst), 1);
}

#[test]
fn a_drag_destination_that_is_not_fenced_is_refused_after_no_effect() {
    let recorded = CoordinateFence::recorded();
    let destinations = [
        (
            "drag-to-a-forged-snapshot",
            TargetRef::Coordinates {
                x: 300,
                y: 300,
                display_id: recorded.display_id.clone(),
                display_geometry_hash: recorded.display_geometry_hash.clone(),
                snapshot_id: "e".repeat(64),
                snapshot_content_hash: recorded.snapshot_content_hash.clone(),
            },
        ),
        (
            "drag-to-a-stale-snapshot-content-hash",
            TargetRef::Coordinates {
                x: 300,
                y: 300,
                display_id: recorded.display_id.clone(),
                display_geometry_hash: recorded.display_geometry_hash.clone(),
                snapshot_id: recorded.snapshot_id.clone(),
                snapshot_content_hash: "e".repeat(64),
            },
        ),
        (
            "drag-to-a-mismatched-display-geometry",
            TargetRef::Coordinates {
                x: 300,
                y: 300,
                display_id: recorded.display_id.clone(),
                display_geometry_hash: "e".repeat(64),
                snapshot_id: recorded.snapshot_id.clone(),
                snapshot_content_hash: recorded.snapshot_content_hash.clone(),
            },
        ),
        (
            "drag-to-a-point-outside-its-named-display",
            TargetRef::Coordinates {
                x: recorded.bounds.width,
                y: 300,
                display_id: recorded.display_id.clone(),
                display_geometry_hash: recorded.display_geometry_hash.clone(),
                snapshot_id: recorded.snapshot_id.clone(),
                snapshot_content_hash: recorded.snapshot_content_hash.clone(),
            },
        ),
    ];
    for (label, destination) in destinations {
        let directory = tempfile::tempdir().expect("temp directory");
        let (executor, engine) = harness(&directory);
        let report = engine
            .execute(
                &request(
                    label,
                    Action::Drag {
                        to: destination,
                        button: MouseButton::Left,
                    },
                    coordinate_target(),
                ),
                &CancellationToken::default(),
            )
            .expect("drag result");

        assert!(
            matches!(
                terminal(&report),
                Terminal::Rejected {
                    code: FailureCode::StaleTarget,
                    ..
                }
            ),
            "{label}"
        );
        assert_eq!(executor.effects.load(Ordering::SeqCst), 0, "{label}");
        assert!(engine.status(label).expect("status").is_some(), "{label}");
    }
}

#[test]
fn secondary_actions_outside_the_allowlist_never_reach_a_claim() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = ledger_path(&directory);
    let executor = FenceExecutor::new();
    let engine = Engine::new(executor.clone(), &ledger, authority());
    for name in [
        "AXPress",
        "AXRaise",
        "AXOpen",
        "AXDelete",
        "axshowmenu",
        "AXShowMenu ",
        " AXShowMenu",
        "AXShowMenu\u{0}",
        "",
        "AXShowMenu,AXPress",
    ] {
        let attacked = request(
            "secondary-allowlist",
            Action::PerformSecondaryAction {
                name: name.to_string(),
            },
            element_target(),
        );
        assert!(
            matches!(
                engine.execute(&attacked, &CancellationToken::default()),
                Err(ProtocolError::InvalidRequest(_))
            ),
            "{name:?}"
        );
    }
    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0);
    assert!(!ledger.exists());
}

#[test]
fn every_allowlisted_secondary_action_is_accepted_and_invoke_is_not_one_of_them() {
    assert!(!ALLOWED_SECONDARY_ACTIONS.contains(&"AXPress"));
    for name in ALLOWED_SECONDARY_ACTIONS {
        let directory = tempfile::tempdir().expect("temp directory");
        let (executor, engine) = harness(&directory);
        let report = engine
            .execute(
                &request(
                    name,
                    Action::PerformSecondaryAction {
                        name: name.to_string(),
                    },
                    element_target(),
                ),
                &CancellationToken::default(),
            )
            .unwrap_or_else(|error| panic!("{name} must be allowlisted, got {error:?}"));
        assert!(
            matches!(
                terminal(&report),
                Terminal::Succeeded { receipt } if receipt.effect == Effect::ExecutedUnverified
            ),
            "{name}"
        );
        assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1, "{name}");
    }
}

#[test]
fn select_text_ranges_beyond_the_protocol_limit_never_reach_a_claim() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = ledger_path(&directory);
    let executor = FenceExecutor::new();
    let engine = Engine::new(executor.clone(), &ledger, authority());
    for (start, length) in [
        (SELECT_TEXT_RANGE_LIMIT, 1),
        (0, SELECT_TEXT_RANGE_LIMIT + 1),
        (SELECT_TEXT_RANGE_LIMIT, SELECT_TEXT_RANGE_LIMIT),
        (u32::MAX, u32::MAX),
        (u32::MAX, 0),
    ] {
        let attacked = request(
            "select-text-range",
            Action::SelectText { start, length },
            element_target(),
        );
        assert!(
            matches!(
                engine.execute(&attacked, &CancellationToken::default()),
                Err(ProtocolError::InvalidRequest(_))
            ),
            "{start}+{length}"
        );
    }
    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0);
    assert!(!ledger.exists());

    let boundary = engine
        .execute(
            &request(
                "select-text-boundary",
                Action::SelectText {
                    start: SELECT_TEXT_RANGE_LIMIT - 1,
                    length: 1,
                },
                element_target(),
            ),
            &CancellationToken::default(),
        )
        .expect("boundary result");
    assert!(matches!(terminal(&boundary), Terminal::Succeeded { .. }));
}

#[test]
fn new_actions_reject_target_kinds_they_cannot_fence() {
    let directory = tempfile::tempdir().expect("temp directory");
    let ledger = ledger_path(&directory);
    let executor = FenceExecutor::new();
    let engine = Engine::new(executor.clone(), &ledger, authority());
    let attacks = [
        (
            "select-text-on-coordinates",
            Action::SelectText {
                start: 0,
                length: 4,
            },
            coordinate_target(),
        ),
        (
            "select-text-without-a-target",
            Action::SelectText {
                start: 0,
                length: 4,
            },
            TargetRef::None,
        ),
        (
            "secondary-action-on-coordinates",
            Action::PerformSecondaryAction {
                name: "AXPick".to_string(),
            },
            coordinate_target(),
        ),
        (
            "secondary-action-without-a-target",
            Action::PerformSecondaryAction {
                name: "AXPick".to_string(),
            },
            TargetRef::None,
        ),
        (
            "drag-from-an-element",
            Action::Drag {
                to: coordinate_target(),
                button: MouseButton::Left,
            },
            element_target(),
        ),
        (
            "drag-without-a-target",
            Action::Drag {
                to: coordinate_target(),
                button: MouseButton::Left,
            },
            TargetRef::None,
        ),
        (
            "drag-to-an-element",
            Action::Drag {
                to: element_target(),
                button: MouseButton::Left,
            },
            coordinate_target(),
        ),
        (
            "drag-to-nothing",
            Action::Drag {
                to: TargetRef::None,
                button: MouseButton::Left,
            },
            coordinate_target(),
        ),
    ];
    for (label, action, target) in attacks {
        let attacked = request(label, action, target);
        assert!(
            matches!(
                engine.execute(&attacked, &CancellationToken::default()),
                Err(ProtocolError::InvalidRequest(_))
            ),
            "{label}"
        );
    }
    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0);
    assert!(!ledger.exists());
}

#[test]
fn a_drag_destination_with_invalid_provenance_is_refused_before_any_claim() {
    let directory = tempfile::tempdir().expect("temp directory");
    let (executor, engine) = harness(&directory);
    let ledger = directory.path().join("operations.jsonl");
    let attacked = request(
        "drag-destination-provenance",
        Action::Drag {
            to: TargetRef::Coordinates {
                x: 1,
                y: 1,
                display_id: String::new(),
                display_geometry_hash: "x".to_string(),
                snapshot_id: String::new(),
                snapshot_content_hash: String::new(),
            },
            button: MouseButton::Left,
        },
        coordinate_target(),
    );

    assert!(matches!(
        engine.execute(&attacked, &CancellationToken::default()),
        Err(ProtocolError::InvalidRequest(_))
    ));
    assert_eq!(executor.dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(executor.effects.load(Ordering::SeqCst), 0);
    assert!(!ledger.exists());
}
