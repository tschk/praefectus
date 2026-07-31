use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use praefectus::semantic::SemanticTargetRef;
use praefectus::{
    AckState, Action, ActionCapability, ActionRequest, AuthorityGrant, BackgroundSupport,
    CancellationToken, Capabilities, DeliveryRoute, Direction, DispatchError, DispatchReceipt,
    Ed25519AuthorityVerifier, Effect, EffectKnowledge, Engine, Evidence, ExecuteReport, Executor,
    FailureCode, InteractionMode, MouseButton, NativeExecutor, NativePoint, Observation,
    PROTOCOL_VERSION, ProtocolError, ResolvedTarget, SafetyClass, SessionIsolation,
    SignedAuthority, TargetRef, Terminal, VerificationPolicy, action_delivery_route,
    normalized_action_hash,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    InvalidRequest,
    RejectedBeforeEffect,
    Verified,
    ExecutedUnverified,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backend {
    Standard,
    Extended,
    Malformed,
    Minimal,
}

impl Backend {
    fn declarations(self) -> Vec<(&'static str, DeliveryRoute, BackgroundSupport)> {
        let standard = vec![
            (
                "invoke",
                DeliveryRoute::TargetAddressed,
                BackgroundSupport::Guarded,
            ),
            (
                "set_value",
                DeliveryRoute::TargetAddressed,
                BackgroundSupport::Guarded,
            ),
            (
                "scroll",
                DeliveryRoute::TargetAddressed,
                BackgroundSupport::Guarded,
            ),
            (
                "click",
                DeliveryRoute::Pointer,
                BackgroundSupport::Unavailable,
            ),
            (
                "type_text",
                DeliveryRoute::Pointer,
                BackgroundSupport::Unavailable,
            ),
            (
                "press",
                DeliveryRoute::Pointer,
                BackgroundSupport::Unavailable,
            ),
            (
                "paste",
                DeliveryRoute::Pointer,
                BackgroundSupport::Unavailable,
            ),
            (
                "hotkey",
                DeliveryRoute::Pointer,
                BackgroundSupport::Unavailable,
            ),
            (
                "move",
                DeliveryRoute::Pointer,
                BackgroundSupport::Unavailable,
            ),
        ];
        match self {
            Self::Standard => standard,
            Self::Extended => {
                let mut declarations = standard;
                declarations.extend([
                    (
                        "drag",
                        DeliveryRoute::Pointer,
                        BackgroundSupport::Unavailable,
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
                ]);
                declarations
            }
            Self::Malformed => vec![
                ("invoke", DeliveryRoute::Pointer, BackgroundSupport::Guarded),
                (
                    "scroll",
                    DeliveryRoute::TargetAddressed,
                    BackgroundSupport::Guarded,
                ),
            ],
            Self::Minimal => vec![
                (
                    "invoke",
                    DeliveryRoute::TargetAddressed,
                    BackgroundSupport::Guarded,
                ),
                (
                    "scroll",
                    DeliveryRoute::TargetAddressed,
                    BackgroundSupport::Guarded,
                ),
            ],
        }
    }

    fn expected(self, case: &Case) -> Outcome {
        if case.expected == Outcome::InvalidRequest {
            return Outcome::InvalidRequest;
        }
        if matches!(self, Self::Malformed) {
            return Outcome::RejectedBeforeEffect;
        }
        if self
            .declarations()
            .iter()
            .any(|(name, _, _)| *name == action_name(&case.action))
        {
            case.expected
        } else {
            Outcome::RejectedBeforeEffect
        }
    }
}

#[derive(Clone)]
struct HostExecutor {
    backend: Backend,
    dispatches: Arc<AtomicUsize>,
}

impl HostExecutor {
    fn new(backend: Backend) -> Self {
        Self {
            backend,
            dispatches: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Executor for HostExecutor {
    fn session_isolation(&self) -> SessionIsolation {
        SessionIsolation::SharedDesktop
    }

    fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
        let declarations = self.backend.declarations();
        Ok(Capabilities {
            platform: "conformance".to_string(),
            backend: "host".to_string(),
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
            display_geometry_hash: "display".to_string(),
        })
    }

    fn shared_desktop_context_hash(&self) -> Result<String, ProtocolError> {
        Ok("preserved-context".to_string())
    }

    fn observe(&self, target: &TargetRef) -> Result<Observation, ProtocolError> {
        let count = self.dispatches.load(Ordering::SeqCst);
        let target_fingerprint_hash = match target {
            TargetRef::Element { target } => target.fingerprint_hash.clone(),
            _ => String::new(),
        };
        Ok(Observation {
            evidence: Evidence {
                observation_hash: format!("observation-{count}"),
                target_fingerprint_hash: Some(target_fingerprint_hash),
                display_geometry_hash: "display".to_string(),
                observed_at_ms: 1,
            },
            element: None,
            state: serde_json::json!({ "count": count }),
        })
    }

    fn resolve(&self, _target: &TargetRef) -> Result<ResolvedTarget, ProtocolError> {
        Ok(ResolvedTarget::None)
    }

    fn dispatch(
        &self,
        _action: &Action,
        _target: &ResolvedTarget,
        _verification: &VerificationPolicy,
        _cancellation: &CancellationToken,
        _deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        Ok(DispatchReceipt {
            backend: "host".to_string(),
            fallback_chain: Vec::new(),
        })
    }
}

struct Case {
    name: &'static str,
    action: Action,
    target: TargetRef,
    interaction_mode: InteractionMode,
    verification: VerificationPolicy,
    expected: Outcome,
}

fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Invoke => "invoke",
        Action::Click { .. } => "click",
        Action::TypeText { .. } => "type_text",
        Action::Press { .. } => "press",
        Action::Paste { .. } => "paste",
        Action::Hotkey { .. } => "hotkey",
        Action::Scroll { .. } => "scroll",
        Action::Move => "move",
        Action::Drag { .. } => "drag",
        Action::SelectText { .. } => "select_text",
        Action::PerformSecondaryAction { .. } => "perform_secondary_action",
        Action::SetValue { .. } => "set_value",
        Action::Screenshot { .. } => "screenshot",
        Action::Application { .. } => "application",
        Action::Window { .. } => "window",
        Action::Open { .. } => "open",
        Action::ClipboardWrite { .. } => "clipboard_write",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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
    request.authority.signature = hex::encode(
        signing_key()
            .sign(
                &praefectus::canonical_authority_bytes(&request.authority.grant)
                    .expect("grant JSON"),
            )
            .to_bytes(),
    );
}

fn semantic_target() -> SemanticTargetRef {
    SemanticTargetRef {
        observation_id: "0".repeat(64),
        generation: 1,
        provenance_hash: "1".repeat(64),
        element_id: "2".repeat(64),
        fingerprint_hash: "3".repeat(64),
    }
}

fn element_target() -> TargetRef {
    TargetRef::Element {
        target: semantic_target(),
    }
}

fn coordinate_target() -> TargetRef {
    TargetRef::Coordinates {
        x: 12,
        y: 34,
        display_id: "display-1".to_string(),
        display_geometry_hash: "4".repeat(64),
        snapshot_id: "5".repeat(64),
        snapshot_content_hash: "6".repeat(64),
    }
}

fn request(operation_id: &str, case: &Case) -> ActionRequest {
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
        action: case.action.clone(),
        target: case.target.clone(),
        interaction_mode: case.interaction_mode,
        deadline_at_ms: i64::MAX,
        verification: case.verification.clone(),
        safety: SafetyClass::Reversible,
    };
    sign_request(&mut request);
    request
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

fn classify(result: Result<ExecuteReport, ProtocolError>) -> Outcome {
    match result {
        Err(ProtocolError::InvalidRequest(_)) => Outcome::InvalidRequest,
        Err(error) => panic!("unexpected protocol error: {error:?}"),
        Ok(report) => match terminal(&report) {
            Terminal::Rejected { .. }
            | Terminal::Failed { .. }
            | Terminal::CancelledBeforeEffect
            | Terminal::ExpiredBeforeEffect => Outcome::RejectedBeforeEffect,
            Terminal::Succeeded { receipt } | Terminal::OutcomeUnknown { receipt, .. } => {
                match receipt.effect {
                    Effect::Verified => Outcome::Verified,
                    Effect::ExecutedUnverified => Outcome::ExecutedUnverified,
                    Effect::Unknown => Outcome::Unknown,
                }
            }
        },
    }
}

fn verified_state() -> VerificationPolicy {
    VerificationPolicy::TargetState {
        expected: serde_json::json!({ "count": 1 }),
    }
}

fn matrix() -> Vec<Case> {
    vec![
        Case {
            name: "invoke-element-interactive-verified",
            action: Action::Invoke,
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: verified_state(),
            expected: Outcome::Verified,
        },
        Case {
            name: "invoke-element-background-verified",
            action: Action::Invoke,
            target: element_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: verified_state(),
            expected: Outcome::Verified,
        },
        Case {
            name: "invoke-element-interactive-unverified",
            action: Action::Invoke,
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::ExecutedUnverified,
        },
        Case {
            name: "scroll-element-interactive-verified",
            action: Action::Scroll {
                direction: Direction::Down,
                amount: 1,
            },
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: verified_state(),
            expected: Outcome::Verified,
        },
        Case {
            name: "scroll-element-background-verified",
            action: Action::Scroll {
                direction: Direction::Down,
                amount: 1,
            },
            target: element_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: verified_state(),
            expected: Outcome::Verified,
        },
        Case {
            name: "set-value-element-interactive-unverified",
            action: Action::SetValue {
                value: "expected value".to_string(),
            },
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::TargetValueHash {
                sha256: sha256_hex(b"expected value"),
            },
            expected: Outcome::ExecutedUnverified,
        },
        Case {
            name: "click-coordinates-interactive-unverified",
            action: Action::Click {
                button: MouseButton::Left,
                count: 1,
                allow_coordinate_fallback: false,
            },
            target: coordinate_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::ExecutedUnverified,
        },
        Case {
            name: "click-element-interactive-unverified",
            action: Action::Click {
                button: MouseButton::Left,
                count: 1,
                allow_coordinate_fallback: false,
            },
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::ExecutedUnverified,
        },
        Case {
            name: "click-coordinates-background-refused",
            action: Action::Click {
                button: MouseButton::Left,
                count: 1,
                allow_coordinate_fallback: false,
            },
            target: coordinate_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: VerificationPolicy::None,
            expected: Outcome::RejectedBeforeEffect,
        },
        Case {
            name: "type-text-element-background-refused",
            action: Action::TypeText {
                text: "x".to_string(),
                clear: false,
                press_return: false,
                delay_ms: None,
            },
            target: element_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: VerificationPolicy::None,
            expected: Outcome::RejectedBeforeEffect,
        },
        Case {
            name: "press-element-background-refused",
            action: Action::Press {
                key: "enter".to_string(),
                count: 1,
                delay_ms: None,
            },
            target: element_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: VerificationPolicy::None,
            expected: Outcome::RejectedBeforeEffect,
        },
        Case {
            name: "paste-element-background-refused",
            action: Action::Paste {
                text: "x".to_string(),
            },
            target: element_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: VerificationPolicy::None,
            expected: Outcome::RejectedBeforeEffect,
        },
        Case {
            name: "hotkey-element-background-refused",
            action: Action::Hotkey {
                keys: vec!["ctrl".to_string(), "a".to_string()],
            },
            target: element_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: VerificationPolicy::None,
            expected: Outcome::RejectedBeforeEffect,
        },
        Case {
            name: "move-coordinates-background-refused",
            action: Action::Move,
            target: coordinate_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: VerificationPolicy::None,
            expected: Outcome::RejectedBeforeEffect,
        },
        Case {
            name: "move-coordinates-interactive-unverified",
            action: Action::Move,
            target: coordinate_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::ExecutedUnverified,
        },
        Case {
            name: "drag-coordinates-interactive",
            action: Action::Drag {
                to: coordinate_target(),
                button: MouseButton::Left,
            },
            target: coordinate_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::ExecutedUnverified,
        },
        Case {
            name: "drag-coordinates-background",
            action: Action::Drag {
                to: coordinate_target(),
                button: MouseButton::Left,
            },
            target: coordinate_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: VerificationPolicy::None,
            expected: Outcome::RejectedBeforeEffect,
        },
        Case {
            name: "drag-element-target-invalid",
            action: Action::Drag {
                to: coordinate_target(),
                button: MouseButton::Left,
            },
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
        Case {
            name: "drag-none-target-invalid",
            action: Action::Drag {
                to: coordinate_target(),
                button: MouseButton::Left,
            },
            target: TargetRef::None,
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
        Case {
            name: "drag-element-destination-invalid",
            action: Action::Drag {
                to: element_target(),
                button: MouseButton::Left,
            },
            target: coordinate_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
        Case {
            name: "drag-none-destination-invalid",
            action: Action::Drag {
                to: TargetRef::None,
                button: MouseButton::Left,
            },
            target: coordinate_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
        Case {
            name: "select-text-element-interactive",
            action: Action::SelectText {
                start: 0,
                length: 4,
            },
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::ExecutedUnverified,
        },
        Case {
            name: "select-text-element-background",
            action: Action::SelectText {
                start: 0,
                length: 4,
            },
            target: element_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: verified_state(),
            expected: Outcome::Verified,
        },
        Case {
            name: "select-text-coordinates-invalid",
            action: Action::SelectText {
                start: 0,
                length: 4,
            },
            target: coordinate_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
        Case {
            name: "select-text-none-target-invalid",
            action: Action::SelectText {
                start: 0,
                length: 4,
            },
            target: TargetRef::None,
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
        Case {
            name: "select-text-out-of-range-invalid",
            action: Action::SelectText {
                start: 1_048_576,
                length: 1,
            },
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
        Case {
            name: "perform-secondary-action-element-interactive",
            action: Action::PerformSecondaryAction {
                name: "AXShowMenu".to_string(),
            },
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::ExecutedUnverified,
        },
        Case {
            name: "perform-secondary-action-element-background",
            action: Action::PerformSecondaryAction {
                name: "AXPick".to_string(),
            },
            target: element_target(),
            interaction_mode: InteractionMode::BackgroundOnly,
            verification: verified_state(),
            expected: Outcome::Verified,
        },
        Case {
            name: "perform-secondary-action-coordinates-invalid",
            action: Action::PerformSecondaryAction {
                name: "AXShowMenu".to_string(),
            },
            target: coordinate_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
        Case {
            name: "perform-secondary-action-none-target-invalid",
            action: Action::PerformSecondaryAction {
                name: "AXShowMenu".to_string(),
            },
            target: TargetRef::None,
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
        Case {
            name: "perform-secondary-action-unlisted-name-invalid",
            action: Action::PerformSecondaryAction {
                name: "AXPress".to_string(),
            },
            target: element_target(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::InvalidRequest,
        },
    ]
}

#[test]
fn every_backend_agrees_on_protocol_outcomes() {
    for case in matrix() {
        for backend in [
            Backend::Standard,
            Backend::Extended,
            Backend::Malformed,
            Backend::Minimal,
        ] {
            let directory = tempfile::tempdir().expect("temp directory");
            let executor = HostExecutor::new(backend);
            let engine = Engine::new(executor.clone(), ledger_path(&directory), authority());
            let request = request(case.name, &case);
            let outcome = classify(engine.execute(&request, &CancellationToken::default()));
            let expected = backend.expected(&case);
            assert_eq!(
                outcome, expected,
                "case {} on {backend:?} backend",
                case.name
            );
            let dispatched = executor.dispatches.load(Ordering::SeqCst);
            match outcome {
                Outcome::InvalidRequest => {
                    assert_eq!(dispatched, 0, "case {}", case.name);
                    assert!(
                        engine.status(case.name).expect("status").is_none(),
                        "case {}",
                        case.name
                    );
                }
                Outcome::RejectedBeforeEffect => {
                    assert_eq!(dispatched, 0, "case {}", case.name);
                    assert!(
                        engine.status(case.name).expect("status").is_some(),
                        "case {}",
                        case.name
                    );
                }
                _ => {
                    assert_eq!(dispatched, 1, "case {}", case.name);
                }
            }
        }
    }
}

#[test]
fn delivery_routes_agree_for_new_actions() {
    for action in [
        Action::Invoke,
        Action::SetValue {
            value: "x".to_string(),
        },
        Action::SelectText {
            start: 0,
            length: 1,
        },
        Action::PerformSecondaryAction {
            name: "AXShowMenu".to_string(),
        },
    ] {
        assert_eq!(
            action_delivery_route(&action),
            DeliveryRoute::TargetAddressed,
            "{}",
            action_name(&action)
        );
    }
    assert_eq!(
        action_delivery_route(&Action::Drag {
            to: coordinate_target(),
            button: MouseButton::Left,
        }),
        DeliveryRoute::Pointer
    );
}

#[test]
fn custom_host_click_is_unverified_where_native_click_is_refused() {
    let case = Case {
        name: "host-click",
        action: Action::Click {
            button: MouseButton::Left,
            count: 1,
            allow_coordinate_fallback: false,
        },
        target: coordinate_target(),
        interaction_mode: InteractionMode::Interactive,
        verification: VerificationPolicy::None,
        expected: Outcome::ExecutedUnverified,
    };
    let directory = tempfile::tempdir().expect("temp directory");
    let executor = HostExecutor::new(Backend::Standard);
    let engine = Engine::new(executor, ledger_path(&directory), authority());
    let report = engine
        .execute(&request(case.name, &case), &CancellationToken::default())
        .expect("host click result");
    assert!(matches!(
        terminal(&report),
        Terminal::Succeeded { receipt } if receipt.effect == Effect::ExecutedUnverified
    ));

    let native = NativeExecutor::default();
    let error = native
        .dispatch(
            &case.action,
            &ResolvedTarget::Point(NativePoint { x: 1, y: 1 }),
            &VerificationPolicy::None,
            &CancellationToken::default(),
            i64::MAX,
        )
        .expect_err("native click is never unverified success");
    assert!(matches!(
        error.effect,
        EffectKnowledge::NoEffect | EffectKnowledge::Unknown
    ));
}

#[test]
fn native_executor_refuses_new_actions_without_a_fenced_target() {
    let native = NativeExecutor::default();
    for action in [
        Action::Drag {
            to: coordinate_target(),
            button: MouseButton::Left,
        },
        Action::SelectText {
            start: 0,
            length: 4,
        },
        Action::PerformSecondaryAction {
            name: "AXShowMenu".to_string(),
        },
    ] {
        let error = native
            .dispatch(
                &action,
                &ResolvedTarget::None,
                &VerificationPolicy::None,
                &CancellationToken::default(),
                i64::MAX,
            )
            .expect_err("unfenced target");
        assert_eq!(
            error.effect,
            EffectKnowledge::NoEffect,
            "{}",
            action_name(&action)
        );
        assert!(
            matches!(error.code, FailureCode::InvalidRequest),
            "{} must be refused by the fence before any capability lookup",
            action_name(&action)
        );
        assert!(
            native
                .capabilities()
                .expect("capabilities")
                .supported_actions
                .iter()
                .all(|supported| supported != action_name(&action))
                || cfg!(target_os = "macos")
        );
    }
}

#[test]
fn new_actions_replay_and_conflict_on_operation_identity() {
    for (index, action) in [
        Action::Drag {
            to: coordinate_target(),
            button: MouseButton::Left,
        },
        Action::SelectText {
            start: 0,
            length: 4,
        },
        Action::PerformSecondaryAction {
            name: "AXShowMenu".to_string(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let target = if matches!(action, Action::Drag { .. }) {
            coordinate_target()
        } else {
            element_target()
        };
        let case = Case {
            name: "replay",
            action: action.clone(),
            target: target.clone(),
            interaction_mode: InteractionMode::Interactive,
            verification: VerificationPolicy::None,
            expected: Outcome::ExecutedUnverified,
        };
        let directory = tempfile::tempdir().expect("temp directory");
        let executor = HostExecutor::new(Backend::Extended);
        let engine = Engine::new(executor.clone(), ledger_path(&directory), authority());
        let operation_id = format!("replay-{index}");
        let first = engine
            .execute(
                &request(&operation_id, &case),
                &CancellationToken::default(),
            )
            .expect("first execution");
        assert_eq!(
            classify(Ok(first)),
            Outcome::ExecutedUnverified,
            "{}",
            action_name(&action)
        );
        assert_eq!(
            executor.dispatches.load(Ordering::SeqCst),
            1,
            "{}",
            action_name(&action)
        );
        let replay = engine
            .execute(
                &request(&operation_id, &case),
                &CancellationToken::default(),
            )
            .expect("replay");
        assert!(
            replay.acknowledgements[0].replayed,
            "{}",
            action_name(&action)
        );
        assert_eq!(
            executor.dispatches.load(Ordering::SeqCst),
            1,
            "{}",
            action_name(&action)
        );

        let mut conflicting = request(&operation_id, &case);
        conflicting.action = Action::Invoke;
        conflicting.target = element_target();
        sign_request(&mut conflicting);
        assert!(
            matches!(
                engine.execute(&conflicting, &CancellationToken::default()),
                Err(ProtocolError::Conflict)
            ),
            "{}",
            action_name(&action)
        );
        assert_eq!(executor.dispatches.load(Ordering::SeqCst), 1);
    }
}
