use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use ed25519_dalek::{Signer, SigningKey};
use praefectus::{
    AckState, Action, ActionRequest, AuthorityGrant, CancellationToken, DenyAuthority,
    Ed25519AuthorityVerifier, Engine, InteractionMode, NativeExecutor, PROTOCOL_VERSION,
    SafetyClass, SignedAuthority, SurfaceRef, TargetRef, Terminal, VerificationPolicy,
    canonical_authority_bytes, default_ledger_path, global_input_allowance, normalized_action_hash,
    persist_no_yolo, semantic::SemanticObservation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const EXIT_USAGE: u8 = 2;
const EXIT_PROTOCOL: u8 = 3;

fn main() -> ExitCode {
    let result = run(std::env::args().skip(1).collect());
    let (value, exit) = match result {
        Ok((output, exit)) => (
            serde_json::to_value(SuccessEnvelope { ok: true, data: output }).unwrap_or_else(|_| {
                serde_json::json!({"ok":false,"error":{"code":"serialization_error","message":"failed to serialize CLI output"}})
            }),
            exit,
        ),
        Err(error) => (
            serde_json::to_value(ErrorEnvelope::new(&error))
                .unwrap_or_else(|_| serde_json::json!({"error":{"code":"serialization_error","message":"failed to serialize CLI error"}})),
            error.exit,
        ),
    };
    match serde_json::to_writer(io::stdout().lock(), &value) {
        Ok(()) => {
            println!();
            ExitCode::from(exit)
        }
        Err(error) => {
            eprintln!("praefectus: {error}");
            ExitCode::FAILURE
        }
    }
}

struct CliError {
    code: &'static str,
    message: String,
    exit: u8,
    report: Option<serde_json::Value>,
    #[cfg(test)]
    diagnostic: Option<String>,
}

impl std::fmt::Debug for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("CliError");
        debug
            .field("code", &self.code)
            .field("message", &self.message);
        #[cfg(test)]
        debug.field("diagnostic", &self.diagnostic);
        debug.finish()
    }
}

#[derive(Serialize)]
struct SuccessEnvelope {
    ok: bool,
    data: serde_json::Value,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    ok: bool,
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'static str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<&'a serde_json::Value>,
}

impl<'a> From<&'a CliError> for ErrorBody<'a> {
    fn from(error: &'a CliError) -> Self {
        Self {
            code: error.code,
            message: &error.message,
            report: error.report.as_ref(),
        }
    }
}

impl<'a> ErrorEnvelope<'a> {
    fn new(error: &'a CliError) -> Self {
        Self {
            ok: false,
            error: error.into(),
        }
    }
}

fn run(arguments: Vec<String>) -> Result<(serde_json::Value, u8), CliError> {
    let mut arguments = arguments;
    let mut no_yolo = false;
    while arguments
        .first()
        .is_some_and(|argument| argument.starts_with('-'))
    {
        match arguments.remove(0).as_str() {
            "--no-yolo" => no_yolo = true,
            other => return Err(usage(format!("unknown option: {other}"))),
        }
    }
    if no_yolo {
        persist_no_yolo(true).map_err(|error| protocol("protocol_error", error))?;
    }
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(usage(
            "usage: praefectus [--no-yolo] execute|status|capabilities|surfaces|observe|observe-surface|allow-global-input",
        ));
    };
    let self_authorize = command == "execute"
        && arguments
            .iter()
            .any(|argument| argument == "--self-authorize-no-host-boundary");
    let arguments: Vec<String> = arguments
        .iter()
        .filter(|argument| command != "execute" || *argument != "--self-authorize-no-host-boundary")
        .cloned()
        .collect();
    let (ledger, positional, parsed_no_yolo) = parse_arguments(&arguments)?;
    if parsed_no_yolo {
        persist_no_yolo(true).map_err(|error| protocol("protocol_error", error))?;
    }
    match command {
        "execute" => run_execute(positional, ledger, self_authorize),
        "status" => run_status(positional, ledger),
        "capabilities" => run_capabilities(positional, ledger),
        "observe" => run_observe(positional),
        "surfaces" => run_surfaces(positional),
        "observe-surface" => run_observe_surface(positional),
        "allow-global-input" => run_allow_global_input(positional),
        _ => Err(usage(format!("unknown command: {command}"))),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteInput {
    observation: SemanticObservation,
    tag: String,
    action: Action,
    verification: Option<VerificationPolicy>,
    interaction_mode: Option<InteractionMode>,
}

fn run_execute(
    positional: Vec<&str>,
    ledger: PathBuf,
    self_authorize: bool,
) -> Result<(serde_json::Value, u8), CliError> {
    if !self_authorize || !positional.is_empty() {
        return Err(usage(
            "execute requires --self-authorize-no-host-boundary and JSON on stdin",
        ));
    }
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(3 * 1024 * 1024 + 1)
        .read_to_end(&mut input)
        .map_err(|error| protocol("protocol_error", error))?;
    if input.len() > 3 * 1024 * 1024 {
        return Err(usage("execute input is too large"));
    }
    let input: ExecuteInput = serde_json::from_slice(&input)
        .map_err(|_| usage("execute requires a valid action and fenced observation"))?;
    execute_input(input, ledger, NativeExecutor::default())
}

fn execute_input<E: praefectus::Executor + 'static>(
    input: ExecuteInput,
    ledger: PathBuf,
    executor: E,
) -> Result<(serde_json::Value, u8), CliError> {
    if !matches!(
        input.action,
        Action::Invoke
            | Action::SetValue { .. }
            | Action::TypeText { .. }
            | Action::Press { .. }
            | Action::Click { .. }
            | Action::Hotkey { .. }
            | Action::Paste { .. }
            | Action::Move
            | Action::Scroll { .. }
            | Action::SelectText { .. }
            | Action::PerformSecondaryAction { .. }
    ) {
        return Err(usage("unsupported execute action"));
    }
    let now = now_ms();
    input
        .observation
        .validate(now)
        .map_err(|error| protocol("observation_error", error))?;
    let target = input
        .observation
        .target(&input.tag)
        .map_err(|error| protocol("observation_error", error))?;
    input
        .observation
        .resolve(&target, now)
        .map_err(|error| protocol("observation_error", error))?;
    let deadline = now
        .saturating_add(20_000)
        .min(input.observation.expires_at_ms);
    let verification = match (&input.action, input.verification) {
        (Action::SetValue { value }, None) => VerificationPolicy::TargetValueHash {
            sha256: hex::encode(Sha256::digest(value.as_bytes())),
        },
        (_, verification) => verification.unwrap_or(VerificationPolicy::None),
    };
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|error| protocol("protocol_error", error))?;
    let key = SigningKey::from_bytes(&seed);
    let operation_id = format!("cli-{}", hex::encode(&key.verifying_key().to_bytes()[..16]));
    let mut request = ActionRequest {
        protocol_version: PROTOCOL_VERSION,
        action_version: PROTOCOL_VERSION,
        target_version: PROTOCOL_VERSION,
        verification_version: PROTOCOL_VERSION,
        operation_id: operation_id.clone(),
        subject: "cli-user".into(),
        session_id: "cli-session".into(),
        authority: SignedAuthority {
            grant: AuthorityGrant {
                protocol_version: PROTOCOL_VERSION,
                issuer: "self-authorized-cli".into(),
                key_id: "ephemeral".into(),
                operation_id,
                subject: "cli-user".into(),
                session_id: "cli-session".into(),
                risk: SafetyClass::External,
                expires_at_ms: deadline,
                policy_generation: "cli-v1".into(),
                action_hash: String::new(),
            },
            signature: String::new(),
        },
        action: input.action,
        target: TargetRef::Element { target },
        interaction_mode: input
            .interaction_mode
            .unwrap_or(InteractionMode::Interactive),
        deadline_at_ms: deadline,
        verification,
        safety: SafetyClass::External,
    };
    request.authority.grant.action_hash =
        normalized_action_hash(&request).map_err(|error| protocol("protocol_error", error))?;
    request.authority.signature = hex::encode(
        key.sign(
            &canonical_authority_bytes(&request.authority.grant)
                .map_err(|error| protocol("protocol_error", error))?,
        )
        .to_bytes(),
    );
    let authority = Ed25519AuthorityVerifier::new([(
        "self-authorized-cli".into(),
        "ephemeral".into(),
        "cli-v1".into(),
        key.verifying_key(),
    )])
    .map_err(|error| protocol("protocol_error", error))?;
    let report = Engine::new(executor, ledger, authority)
        .execute(&request, &CancellationToken::default())
        .map_err(|error| protocol("protocol_error", error))?;
    let succeeded = matches!(report.acknowledgements.last().map(|ack| &ack.state),
        Some(AckState::Terminal { terminal }) if matches!(terminal.as_ref(), Terminal::Succeeded { .. }));
    let report = serialize(report)?;
    if succeeded {
        Ok((report, 0))
    } else {
        Err(CliError {
            code: "execution_failed",
            message: "action did not succeed; reconcile before retrying".into(),
            exit: EXIT_PROTOCOL,
            report: Some(report),
            #[cfg(test)]
            diagnostic: None,
        })
    }
}

fn run_status(positional: Vec<&str>, ledger: PathBuf) -> Result<(serde_json::Value, u8), CliError> {
    let operation_id = match positional.as_slice() {
        [operation_id] => operation_id,
        [] => return Err(usage("status requires an operation ID")),
        _ => return Err(usage("status accepts exactly one operation ID")),
    };
    let engine = Engine::new(NativeExecutor::default(), ledger, DenyAuthority);
    Ok((
        serialize(
            engine
                .status(operation_id)
                .map_err(|error| protocol("protocol_error", error))?,
        )?,
        0,
    ))
}

fn run_capabilities(
    positional: Vec<&str>,
    ledger: PathBuf,
) -> Result<(serde_json::Value, u8), CliError> {
    if !positional.is_empty() {
        return Err(usage("capabilities does not accept positional arguments"));
    }
    let engine = Engine::new(NativeExecutor::default(), ledger, DenyAuthority);
    Ok((
        serialize(
            engine
                .capabilities()
                .map_err(|error| protocol("protocol_error", error))?,
        )?,
        0,
    ))
}

fn run_observe(positional: Vec<&str>) -> Result<(serde_json::Value, u8), CliError> {
    if !positional.is_empty() {
        return Err(usage("observe does not accept positional arguments"));
    }
    let executor = NativeExecutor::default();
    Ok((
        serialize(
            executor
                .observe_semantic(
                    &CancellationToken::default(),
                    now_ms().saturating_add(30_000),
                )
                .map_err(|error| protocol("observation_error", error))?,
        )?,
        0,
    ))
}

fn run_surfaces(positional: Vec<&str>) -> Result<(serde_json::Value, u8), CliError> {
    if !positional.is_empty() {
        return Err(usage("surfaces does not accept positional arguments"));
    }
    let executor = NativeExecutor::default();
    Ok((
        serialize(
            executor
                .list_surfaces(
                    &CancellationToken::default(),
                    now_ms().saturating_add(30_000),
                )
                .map_err(|error| protocol("observation_error", error))?,
        )?,
        0,
    ))
}

fn run_observe_surface(positional: Vec<&str>) -> Result<(serde_json::Value, u8), CliError> {
    let surface_id = match positional.as_slice() {
        [surface_id] => surface_id,
        [] => return Err(usage("observe-surface requires a surface ID")),
        _ => return Err(usage("observe-surface accepts exactly one surface ID")),
    };
    let executor = NativeExecutor::default();
    Ok((
        serialize(
            executor
                .observe_surface(
                    &SurfaceRef {
                        id: (*surface_id).to_string(),
                    },
                    &CancellationToken::default(),
                    now_ms().saturating_add(30_000),
                )
                .map_err(|error| protocol("observation_error", error))?,
        )?,
        0,
    ))
}

fn run_allow_global_input(positional: Vec<&str>) -> Result<(serde_json::Value, u8), CliError> {
    match positional.as_slice() {
        [] => Ok((serialize(global_input_allowance())?, 0)),
        ["allow"] => Ok((
            serialize(persist_no_yolo(false).map_err(|error| protocol("protocol_error", error))?)?,
            0,
        )),
        ["deny"] | ["--no-yolo"] => Ok((
            serialize(persist_no_yolo(true).map_err(|error| protocol("protocol_error", error))?)?,
            0,
        )),
        _ => Err(usage(
            "allow-global-input accepts no arguments, allow, deny, or --no-yolo",
        )),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

fn serialize(value: impl Serialize) -> Result<serde_json::Value, CliError> {
    serde_json::to_value(value).map_err(|error| protocol("serialization_error", error))
}

fn parse_arguments(arguments: &[String]) -> Result<(PathBuf, Vec<&str>, bool), CliError> {
    let mut values = Vec::new();
    let mut ledger = None;
    let mut no_yolo = false;
    let mut index = 1;
    while index < arguments.len() {
        if arguments[index] == "--ledger" {
            if ledger.is_some() {
                return Err(usage("--ledger may only be specified once"));
            }
            let path = arguments
                .get(index + 1)
                .filter(|path| !path.starts_with('-'))
                .ok_or_else(|| usage("--ledger requires a path"))?;
            ledger = Some(PathBuf::from(path));
            index += 2;
        } else if arguments[index] == "--no-yolo" {
            no_yolo = true;
            index += 1;
        } else if arguments[index].starts_with('-') {
            return Err(usage(format!("unknown option: {}", arguments[index])));
        } else {
            values.push(arguments[index].as_str());
            index += 1;
        }
    }
    Ok((ledger.unwrap_or_else(default_ledger_path), values, no_yolo))
}

fn usage(message: impl Into<String>) -> CliError {
    CliError {
        code: "usage",
        message: message.into(),
        exit: EXIT_USAGE,
        report: None,
        #[cfg(test)]
        diagnostic: None,
    }
}

fn protocol(code: &'static str, _error: impl ToString) -> CliError {
    CliError {
        code,
        message: "protocol operation failed".to_string(),
        exit: EXIT_PROTOCOL,
        report: None,
        #[cfg(test)]
        diagnostic: Some(_error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use praefectus::semantic::{
        Actionability, SemanticBackend, SemanticElement, SemanticProvenance,
    };
    use praefectus::{
        ActionCapability, BackgroundSupport, Capabilities, DeliveryRoute, DispatchError,
        DispatchReceipt, Evidence, Observation, ProtocolError, ResolvedTarget, SessionIsolation,
    };

    struct TestExecutor {
        expected: praefectus::semantic::SemanticTargetRef,
    }

    impl praefectus::Executor for TestExecutor {
        fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
            Ok(Capabilities {
                platform: "test".into(),
                backend: "test".into(),
                session_isolation: SessionIsolation::SharedDesktop,
                supported_actions: vec!["invoke".into()],
                action_capabilities: vec![ActionCapability {
                    action: "invoke".into(),
                    delivery_route: DeliveryRoute::TargetAddressed,
                    background_support: BackgroundSupport::Guarded,
                }],
                permissions: Default::default(),
                display_geometry_hash: "c".repeat(64),
            })
        }

        fn observe(&self, _: &TargetRef) -> Result<Observation, ProtocolError> {
            Ok(Observation {
                evidence: Evidence {
                    observation_hash: "same".into(),
                    target_fingerprint_hash: Some(self.expected.fingerprint_hash.clone()),
                    display_geometry_hash: "c".repeat(64),
                    observed_at_ms: now_ms(),
                },
                element: None,
                state: serde_json::json!({}),
            })
        }

        fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, ProtocolError> {
            if matches!(target, TargetRef::Element { target } if *target == self.expected) {
                Ok(ResolvedTarget::None)
            } else {
                Err(ProtocolError::StaleTarget("target changed".into()))
            }
        }

        fn dispatch(
            &self,
            _: &Action,
            _: &ResolvedTarget,
            _: &VerificationPolicy,
            _: &CancellationToken,
            _: i64,
        ) -> Result<DispatchReceipt, DispatchError> {
            Ok(DispatchReceipt {
                backend: "test".into(),
                fallback_chain: vec![],
            })
        }
    }

    fn observation() -> SemanticObservation {
        let now = now_ms();
        SemanticObservation {
            protocol_version: PROTOCOL_VERSION,
            observation_id: "a".repeat(64),
            generation: 1,
            provenance: SemanticProvenance {
                backend: SemanticBackend::Accessibility,
                backend_name: "test".into(),
                process_id: 42,
                process_generation: "generation".into(),
                window_id: "window".into(),
                document_id: None,
                display_geometry_hash: "c".repeat(64),
                host_opt_ins: vec![],
            },
            observed_at_ms: now - 1,
            expires_at_ms: now + 20_000,
            truncated: false,
            elements: vec![SemanticElement {
                tag: "e1".into(),
                element_id: "b".repeat(64),
                parent_id: None,
                fingerprint_hash: "d".repeat(64),
                role: "button".into(),
                name: None,
                bounds: None,
                actionability: Actionability {
                    visible: true,
                    enabled: true,
                    unambiguous: true,
                    stable: true,
                    receives_events: true,
                    invokable: true,
                    editable: false,
                },
            }],
        }
    }

    fn input(observation: SemanticObservation, verification: VerificationPolicy) -> ExecuteInput {
        ExecuteInput {
            observation,
            tag: "e1".into(),
            action: Action::Invoke,
            verification: Some(verification),
            interaction_mode: None,
        }
    }

    #[test]
    fn signed_execution_reports_verification_failure_and_rejects_changed_fence() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        {
            let output = std::process::Command::new("icacls.exe")
                .arg(directory.path())
                .output()
                .unwrap();
            assert!(output.status.success(), "ACL diagnostic failed");
            let text = String::from_utf8_lossy(&output.stdout);
            let path = directory.path().to_string_lossy();
            let mut count = 0;
            for line in text.lines() {
                let ace = line.strip_prefix(path.as_ref()).unwrap_or(line).trim();
                if ace.contains(":(") {
                    eprintln!("ACE: {ace}");
                    count += 1;
                }
            }
            assert!(count > 0, "ACL diagnostic returned no ACEs");
        }
        let observation = observation();
        let expected = observation.target("e1").unwrap();
        let (success, exit) = execute_input(
            input(observation.clone(), VerificationPolicy::None),
            directory.path().join("success"),
            TestExecutor {
                expected: expected.clone(),
            },
        )
        .unwrap();
        assert_eq!(exit, 0);
        assert_eq!(
            success["acknowledgements"][2]["state"]["terminal"]["kind"],
            "succeeded"
        );
        let error = execute_input(
            input(observation.clone(), VerificationPolicy::SnapshotChanged),
            directory.path().join("first"),
            TestExecutor {
                expected: expected.clone(),
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.exit, 3);
        let envelope = serde_json::to_value(ErrorEnvelope::new(&error)).unwrap();
        assert_eq!(envelope["ok"], false);
        let terminal = &envelope["error"]["report"]["acknowledgements"][2]["state"]["terminal"];
        assert_eq!(terminal["kind"], "outcome_unknown");
        assert_eq!(terminal["receipt"]["effect"], "executed_unverified");
        assert_eq!(terminal["receipt"]["delivery_route"], "target_addressed");

        let mut changed = observation.clone();
        changed.elements[0].fingerprint_hash = "e".repeat(64);
        let error = execute_input(
            input(changed, VerificationPolicy::None),
            directory.path().join("second"),
            TestExecutor {
                expected: expected.clone(),
            },
        )
        .err()
        .unwrap();
        let report = error.report.unwrap();
        let terminal = &report["acknowledgements"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["state"]["terminal"];
        assert_eq!(terminal["kind"], "rejected");
        assert_eq!(terminal["code"], "stale_target");

        let mut stale = observation;
        stale.expires_at_ms = now_ms() - 1;
        stale.observed_at_ms = stale.expires_at_ms - 1_000;
        let error = execute_input(
            input(stale, VerificationPolicy::None),
            directory.path().join("third"),
            TestExecutor { expected },
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "observation_error");
        assert!(error.report.is_none());
    }

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_arguments_empty() {
        let arguments = args(&["command"]);
        let (ledger, values, no_yolo) = parse_arguments(&arguments).ok().unwrap();
        assert_eq!(ledger, default_ledger_path());
        assert!(values.is_empty());
        assert!(!no_yolo);
    }

    #[test]
    fn parse_arguments_positional() {
        let arguments = args(&["command", "value1", "value2"]);
        let (ledger, values, no_yolo) = parse_arguments(&arguments).ok().unwrap();
        assert_eq!(ledger, default_ledger_path());
        assert_eq!(values, vec!["value1", "value2"]);
        assert!(!no_yolo);
    }

    #[test]
    fn parse_arguments_ledger() {
        let arguments = args(&["command", "--ledger", "custom/path.json"]);
        let (ledger, values, no_yolo) = parse_arguments(&arguments).ok().unwrap();
        assert_eq!(ledger, PathBuf::from("custom/path.json"));
        assert!(values.is_empty());
        assert!(!no_yolo);
    }

    #[test]
    fn parse_arguments_mixed() {
        let arguments = args(&[
            "command",
            "value1",
            "--ledger",
            "custom/path.json",
            "value2",
        ]);
        let (ledger, values, no_yolo) = parse_arguments(&arguments).ok().unwrap();
        assert_eq!(ledger, PathBuf::from("custom/path.json"));
        assert_eq!(values, vec!["value1", "value2"]);
        assert!(!no_yolo);
    }

    #[test]
    fn parse_arguments_ledger_missing_path() {
        let arguments = args(&["command", "--ledger"]);
        let err = parse_arguments(&arguments).err().unwrap();
        assert_eq!(err.message, "--ledger requires a path");
    }

    #[test]
    fn parse_arguments_ledger_dash_path() {
        let arguments = args(&["command", "--ledger", "--other"]);
        let err = parse_arguments(&arguments).err().unwrap();
        assert_eq!(err.message, "--ledger requires a path");
    }

    #[test]
    fn parse_arguments_multiple_ledgers() {
        let arguments = args(&[
            "command",
            "--ledger",
            "path1.json",
            "--ledger",
            "path2.json",
        ]);
        let err = parse_arguments(&arguments).err().unwrap();
        assert_eq!(err.message, "--ledger may only be specified once");
    }

    #[test]
    fn parse_arguments_unknown_option() {
        let arguments = args(&["command", "--unknown"]);
        let err = parse_arguments(&arguments).err().unwrap();
        assert_eq!(err.message, "unknown option: --unknown");
    }

    #[test]
    fn parse_arguments_accepts_no_yolo() {
        let arguments = args(&["capabilities", "--no-yolo"]);
        let (_, values, no_yolo) = parse_arguments(&arguments).ok().unwrap();
        assert!(values.is_empty());
        assert!(no_yolo);
    }
}
