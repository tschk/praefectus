//! Explicitly approved, fixed-content TextEdit demo; never a general execution bridge.
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use praefectus::{
    AckState, Action, ActionRequest, AuthorityGrant, CancellationToken, Ed25519AuthorityVerifier,
    Effect, Engine, InteractionMode, NativeExecutor, PROTOCOL_VERSION, SafetyClass,
    SignedAuthority, SurfaceRef, TargetRef, Terminal, VerificationPolicy,
    canonical_authority_bytes, normalized_action_hash,
};
use sha2::{Digest, Sha256};

const WINDOW: &str = "Tofu Praefectus Demo.txt";
const NOTE: &str = "KL / haze story research\nJournalist briefing - 15 October 2026\n\nSingapore: the Kalimantan connection\nMSS reported on 14 October that dense smoke from Kalimantan fires was drifting towards Singapore on southeasterly winds. Smoke was also present over Sumatra.\nhttps://www.weather.gov.sg/haze-situation-update-14-october-2026/\n\nMalaysia: regional evidence, local questions\nNEA’s regional update on 15 October describes smoke over Peninsular Malaysia, Kalimantan and Sumatra. It does not establish a current reading or exact smoke source for a particular KL neighbourhood.\nhttps://www.nea.gov.sg/corporate-functions/weather/regional-haze-situation\n\nReporting leads\nCheck Malaysia’s APIMS for current local readings, ask the relevant agencies about transport pathways, and seek comment from KL residents. These are suggested follow-ups, not interviews already conducted.\nhttps://apims.doe.gov.my/\n\nDated research, not a live air-quality monitor. Sources read by the host in a real browser. Written into TextEdit through Praefectus with signed authority and value-hash verification.\n";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.first().map(String::as_str) != Some("--approved-demo") || arguments.len() > 2 {
        return Err("usage: cargo run --example tofu_textedit_demo -- --approved-demo; foreground the disposable TextEdit document 'Tofu Praefectus Demo.txt' first; its contents will be replaced".into());
    }
    let cancellation = CancellationToken::default();
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let deadline = now + 20_000;
    let executor = NativeExecutor::default();
    let observation = if let Some(id) = arguments.get(1) {
        executor.observe_surface(&SurfaceRef { id: id.clone() }, &cancellation, deadline)?
    } else {
        executor.observe_semantic(&cancellation, deadline)?
    };
    let process = std::process::Command::new("/bin/ps")
        .args([
            "-p",
            &observation.provenance.process_id.to_string(),
            "-o",
            "comm=",
        ])
        .output()?;
    let executable = String::from_utf8(process.stdout)?;
    if !process.status.success() || !executable.trim().ends_with("/TextEdit") {
        return Err("refusing: selected app must be TextEdit".into());
    }
    if !observation
        .elements
        .iter()
        .any(|element| element.name.as_deref() == Some(WINDOW))
    {
        return Err(
            "refusing: selected window must be named exactly 'Tofu Praefectus Demo.txt'".into(),
        );
    }
    let editable: Vec<_> = observation
        .elements
        .iter()
        .filter(|element| {
            element.actionability.editable
                && element.actionability.enabled
                && element.actionability.visible
        })
        .collect();
    if editable.len() != 1 {
        return Err("refusing: expected exactly one visible editable element".into());
    }
    let target = observation.target(&editable[0].tag)?;
    let mut seed = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let key = SigningKey::from_bytes(&seed);
    let mut request = ActionRequest {
        protocol_version: PROTOCOL_VERSION,
        action_version: PROTOCOL_VERSION,
        target_version: PROTOCOL_VERSION,
        verification_version: PROTOCOL_VERSION,
        operation_id: format!("tofu-demo-{now}"),
        subject: "tofu-demo-user".into(),
        session_id: "tofu-demo-session".into(),
        authority: SignedAuthority {
            grant: AuthorityGrant {
                protocol_version: PROTOCOL_VERSION,
                issuer: "tofu-demo-host".into(),
                key_id: "ephemeral".into(),
                operation_id: format!("tofu-demo-{now}"),
                subject: "tofu-demo-user".into(),
                session_id: "tofu-demo-session".into(),
                risk: SafetyClass::Reversible,
                expires_at_ms: deadline,
                policy_generation: "fixed-demo-v1".into(),
                action_hash: String::new(),
            },
            signature: String::new(),
        },
        action: Action::SetValue { value: NOTE.into() },
        target: TargetRef::Element { target },
        interaction_mode: InteractionMode::Interactive,
        deadline_at_ms: deadline,
        verification: VerificationPolicy::TargetValueHash {
            sha256: hex::encode(Sha256::digest(NOTE.as_bytes())),
        },
        safety: SafetyClass::Reversible,
    };
    request.authority.grant.action_hash = normalized_action_hash(&request)?;
    request.authority.signature = hex::encode(
        key.sign(&canonical_authority_bytes(&request.authority.grant)?)
            .to_bytes(),
    );
    let authority = Ed25519AuthorityVerifier::new([(
        "tofu-demo-host".into(),
        "ephemeral".into(),
        "fixed-demo-v1".into(),
        key.verifying_key(),
    )])?;
    // The caller owns this one-shot approval; private state never becomes a model parameter.
    let ledger = praefectus::default_ledger_path().with_file_name("tofu-demo-operations.jsonl");
    let engine = Engine::new(executor, ledger, authority);
    let reports = engine.execute_batch(&[request], &cancellation);
    let report = reports.into_iter().next().ok_or("no action attempted")??;
    let verified = matches!(report.acknowledgements.last().map(|ack| &ack.state),
        Some(AckState::Terminal { terminal }) if matches!(terminal.as_ref(),
            Terminal::Succeeded { receipt } if receipt.effect == Effect::Verified));
    println!("{}", serde_json::to_string(&report)?);
    if !verified {
        return Err("demo did not produce a verified success; reconcile before retrying".into());
    }
    Ok(())
}
