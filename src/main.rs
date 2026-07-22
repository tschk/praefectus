use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use praefectus::{
    CancellationToken, DenyAuthority, Engine, NativeExecutor, SurfaceRef, default_ledger_path,
};
use serde::Serialize;

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
}

impl<'a> From<&'a CliError> for ErrorBody<'a> {
    fn from(error: &'a CliError) -> Self {
        Self {
            code: error.code,
            message: &error.message,
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
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(usage(
            "usage: praefectus execute|status|capabilities|surfaces|observe|observe-surface",
        ));
    };
    let (ledger, positional) = parse_arguments(&arguments)?;
    match command {
        "execute" => Err(usage(
            "execute is library-only and requires a host-injected trusted AuthorityVerifier",
        )),
        "status" => {
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
        "capabilities" => {
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
        "observe" => {
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
        "surfaces" => {
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
        "observe-surface" => {
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
        _ => Err(usage(format!("unknown command: {command}"))),
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

fn parse_arguments(arguments: &[String]) -> Result<(PathBuf, Vec<&str>), CliError> {
    let mut values = Vec::new();
    let mut ledger = None;
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
        } else if arguments[index].starts_with('-') {
            return Err(usage(format!("unknown option: {}", arguments[index])));
        } else {
            values.push(arguments[index].as_str());
            index += 1;
        }
    }
    Ok((ledger.unwrap_or_else(default_ledger_path), values))
}

fn usage(message: impl Into<String>) -> CliError {
    CliError {
        code: "usage",
        message: message.into(),
        exit: EXIT_USAGE,
    }
}

fn protocol(code: &'static str, _error: impl ToString) -> CliError {
    CliError {
        code,
        message: "protocol operation failed".to_string(),
        exit: EXIT_PROTOCOL,
    }
}
