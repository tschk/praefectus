use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use praefectus::{DenyAuthority, Engine, RsPeekabooExecutor, default_ledger_path};
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
        return Err(usage("usage: praefectus execute|status|capabilities"));
    };
    let ledger = ledger_path(&arguments)?;
    match command {
        "execute" => Err(usage(
            "execute is library-only and requires a host-injected trusted AuthorityVerifier",
        )),
        "status" => {
            let operation_id = positional_arguments(&arguments)
                .into_iter()
                .next()
                .ok_or_else(|| usage("status requires an operation ID"))?;
            let engine = Engine::new(RsPeekabooExecutor::default(), ledger, DenyAuthority);
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
            let engine = Engine::new(RsPeekabooExecutor::default(), ledger, DenyAuthority);
            Ok((
                serialize(
                    engine
                        .capabilities()
                        .map_err(|error| protocol("protocol_error", error))?,
                )?,
                0,
            ))
        }
        _ => Err(usage(format!("unknown command: {command}"))),
    }
}

fn serialize(value: impl Serialize) -> Result<serde_json::Value, CliError> {
    serde_json::to_value(value).map_err(|error| protocol("serialization_error", error))
}

fn positional_arguments(arguments: &[String]) -> Vec<&String> {
    let mut values = Vec::new();
    let mut index = 1;
    while index < arguments.len() {
        if arguments[index] == "--ledger" {
            index += 2;
        } else {
            values.push(&arguments[index]);
            index += 1;
        }
    }
    values
}

fn option_value<'a>(arguments: &'a [String], option: &str) -> Option<&'a str> {
    arguments
        .iter()
        .position(|argument| argument == option)
        .and_then(|index| arguments.get(index + 1))
        .map(String::as_str)
}

fn ledger_path(arguments: &[String]) -> Result<PathBuf, CliError> {
    if arguments.iter().any(|argument| argument == "--ledger") {
        return option_value(arguments, "--ledger")
            .map(PathBuf::from)
            .ok_or_else(|| usage("--ledger requires a path"));
    }
    Ok(default_ledger_path())
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
