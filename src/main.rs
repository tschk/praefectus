use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use praefectus::{
    CancellationToken, DenyAuthority, Engine, NativeExecutor, SurfaceRef, default_ledger_path,
    global_input_allowance, persist_no_yolo,
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
    let (ledger, positional, parsed_no_yolo) = parse_arguments(&arguments)?;
    if parsed_no_yolo {
        persist_no_yolo(true).map_err(|error| protocol("protocol_error", error))?;
    }
    match command {
        "execute" => Err(usage(
            "execute is library-only and requires a host-injected trusted AuthorityVerifier",
        )),
        "status" => run_status(positional, ledger),
        "capabilities" => run_capabilities(positional, ledger),
        "observe" => run_observe(positional),
        "surfaces" => run_surfaces(positional),
        "observe-surface" => run_observe_surface(positional),
        "allow-global-input" => run_allow_global_input(positional),
        _ => Err(usage(format!("unknown command: {command}"))),
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
    }
}

fn protocol(code: &'static str, _error: impl ToString) -> CliError {
    CliError {
        code,
        message: "protocol operation failed".to_string(),
        exit: EXIT_PROTOCOL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
