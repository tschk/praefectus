use praefectus::{DenyAuthority, Engine, NativeExecutor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let ledger = directory.path().join("operations.jsonl");
    let engine = Engine::new(NativeExecutor::default(), ledger, DenyAuthority);
    let capabilities = engine.capabilities()?;
    println!("platform={}", capabilities.platform);
    println!("backend={}", capabilities.backend);
    println!("session_isolation={:?}", capabilities.session_isolation);
    println!("supported_actions={:?}", capabilities.supported_actions);
    match engine.status("example-missing-operation")? {
        Some(acknowledgement) => println!("status={}", acknowledgement.operation_id),
        None => println!("status=none"),
    }
    Ok(())
}
