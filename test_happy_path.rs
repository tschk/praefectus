#[test]
fn test_list_windows_success() {
    let executor = NativeExecutor::default();
    let token = CancellationToken::default();
    // Use an unexpired token with plenty of time
    let result = executor.list_windows(&token, i64::MAX);

    match result {
        Ok(value) => {
            // It should be successfully serialized to a JSON array (or potentially an Executor error if backend fails)
            assert!(value.is_array());
        },
        Err(e) => {
            // Depending on the CI environment (e.g. headless linux without desktop environment),
            // the desktop backend might legitimately return an Executor error for no surfaces.
            // We ensure it didn't fail due to boundary conditions.
            assert!(matches!(e, super::ProtocolError::Executor(_)));
        }
    }
}
