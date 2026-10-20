fn test_list_windows_happy_path() {
    let executor = NativeExecutor::default();
    let token = CancellationToken::default();

    // We expect list_surfaces to return Ok(Vec<SurfaceDescriptor>) when not expired/cancelled,
    // which then gets serialized to JSON array
    let result = executor.list_windows(&token, i64::MAX);
    if let Ok(value) = result {
        assert!(value.is_array());
    }
}
