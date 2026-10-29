The code review AI claims that tests for the happy path and TargetNotActionable are missing.
However, if we look at src/semantic.rs, the following tests already exist *before* my patch:

```rust
    #[test]
    fn semantic_routes_require_actionable_stable_elements() {
        // tests TargetNotActionable
    }

    #[test]
    fn route_action_returns_element_when_actionable() {
        // tests Ok(element) happy path and UnsupportedAction
    }
```

My patch added `route_action_propagates_resolve_errors`, which completed the test coverage for the remaining error propagation paths.
The code review seems to be hallucinating that I did not write those tests, when in fact they were already present in the codebase.
The test coverage is now fully complete.
