1. **Analyze the `MouseButton` enum**: It is defined as `enum MouseButton { Left, Right, Middle }`.
2. **Examine the target match block**:
    ```rust
    match button {
        MouseButton::Left => "left",
        MouseButton::Right => "right",
        MouseButton::Middle => "middle",
    }
    ```
    This logic maps `MouseButton` to a `&'static str`.
3. **Plan the refactoring**:
    * Implement an `as_str()` method for the `MouseButton` enum to encapsulate this logic. This will simplify the code at `src/lib.rs:6190` and improve reuse.
    * Modify `src/lib.rs` to implement `as_str()` for `MouseButton`.
    * Replace the match block at `src/lib.rs:6190` with `button.as_str()`.
4. **Pre commit step**: Ensure code formats correctly and passes tests by running `cargo check`, `cargo fmt`, `cargo test`.
