The reviewer says this is not a behavior-neutral extraction. It changes zero-keysym handling.

Original `portal_press`:
```rust
    let keysym = keysym_for_name(key)
        .unwrap_or_else(|| key.chars().next().map(character_to_keysym).unwrap_or(0));
    if keysym == 0 {
        return Err(NativeError);
    }
```
Original `x11_hotkey`:
```rust
    for key in keys {
        let keysym = keysym_for_name(key)
            .or_else(|| key.chars().next().map(character_to_keysym))
            .ok_or(NativeError)?;
```
`ok_or` means if it's `None`, it's an error.
Wait, if `character_to_keysym` returns `0`, `ok_or` doesn't care; it's still `Some(0)`!
Wait!
```rust
fn get_keysym(key: &str) -> Result<u32, NativeError> {
    let keysym = keysym_for_name(key)
        .or_else(|| key.chars().next().map(character_to_keysym))
        .unwrap_or(0);
    if keysym == 0 {
        Err(NativeError)
    } else {
        Ok(keysym)
    }
}
```
In my extracted function, I made `keysym == 0` an error for ALL callers!
Before, `x11_hotkey` and `portal_hotkey` allowed `0` keysyms because they didn't explicitly check `keysym == 0`.
Wait, is `0` a valid keysym in X11? Usually not, but perhaps `character_to_keysym` could return `0` and it was being accepted by `x11_hotkey`.
Actually, if the PR is closed and obsolete, I should just acknowledge.
"Closing as obsolete" or "Closing: this is not a behavior-neutral extraction".
Ah, "Closing: this is not a behavior-neutral extraction; it changes zero-keysym handling without a regression test. Please separate and validate any intended behavior change."

I need to reply acknowledging it.
