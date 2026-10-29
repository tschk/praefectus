I have analyzed the code health issue in `src/linux_input.rs:488`.

The issue is "Complex Function", focusing on `portal_press`. It has duplicate/similar logic with other functions. For instance, both `portal_press` and `x11_press` have:
1. Logic to extract the keysym from a string:
```rust
    let keysym = keysym_for_name(key)
        .unwrap_or_else(|| key.chars().next().map(character_to_keysym).unwrap_or(0));
    if keysym == 0 {
        return Err(NativeError);
    }
```
2. Logic to sleep for a given delay conditionally:
```rust
        if i > 0 {
            if let Some(delay) = delay_ms {
                if delay > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
            }
        }
```

Wait, `keysym_for_name` is also called like this in `x11_hotkey` and `portal_hotkey`:
```rust
        let keysym = keysym_for_name(key)
            .or_else(|| key.chars().next().map(character_to_keysym))
            .ok_or(NativeError)?;
```
Wait, this does essentially the same thing, except the `portal_press` has `unwrap_or(0)` and then checks if it's `0`, whereas `portal_hotkey` uses `.ok_or(NativeError)?` which requires it to be non-zero... well wait, `character_to_keysym` can return `0` if a character maps to `0`? Actually no, `character_to_keysym` doesn't seem to return `0` specifically unless the character is 0, but a keysym of `0` is invalid in X11/wayland.

I think the best way to reduce the complexity of `portal_press` (and implicitly `x11_press`, `portal_type_text`, `x11_type_text`) is to extract the conditional sleep into a helper function:
```rust
fn sleep_if_needed(delay_ms: Option<u64>) {
    if let Some(delay) = delay_ms {
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
    }
}
```
Wait, the sleep helper would clean up all those nested `if` statements.

Also we can extract the key string to keysym logic:
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
And replace the duplicated parsing logic in `x11_press` and `portal_press`.

Would this be the right path? I'll request a review.
