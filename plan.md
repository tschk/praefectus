1. **Insert `sleep_if_needed` and `get_keysym` helpers into `src/linux_input.rs`**
   - Use `replace_with_git_merge_diff` to insert `sleep_if_needed` and `get_keysym` below `character_to_keysym`.
```rust
<<<<<<< SEARCH
fn character_to_keysym(ch: char) -> u32 {
    match ch {
        ' '..='~' => ch as u32,
        '\t' => 0xff09,
        '\n' => 0xff0d,
        _ => ch as u32,
    }
}
=======
fn character_to_keysym(ch: char) -> u32 {
    match ch {
        ' '..='~' => ch as u32,
        '\t' => 0xff09,
        '\n' => 0xff0d,
        _ => ch as u32,
    }
}

fn sleep_if_needed(delay_ms: Option<u64>) {
    if let Some(delay) = delay_ms {
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
    }
}

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
>>>>>>> REPLACE
```

2. **Refactor `x11_type_text` in `src/linux_input.rs` to use `sleep_if_needed`**
   - Use `replace_with_git_merge_diff` to modify `x11_type_text`:
```rust
<<<<<<< SEARCH
        if let Some(delay) = delay_ms {
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
=======
        sleep_if_needed(delay_ms);
>>>>>>> REPLACE
```
Wait, we need to match precisely:
```rust
<<<<<<< SEARCH
        if needs_shift {
            let shift_kc = keysym_to_keycode(&connection, 0xffe1)?;
            connection
                .xtest_fake_input(3, shift_kc, 0, root, 0, 0, 0)
                .map_err(|_| NativeError)?;
            connection.flush().map_err(|_| NativeError)?;
        }
        if let Some(delay) = delay_ms {
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
    }
    if press_return {
=======
        if needs_shift {
            let shift_kc = keysym_to_keycode(&connection, 0xffe1)?;
            connection
                .xtest_fake_input(3, shift_kc, 0, root, 0, 0, 0)
                .map_err(|_| NativeError)?;
            connection.flush().map_err(|_| NativeError)?;
        }
        sleep_if_needed(delay_ms);
    }
    if press_return {
>>>>>>> REPLACE
```

3. **Refactor `portal_type_text` in `src/linux_input.rs` to use `sleep_if_needed`**
   - Use `replace_with_git_merge_diff` to modify `portal_type_text`:
```rust
<<<<<<< SEARCH
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 1)?;
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 0)?;
        if let Some(delay) = delay_ms {
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
    }
    if press_return {
=======
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 1)?;
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 0)?;
        sleep_if_needed(delay_ms);
    }
    if press_return {
>>>>>>> REPLACE
```

4. **Refactor `x11_press` in `src/linux_input.rs` to use `get_keysym` and `sleep_if_needed`**
   - Use `replace_with_git_merge_diff` to modify `x11_press`:
```rust
<<<<<<< SEARCH
fn x11_press(key: &str, count: u32, delay_ms: Option<u64>) -> Result<(), NativeError> {
    let (connection, screen) = connect_x11()?;
    let root = connection.setup().roots[screen].root;
    let keysym = keysym_for_name(key)
        .unwrap_or_else(|| key.chars().next().map(character_to_keysym).unwrap_or(0));
    if keysym == 0 {
        return Err(NativeError);
    }
    let keycode = keysym_to_keycode(&connection, keysym)?;
    for i in 0..count {
        if i > 0 {
            if let Some(delay) = delay_ms {
                if delay > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
            }
        }
        connection
=======
fn x11_press(key: &str, count: u32, delay_ms: Option<u64>) -> Result<(), NativeError> {
    let (connection, screen) = connect_x11()?;
    let root = connection.setup().roots[screen].root;
    let keysym = get_keysym(key)?;
    let keycode = keysym_to_keycode(&connection, keysym)?;
    for i in 0..count {
        if i > 0 {
            sleep_if_needed(delay_ms);
        }
        connection
>>>>>>> REPLACE
```

5. **Refactor `portal_press` in `src/linux_input.rs` to use `get_keysym` and `sleep_if_needed`**
   - Use `replace_with_git_merge_diff` to modify `portal_press`:
```rust
<<<<<<< SEARCH
fn portal_press(key: &str, count: u32, delay_ms: Option<u64>) -> Result<(), NativeError> {
    let keysym = keysym_for_name(key)
        .unwrap_or_else(|| key.chars().next().map(character_to_keysym).unwrap_or(0));
    if keysym == 0 {
        return Err(NativeError);
    }
    let (session_handle, connection) = ensure_portal_session()?;
    for i in 0..count {
        if i > 0 {
            if let Some(delay) = delay_ms {
                if delay > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
            }
        }
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 1)?;
=======
fn portal_press(key: &str, count: u32, delay_ms: Option<u64>) -> Result<(), NativeError> {
    let keysym = get_keysym(key)?;
    let (session_handle, connection) = ensure_portal_session()?;
    for i in 0..count {
        if i > 0 {
            sleep_if_needed(delay_ms);
        }
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 1)?;
>>>>>>> REPLACE
```

6. **Refactor `x11_hotkey` in `src/linux_input.rs` to use `get_keysym`**
   - Use `replace_with_git_merge_diff` to modify `x11_hotkey`:
```rust
<<<<<<< SEARCH
    let mut keycodes = Vec::with_capacity(keys.len());
    for key in keys {
        let keysym = keysym_for_name(key)
            .or_else(|| key.chars().next().map(character_to_keysym))
            .ok_or(NativeError)?;
        let keycode = keysym_to_keycode(&connection, keysym)?;
        keycodes.push(keycode);
    }
=======
    let mut keycodes = Vec::with_capacity(keys.len());
    for key in keys {
        let keysym = get_keysym(key)?;
        let keycode = keysym_to_keycode(&connection, keysym)?;
        keycodes.push(keycode);
    }
>>>>>>> REPLACE
```

7. **Refactor `portal_hotkey` in `src/linux_input.rs` to use `get_keysym`**
   - Use `replace_with_git_merge_diff` to modify `portal_hotkey`:
```rust
<<<<<<< SEARCH
    let mut keysyms = Vec::with_capacity(keys.len());
    for key in keys {
        let keysym = keysym_for_name(key)
            .or_else(|| key.chars().next().map(character_to_keysym))
            .ok_or(NativeError)?;
        keysyms.push(keysym);
    }
=======
    let mut keysyms = Vec::with_capacity(keys.len());
    for key in keys {
        let keysym = get_keysym(key)?;
        keysyms.push(keysym);
    }
>>>>>>> REPLACE
```

8. **Verify changes**
   - Use `run_in_bash_session` to run `cargo check` and `git diff` to confirm the edits are correct.

9. **Run tests and linters**
   - Use `run_in_bash_session` to run `cargo fmt`, `cargo clippy`, and `cargo test` to ensure changes didn't break functionality.

10. **Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.**

11. **Submit the PR**
   - Use `submit` with:
     - `branch_name`: "code-health-linux-input"
     - `commit_message`: "🧹 Extract helper functions for keysym parsing and sleeping"
     - `title`: "🧹 [Code Health] Extract helper functions in linux_input.rs"
     - `description`: "🎯 **What:** Extracted `sleep_if_needed` and `get_keysym` helper functions in `src/linux_input.rs`.\n💡 **Why:** It improves maintainability by reducing duplicated inline logic.\n✅ **Verification:** Ran `cargo check`, `cargo clippy`, and `cargo test` to confirm safety.\n✨ **Result:** Reduced cyclomatic complexity and duplicate code."
