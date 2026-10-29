1. **Define the helper function `sleep_if_needed(delay_ms: Option<u64>)`**
   - Use `replace_with_git_merge_diff` to add the `sleep_if_needed` function just above `native_type_text` in `src/linux_input.rs`:
```
<<<<<<< SEARCH
pub(crate) fn native_type_text(
    text: &str,
    clear: bool,
    press_return: bool,
    delay_ms: Option<u64>,
) -> Result<(), NativeError> {
=======
fn sleep_if_needed(delay_ms: Option<u64>) {
    if let Some(delay) = delay_ms {
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
    }
}

pub(crate) fn native_type_text(
    text: &str,
    clear: bool,
    press_return: bool,
    delay_ms: Option<u64>,
) -> Result<(), NativeError> {
>>>>>>> REPLACE
```

2. **Refactor `x11_type_text` to use `sleep_if_needed`**
   - Use `replace_with_git_merge_diff` in `src/linux_input.rs`:
```
<<<<<<< SEARCH
        if let Some(delay) = delay_ms {
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
    }
    if press_return {
        let return_keysym = 0xff0d;
=======
        sleep_if_needed(delay_ms);
    }
    if press_return {
        let return_keysym = 0xff0d;
>>>>>>> REPLACE
```

3. **Refactor `portal_type_text` to use `sleep_if_needed`**
   - Use `replace_with_git_merge_diff` in `src/linux_input.rs`:
```
<<<<<<< SEARCH
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 0)?;
        if let Some(delay) = delay_ms {
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }
    }
    if press_return {
        portal_notify_keyboard_keysym(&connection, &session_handle, 0xff0d, 1)?;
=======
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 0)?;
        sleep_if_needed(delay_ms);
    }
    if press_return {
        portal_notify_keyboard_keysym(&connection, &session_handle, 0xff0d, 1)?;
>>>>>>> REPLACE
```

4. **Refactor `x11_press` to use `sleep_if_needed`**
   - Use `replace_with_git_merge_diff` in `src/linux_input.rs`:
```
<<<<<<< SEARCH
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
            .xtest_fake_input(2, keycode, 0, root, 0, 0, 0)
=======
    let keycode = keysym_to_keycode(&connection, keysym)?;
    for i in 0..count {
        if i > 0 {
            sleep_if_needed(delay_ms);
        }
        connection
            .xtest_fake_input(2, keycode, 0, root, 0, 0, 0)
>>>>>>> REPLACE
```

5. **Refactor `portal_press` to use `sleep_if_needed`**
   - Use `replace_with_git_merge_diff` in `src/linux_input.rs`:
```
<<<<<<< SEARCH
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
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 0)?;
    }
=======
    let (session_handle, connection) = ensure_portal_session()?;
    for i in 0..count {
        if i > 0 {
            sleep_if_needed(delay_ms);
        }
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 1)?;
        portal_notify_keyboard_keysym(&connection, &session_handle, keysym, 0)?;
    }
>>>>>>> REPLACE
```

6. **Verify compilation and formatting**
   - Use `run_in_bash_session` to run `cargo fmt --all && cargo clippy && umask 0077 && export RUSTUP_HOME=/home/jules/.rustup && export CARGO_HOME=/home/jules/.cargo && export PATH="/home/jules/.cargo/bin:$PATH" && export HOME=/tmp/isolated_home && mkdir -p $HOME/.local/share/praefectus && cargo test`.

7. **Complete pre-commit steps**
   - Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.

8. **Submit changes**
   - Use `submit` with:
   - title: "🧹 [code health improvement] Refactor delay logic into helper function in linux_input.rs"
   - branch_name: "refactor-linux-input-delay"
   - description: "
🎯 **What:** Extracted repetitive thread sleep logic into a `sleep_if_needed` helper function in `src/linux_input.rs`.
💡 **Why:** Reduces cyclomatic complexity and code duplication in text typing and key press functions (`x11_press`, `portal_press`, `x11_type_text`, `portal_type_text`), making the code more readable and maintainable.
✅ **Verification:** Verified by compiling the project, running clippy lints, and running tests.
✨ **Result:** A more concise and DRY implementation of the delay functionality across linux input methods.
"
