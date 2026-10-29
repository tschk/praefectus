import re

with open('src/linux_input.rs', 'r') as f:
    content = f.read()

sleep_helper = """fn sleep_if_needed(delay_ms: Option<u64>) {
    if let Some(delay) = delay_ms {
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
    }
}
"""

get_keysym_helper = """fn get_keysym(key: &str) -> Result<u32, NativeError> {
    let keysym = keysym_for_name(key)
        .unwrap_or_else(|| key.chars().next().map(character_to_keysym).unwrap_or(0));
    if keysym == 0 {
        Err(NativeError)
    } else {
        Ok(keysym)
    }
}
"""
