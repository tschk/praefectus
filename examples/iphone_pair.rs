//! Explicit one-time USB setup. Never run against a device without its owner's approval.
#[cfg(all(unix, not(target_os = "ios")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("usage: iphone_pair OWNED_USB_DEVICE_UDID NEW_OUTPUT_PLIST".into());
    }
    let udid = args[1].to_str().ok_or("invalid UDID")?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args[2])?;
    eprintln!("Pairing the selected USB device. Approve its Trust prompt if shown.");
    let result = praefectus::iphone::pair_iphone_over_usb(udid);
    match result {
        Ok(bytes) => {
            output.write_all(&bytes)?;
            output.sync_all()?;
        }
        Err(_) => {
            drop(output);
            std::fs::remove_file(&args[2])?;
            return Err("USB pairing failed; no credentials exported".into());
        }
    }
    eprintln!(
        "Device-pinned record saved privately. Transfer securely to the phone, then remove exported copies."
    );
    Ok(())
}

#[cfg(any(not(unix), target_os = "ios"))]
fn main() {
    eprintln!("One-time USB setup requires a trusted macOS or Linux host.");
    std::process::exit(2);
}
