//! One legacy USB observation through the real library; metadata only, no image output.
#[cfg(all(unix, not(target_os = "ios")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use praefectus::{CancellationToken, iphone::observe_iphone_over_usb};
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("usage: iphone_observe_usb OWNED_USB_DEVICE_UDID".into());
    }
    let udid = args[1].to_str().ok_or("invalid USB device selection")?;
    let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64 + 15_000;
    let screen = observe_iphone_over_usb(udid, &CancellationToken::default(), deadline)?;
    // Independently decode the returned image in memory, not just its PNG header.
    let mut reader = png::Decoder::new(Cursor::new(screen.png())).read_info()?;
    let mut pixels = vec![0; reader.output_buffer_size().ok_or("invalid image size")?];
    let info = reader.next_frame(&mut pixels)?;
    let display = &screen.coordinates().displays[0];
    if i64::from(info.width) != display.width
        || i64::from(info.height) != display.height
        || info.buffer_size() == 0
        || screen.coordinates().snapshot_content_hash.len() != 64
    {
        return Err("observation verification failed".into());
    }
    screen.target(display.width - 1, display.height - 1)?;
    if screen.target(display.width, display.height - 1).is_ok() {
        return Err("observation bounds verification failed".into());
    }
    println!(
        "{{\"ok\":true,\"transport\":\"usb_screenshotr\",\"format\":\"PNG\",\"width\":{},\"height\":{},\"decoded_pixels_verified\":true,\"bounds_verified\":true}}",
        display.width, display.height
    );
    Ok(())
}

#[cfg(any(not(unix), target_os = "ios"))]
fn main() {
    eprintln!("USB-assisted observation requires a trusted macOS or Linux host.");
    std::process::exit(2);
}
