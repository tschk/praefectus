use foreign_types::ForeignTypeRef;
use screencapturekit::CGImage;
use screencapturekit::prelude::{
    SCContentFilter, SCDisplay, SCShareableContent, SCStreamConfiguration,
};
use screencapturekit::screenshot_manager::SCScreenshotManager;
use sha2::{Digest, Sha256};

pub(crate) struct CaptureError;

fn configuration(width: u32, height: u32) -> SCStreamConfiguration {
    SCStreamConfiguration::new()
        .with_width(width.max(1))
        .with_height(height.max(1))
        .with_shows_cursor(false)
}

fn image_digest(image: &CGImage, hasher: &mut Sha256) {
    hasher.update(image.width().to_be_bytes());
    hasher.update(image.height().to_be_bytes());
    hasher.update(image.bytes_per_row().to_be_bytes());
    let pointer = image.as_ptr();
    if pointer.is_null() {
        return;
    }
    let borrowed = unsafe { core_graphics::image::CGImageRef::from_ptr(pointer.cast()) };
    hasher.update(borrowed.data().as_ref());
}

fn displays() -> Result<Vec<SCDisplay>, CaptureError> {
    Ok(SCShareableContent::get()
        .map_err(|_| CaptureError)?
        .displays())
}

fn capture(filter: &SCContentFilter, width: u32, height: u32) -> Result<CGImage, CaptureError> {
    SCScreenshotManager::capture_image(filter, &configuration(width, height))
        .map_err(|_| CaptureError)
}

const CAPTURE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) fn screen_content_hash() -> Result<String, CaptureError> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .spawn(move || {
            let _ = sender.send(blocking_screen_content_hash());
        })
        .map_err(|_| CaptureError)?;
    receiver
        .recv_timeout(CAPTURE_TIMEOUT)
        .map_err(|_| CaptureError)?
}

fn blocking_screen_content_hash() -> Result<String, CaptureError> {
    let displays = displays()?;
    if displays.is_empty() {
        return Err(CaptureError);
    }
    let mut hasher = Sha256::new();
    for display in displays {
        let frame = display.frame();
        let filter = SCContentFilter::create()
            .with_display(&display)
            .with_excluding_windows(&[])
            .build();
        let image = capture(&filter, display.width(), display.height())?;
        hasher.update(display.display_id().to_be_bytes());
        hasher.update(frame.size.width.to_bits().to_be_bytes());
        hasher.update(frame.size.height.to_bits().to_be_bytes());
        image_digest(&image, &mut hasher);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_clamps_zero_dimensions_and_hides_the_cursor() {
        let config = configuration(0, 0);
        assert_eq!(config.width(), 1);
        assert_eq!(config.height(), 1);
        assert!(!config.shows_cursor());
    }

    #[test]
    fn configuration_preserves_nonzero_dimensions() {
        let config = configuration(1920, 1080);
        assert_eq!(config.width(), 1920);
        assert_eq!(config.height(), 1080);
        assert!(!config.shows_cursor());
    }
}
