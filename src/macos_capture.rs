use foreign_types::ForeignTypeRef;
use screencapturekit::CGImage;
use screencapturekit::prelude::{
    SCContentFilter, SCDisplay, SCShareableContent, SCStreamConfiguration, SCWindow,
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

fn windows() -> Result<Vec<SCWindow>, CaptureError> {
    Ok(SCShareableContent::get()
        .map_err(|_| CaptureError)?
        .windows())
}

fn capture(filter: &SCContentFilter, width: u32, height: u32) -> Result<CGImage, CaptureError> {
    SCScreenshotManager::capture_image(filter, &configuration(width, height))
        .map_err(|_| CaptureError)
}

pub(crate) fn available() -> bool {
    SCShareableContent::get().is_ok_and(|content| !content.displays().is_empty())
}

pub(crate) fn screen_content_hash() -> Result<String, CaptureError> {
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
        let image = capture(&filter, frame.size.width as u32, frame.size.height as u32)?;
        hasher.update(display.display_id().to_be_bytes());
        image_digest(&image, &mut hasher);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) fn window_content_hash(window_id: u32) -> Result<String, CaptureError> {
    let window = windows()?
        .into_iter()
        .find(|window| window.window_id() == window_id)
        .ok_or(CaptureError)?;
    let frame = window.frame();
    let filter = SCContentFilter::create().with_window(&window).build();
    let image = capture(&filter, frame.size.width as u32, frame.size.height as u32)?;
    let mut hasher = Sha256::new();
    hasher.update(window_id.to_be_bytes());
    image_digest(&image, &mut hasher);
    Ok(hex::encode(hasher.finalize()))
}
