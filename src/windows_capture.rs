use crate::NativeError;
use sha2::{Digest, Sha256};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::WindowsAndMessaging::*;

#[cfg(windows)]
pub(crate) fn native_screen_content_hash() -> Result<String, NativeError> {
    let cx = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) };
    let cy = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) };
    let ox = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    let oy = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    if cx <= 0 || cy <= 0 {
        return Err(NativeError);
    }
    let screen_dc = unsafe { GetDC(None) };
    if screen_dc.0.is_null() {
        return Err(NativeError);
    }
    let mem_dc = unsafe { CreateCompatibleDC(Some(screen_dc)) };
    if mem_dc.0.is_null() {
        unsafe {
            let _ = ReleaseDC(None, screen_dc);
        }
        return Err(NativeError);
    }
    let bitmap = unsafe { CreateCompatibleBitmap(screen_dc, cx, cy) };
    if bitmap.0.is_null() {
        unsafe {
            let _ = DeleteDC(mem_dc);
            let _ = ReleaseDC(None, screen_dc);
        }
        return Err(NativeError);
    }
    let old_bmp = unsafe { SelectObject(mem_dc, bitmap.into()) };
    let blt_ok = unsafe { BitBlt(mem_dc, 0, 0, cx, cy, Some(screen_dc), ox, oy, SRCCOPY) }.is_ok();
    unsafe {
        let _ = SelectObject(mem_dc, old_bmp);
    }
    if !blt_ok {
        unsafe {
            let _ = DeleteObject(HGDIOBJ(bitmap.0));
            let _ = DeleteDC(mem_dc);
            let _ = ReleaseDC(None, screen_dc);
        }
        return Err(NativeError);
    }
    let mut bmi: BITMAPINFO = unsafe { std::mem::zeroed() };
    bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bmi.bmiHeader.biWidth = cx;
    bmi.bmiHeader.biHeight = -cy;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = 0;
    let buf_len = (cx as usize) * (cy as usize) * 4;
    let mut pixels = vec![0u8; buf_len];
    let n = unsafe {
        GetDIBits(
            mem_dc,
            bitmap,
            0,
            cy as u32,
            Some(pixels.as_mut_ptr().cast()),
            &mut bmi,
            DIB_RGB_COLORS,
        )
    };
    unsafe {
        let _ = DeleteObject(HGDIOBJ(bitmap.0));
        let _ = DeleteDC(mem_dc);
        let _ = ReleaseDC(None, screen_dc);
    }
    if n <= 0 {
        return Err(NativeError);
    }
    let used = (n as usize) * (cx as usize) * 4;
    let mut hasher = Sha256::new();
    hasher.update((ox as i64).to_be_bytes());
    hasher.update((oy as i64).to_be_bytes());
    hasher.update((cx as i64).to_be_bytes());
    hasher.update((cy as i64).to_be_bytes());
    hasher.update(&pixels[..used]);
    return Ok(hex::encode(hasher.finalize()));
}
