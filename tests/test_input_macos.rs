/// Direct CGEvent input test — bypasses protocol, exercises the actual input code.
/// This is what the native_* functions in lib.rs use under the hood.

#[cfg(target_os = "macos")]
mod mac_tests {
    use core_graphics::event::{CGEvent, CGEventTapLocation, CGEventType, CGMouseButton};
    use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
    use core_graphics::geometry::CGPoint;

    fn post_key(code: u16, flags: u64) {
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState).unwrap();
        let down = CGEvent::new_keyboard_event(source.clone(), code, true).unwrap();
        down.set_flags(core_graphics::event::CGEventFlags::from_bits_truncate(
            flags,
        ));
        down.post(CGEventTapLocation::HID);
        let source_up = CGEventSource::new(CGEventSourceStateID::CombinedSessionState).unwrap();
        let up = CGEvent::new_keyboard_event(source_up, code, false).unwrap();
        up.set_flags(core_graphics::event::CGEventFlags::from_bits_truncate(
            flags,
        ));
        up.post(CGEventTapLocation::HID);
    }

    #[test]
    fn move_cursor_to_corner() {
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState).unwrap();
        let pos = CGPoint::new(200.0, 200.0);
        let event =
            CGEvent::new_mouse_event(source, CGEventType::MouseMoved, pos, CGMouseButton::Left)
                .unwrap();
        event.post(CGEventTapLocation::HID);
        eprintln!("moved cursor to (200, 200)");
    }

    #[test]
    fn type_hello_world() {
        // Type "hello" — key codes: h=0x04, e=0x0E, l=0x25, l=0x25, o=0x1F
        let codes: &[(u16, char)] = &[
            (0x04, 'h'),
            (0x0E, 'e'),
            (0x25, 'l'),
            (0x25, 'l'),
            (0x1F, 'o'),
        ];
        for &(code, ch) in codes {
            post_key(code, 0);
            std::thread::sleep(std::time::Duration::from_millis(30));
            eprintln!("typed '{ch}' (keycode {code:#04x})");
        }
    }

    #[test]
    fn press_escape() {
        post_key(0x35, 0);
        eprintln!("pressed Escape");
    }

    #[test]
    fn press_return() {
        post_key(0x24, 0);
        eprintln!("pressed Return");
    }

    #[test]
    fn hotkey_cmd_space() {
        // Cmd+Space — opens Spotlight on macOS
        let cmd_flag: u64 = 1 << 20;
        post_key(0x31, cmd_flag);
        eprintln!("sent Cmd+Space (Spotlight)");
        // Close it immediately
        std::thread::sleep(std::time::Duration::from_millis(500));
        post_key(0x35, 0); // Escape to close
        eprintln!("sent Escape to close Spotlight");
    }

    #[test]
    fn scroll_down() {
        unsafe extern "C" {
            fn CGEventCreateScrollWheelEvent(
                source: *const std::ffi::c_void,
                units: u32,
                wheel_count: u32,
                wheel1: i32,
                wheel2: i32,
            ) -> *mut std::ffi::c_void;
            fn CGEventPost(tap: u32, event: *const std::ffi::c_void);
        }
        const K_CGSCROLL_EVENT_UNIT_LINE: u32 = 1;
        const K_CGHID_EVENT_TAP: u32 = 0;

        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState).unwrap();
        let source_ptr: *mut core_graphics::sys::CGEventSource =
            unsafe { std::mem::transmute_copy(&source) };
        let raw = unsafe {
            CGEventCreateScrollWheelEvent(source_ptr.cast(), K_CGSCROLL_EVENT_UNIT_LINE, 2, -3, 0)
        };
        assert!(
            !raw.is_null(),
            "CGEventCreateScrollWheelEvent returned null"
        );
        unsafe { CGEventPost(K_CGHID_EVENT_TAP, raw) };
        eprintln!("scrolled down 3 lines");
    }

    #[test]
    fn left_click() {
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState).unwrap();
        let pos = CGPoint::new(300.0, 300.0);
        let down = CGEvent::new_mouse_event(
            source.clone(),
            CGEventType::LeftMouseDown,
            pos,
            CGMouseButton::Left,
        )
        .unwrap();
        down.post(CGEventTapLocation::HID);
        let up =
            CGEvent::new_mouse_event(source, CGEventType::LeftMouseUp, pos, CGMouseButton::Left)
                .unwrap();
        up.post(CGEventTapLocation::HID);
        eprintln!("left-clicked at (300, 300)");
    }
}
