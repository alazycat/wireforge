//! Cross-platform utility functions shared by all platform backends.

use std::time::Duration;

/// Set socket receive timeout (SO_RCVTIMEO) across platforms.
///
/// Linux/macOS use `timeval`, Windows uses `DWORD` (milliseconds).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn set_socket_timeout(fd: i32, dur: Option<Duration>) -> Result<(), crate::error::IoError> {
    let tv = dur.map(|d| libc::timeval {
        tv_sec: d.as_secs() as libc::time_t,
        tv_usec: d.subsec_micros() as libc::suseconds_t,
    });
    let tv_ptr: *const libc::timeval = match tv.as_ref() {
        Some(t) => t,
        None => std::ptr::null(),
    };
    unsafe {
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            tv_ptr as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        ) < 0
        {
            return Err(crate::error::IoError::Socket(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn set_socket_timeout(_fd: i32, _dur: Option<Duration>) -> Result<(), crate::error::IoError> {
    // Windows uses setsockopt with DWORD timeout in milliseconds.
    // Placeholder until Issue #32 implements Windows L3.
    Err(crate::error::IoError::UnsupportedPlatform)
}
