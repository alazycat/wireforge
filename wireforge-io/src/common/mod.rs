//! Cross-platform utility functions shared by all platform backends.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::Duration;

/// Set socket receive timeout (SO_RCVTIMEO) on Linux/macOS.
///
/// Uses `timeval`; Windows backends configure `SO_RCVTIMEO` themselves.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
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
            return Err(crate::error::IoError::Socket(
                std::io::Error::last_os_error(),
            ));
        }
    }
    Ok(())
}
