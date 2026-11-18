//! Caller-buffer numeric MIB reads for macOS.

/// Reads one numeric MIB into caller-owned initialized storage.
///
/// Performs exactly one synchronous `sysctl` call after validation. No type
/// lookup, size query, allocation, retry, or value conversion is performed.
/// On success, returns the kernel-reported byte count, at most `output.len()`.
/// Callers must validate the expected record size and decode bytes themselves.
/// On error, output contents are unspecified and must not be used as a result.
/// A successful short or empty result is not evidence of a complete record.
///
/// `mib` must have 2..=12 components (the macOS CTL_MAXNAME bound); `output`
/// must be nonempty, preventing accidental size-query semantics. Invalid input
/// yields EINVAL, an impossible successful output length yields EOVERFLOW,
/// and syscall errors retain their raw errno, including ENOMEM and ESRCH.
/// Null newp and zero newlen request no value write. A numeric query may still
/// have kernel-defined read side effects; choose MIBs appropriate to the caller.
/// No hard timeout or cancellation of the synchronous kernel call is provided.
pub fn read_into(mib: &[libc::c_int], output: &mut [u8]) -> std::io::Result<usize> {
    // macOS public sys/sysctl.h: CTL_MAXNAME = 12. The crate-wide constant
    // is 24 and must not be used for this target-specific bound.
    const MAX_COMPONENTS: usize = 12;
    if !(2..=MAX_COMPONENTS).contains(&mib.len()) || output.is_empty() {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    let namelen = libc::c_uint::try_from(mib.len())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // Darwin's C declaration takes a mutable pointer. Copy into exclusive,
    // bounded stack storage rather than casting away the shared input borrow.
    let mut name = [0; MAX_COMPONENTS];
    name[..mib.len()].copy_from_slice(mib);
    let capacity = output.len();
    let mut written = capacity;
    // SAFETY: name holds namelen initialized c_ints; output is exclusively
    // borrowed initialized writable storage of capacity bytes; written is a
    // valid size_t. sysctl respects oldlenp's input bound. No new value is
    // supplied. All storage remains live for the synchronous call. No typed
    // references are constructed from output and no input alias is mutated.
    let result = unsafe {
        libc::sysctl(
            name.as_mut_ptr(), namelen, output.as_mut_ptr().cast(),
            &mut written, std::ptr::null_mut(), 0,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if written > capacity {
        return Err(std::io::Error::from_raw_os_error(libc::EOVERFLOW));
    }
    Ok(written)
}
