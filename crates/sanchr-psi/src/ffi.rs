//! C-ABI FFI bridge for iOS OPRF client operations.
//!
//! Exposes [`oprf::blind`] and [`oprf::unblind`] as `extern "C"` functions
//! so the Swift layer can call them through the static library without
//! reimplementing the Ristretto255 arithmetic.

use std::ffi::CStr;
use std::os::raw::c_char;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::oprf;

/// Blind a phone number for OPRF evaluation.
///
/// On success writes:
///   - 32 bytes of the blinding scalar into `blinding_scalar_out`
///   - 32 bytes of the compressed blinded point into `blinded_point_out`
///
/// Returns 0 on success, -1 on error (invalid UTF-8 phone string, null pointer).
///
/// # Safety
///
/// - `phone` must be a valid, non-null, null-terminated C string.
/// - `blinding_scalar_out` must point to at least 32 writable bytes.
/// - `blinded_point_out` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sanchr_oprf_blind(
    phone: *const c_char,
    blinding_scalar_out: *mut u8,
    blinded_point_out: *mut u8,
) -> i32 {
    if phone.is_null() || blinding_scalar_out.is_null() || blinded_point_out.is_null() {
        return -1;
    }

    let phone_str = match unsafe { CStr::from_ptr(phone) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let (scalar, blinded_compressed) = oprf::blind(phone_str);

    let scalar_bytes = scalar.to_bytes();
    let point_bytes = blinded_compressed.to_bytes();

    unsafe {
        std::ptr::copy_nonoverlapping(scalar_bytes.as_ptr(), blinding_scalar_out, 32);
        std::ptr::copy_nonoverlapping(point_bytes.as_ptr(), blinded_point_out, 32);
    }

    0
}

/// Unblind a server OPRF response.
///
/// Given the server's 32-byte compressed-point response and the client's
/// 32-byte blinding scalar, computes `r^{-1} * R` and writes the resulting
/// 32-byte compressed point into `unblinded_out`.
///
/// Returns 0 on success, -1 on error (decompression failure, zero scalar, null pointer).
///
/// # Safety
///
/// - `server_response` must point to at least 32 readable bytes (a compressed Ristretto point).
/// - `blinding_scalar` must point to at least 32 readable bytes.
/// - `unblinded_out` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sanchr_oprf_unblind(
    server_response: *const u8,
    blinding_scalar: *const u8,
    unblinded_out: *mut u8,
) -> i32 {
    if server_response.is_null() || blinding_scalar.is_null() || unblinded_out.is_null() {
        return -1;
    }

    let mut resp_bytes = [0u8; 32];
    let mut scalar_bytes = [0u8; 32];
    unsafe {
        std::ptr::copy_nonoverlapping(server_response, resp_bytes.as_mut_ptr(), 32);
        std::ptr::copy_nonoverlapping(blinding_scalar, scalar_bytes.as_mut_ptr(), 32);
    }

    let compressed_response = CompressedRistretto(resp_bytes);
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);

    match oprf::unblind(&scalar, &compressed_response) {
        Ok(unblinded_compressed) => {
            let out_bytes = unblinded_compressed.to_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(out_bytes.as_ptr(), unblinded_out, 32);
            }
            0
        }
        Err(_) => -1,
    }
}
