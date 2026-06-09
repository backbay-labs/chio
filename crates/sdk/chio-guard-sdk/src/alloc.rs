//! Vec-based guest allocator for the Chio WASM guard ABI.
//!
//! The host runtime calls `chio_alloc` to reserve space in guest linear memory
//! before writing the serialized `GuardRequest` JSON. The guest calls
//! `chio_free` to release the allocation when done.
//!
//! This allocator keeps each `Vec<u8>` alive in thread-local storage so the
//! underlying memory is not reclaimed before the host writes into it.

use std::cell::RefCell;

thread_local! {
    static ALLOCATIONS: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Allocate `size` bytes of zeroed memory in the guest and return a pointer.
///
/// Returns 0 if `size <= 0` or if the allocation fails for any reason.
/// The host probes this export via `get_typed_func::<i32, i32>`.
#[no_mangle]
pub extern "C" fn chio_alloc(size: i32) -> i32 {
    if size <= 0 {
        return 0;
    }
    let buf = vec![0u8; size as usize];
    let ptr = buf.as_ptr() as usize;
    // On wasm32, usize is 32 bits so this cast is lossless.
    // On 64-bit native targets (used for testing), truncation may occur
    // but the allocator logic itself is still exercised correctly.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let ptr_i32 = ptr as i32;
    ALLOCATIONS.with(|allocs| {
        if let Ok(mut v) = allocs.try_borrow_mut() {
            v.push(buf);
        }
    });
    ptr_i32
}

/// Free a previously allocated region.
///
/// Removes the matching `Vec` from thread-local storage. If no match is
/// found (e.g., double-free or invalid pointer), this is a silent no-op.
#[no_mangle]
pub extern "C" fn chio_free(ptr: i32, size: i32) {
    if ptr <= 0 || size <= 0 {
        return;
    }
    ALLOCATIONS.with(|allocs| {
        if let Ok(mut v) = allocs.try_borrow_mut() {
            // Find and remove the allocation whose base pointer and length match.
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let idx = v
                .iter()
                .position(|buf| buf.as_ptr() as usize as i32 == ptr && buf.len() as i32 == size);
            if let Some(i) = idx {
                v.swap_remove(i);
            }
        }
    });
}

/// Clear all tracked allocations (for testing).
#[cfg(test)]
fn reset_allocations() {
    ALLOCATIONS.with(|allocs| {
        if let Ok(mut v) = allocs.try_borrow_mut() {
            v.clear();
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn alloc_positive_size_returns_nonzero() {
        reset_allocations();
        let ptr = chio_alloc(100);
        assert_ne!(ptr, 0, "chio_alloc(100) should return a non-zero pointer");
        reset_allocations();
    }

    #[test]
    fn alloc_zero_returns_zero() {
        reset_allocations();
        let ptr = chio_alloc(0);
        assert_eq!(ptr, 0, "chio_alloc(0) should return 0");
        reset_allocations();
    }

    #[test]
    fn alloc_negative_returns_zero() {
        reset_allocations();
        let ptr = chio_alloc(-1);
        assert_eq!(ptr, 0, "chio_alloc(-1) should return 0");
        reset_allocations();
    }

    #[test]
    fn alloc_multiple_returns_different_pointers() {
        reset_allocations();
        let p1 = chio_alloc(64);
        let p2 = chio_alloc(64);
        assert_ne!(p1, 0);
        assert_ne!(p2, 0);
        assert_ne!(p1, p2, "Two allocations should return different pointers");
        reset_allocations();
    }

    #[test]
    fn free_does_not_panic() {
        reset_allocations();
        let ptr = chio_alloc(32);
        // Free a valid allocation
        chio_free(ptr, 32);
        // Free an invalid allocation (should not panic)
        chio_free(999, 999);
        reset_allocations();
    }
}
