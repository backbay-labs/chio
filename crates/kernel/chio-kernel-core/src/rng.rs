//! Abstract entropy source for receipt IDs and DPoP nonces.
//!
//! The kernel core never calls `OsRng` directly. Browser adapters route
//! to `crypto.getRandomValues()` through `getrandom`'s `js` feature;
//! WASI adapters route to the host's random API; mobile adapters use
//! `SecRandomCopyBytes` / `/dev/urandom`.

/// Trait boundary for cryptographically-secure random byte production.
///
/// Implementations MUST produce cryptographically strong randomness.
/// Failing to do so defeats replay protection (DPoP nonces) and
/// capability-ID unpredictability. The trait deliberately exposes only
/// `fill_bytes` so adapters can route to CSPRNG primitives native to
/// their platform without extra shims.
pub trait Rng {
    /// Fill `dest` with cryptographically secure random bytes.
    fn fill_bytes(&self, dest: &mut [u8]);
}

/// Entropy-free RNG that refuses to produce bytes.
///
/// Useful for test paths that should never require randomness (e.g. pure
/// verdict evaluation with no receipt ID generation). Callers that need
/// to mint receipt IDs must supply a real RNG, typically via the
/// `getrandom`-backed adapter shim in `chio-kernel`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullRng;

impl Rng for NullRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        // Fill with zeros so deterministic-but-non-random contexts still
        // receive a valid slice. Callers that actually need entropy must
        // plug in a real RNG; NullRng is for tests only.
        for byte in dest.iter_mut() {
            *byte = 0;
        }
    }
}

impl<T: Rng + ?Sized> Rng for &T {
    fn fill_bytes(&self, dest: &mut [u8]) {
        (**self).fill_bytes(dest)
    }
}
