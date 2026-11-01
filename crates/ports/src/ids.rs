//! The `IdGenerator` port and the system id generator.
//!
//! Identifiers and random bytes reach the application only through [`IdGenerator`] (`ENGINEERING_RULES` R9):
//! `Uuid::new_v4`, `Uuid::now_v7` and the `rand` entry points are disallowed everywhere except in [`UuidV7`]. Tests
//! use the deterministic `SeqIds` of the `testing` feature.

use std::sync::Arc;

use uuid::Uuid;

/// The source of identifiers and random bytes.
pub trait IdGenerator: Send + Sync {
    /// A new identifier. Production returns a UUIDv7, so database indexes stay roughly ordered by creation time.
    fn new_id(&self) -> Uuid;

    /// `len` random bytes for secrets, nonces and salts. Production reads the operating system's random source.
    /// Callers keep `len` small (credentials and nonces are tens of bytes).
    fn random_bytes(&self, len: usize) -> Vec<u8>;
}

impl<G: IdGenerator + ?Sized> IdGenerator for Arc<G> {
    fn new_id(&self) -> Uuid {
        (**self).new_id()
    }

    fn random_bytes(&self, len: usize) -> Vec<u8> {
        (**self).random_bytes(len)
    }
}

/// Typed identifiers on top of any [`IdGenerator`]: `ids.new_typed::<TenantId>()`.
pub trait IdGeneratorExt: IdGenerator {
    /// A new identifier wrapped in the id type `T` (any `davhaven_domain` id newtype).
    fn new_typed<T: From<Uuid>>(&self) -> T {
        T::from(self.new_id())
    }
}

impl<G: IdGenerator + ?Sized> IdGeneratorExt for G {}

/// The production generator: UUIDv7 identifiers and operating-system randomness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UuidV7;

impl IdGenerator for UuidV7 {
    #[expect(
        clippy::disallowed_methods,
        reason = "this is the production id generator behind the IdGenerator port"
    )]
    fn new_id(&self) -> Uuid {
        Uuid::now_v7()
    }

    #[expect(
        clippy::panic,
        reason = "continuing without operating-system randomness would hand out predictable secrets"
    )]
    fn random_bytes(&self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; len];
        if let Err(error) = getrandom::fill(&mut bytes) {
            panic!("the operating system random source failed: {error}");
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use davhaven_domain::TenantId;

    use super::*;
    use crate::clock::Clock;

    #[test]
    fn ids_are_version_7_and_unique() {
        let ids = UuidV7;
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let id = ids.new_id();
            assert_eq!(id.get_version_num(), 7);
            assert!(seen.insert(id), "duplicate id {id}");
        }
    }

    #[test]
    fn ids_embed_the_current_time() {
        let id = UuidV7.new_id();
        let (seconds, _) = id.get_timestamp().expect("version 7 ids carry a timestamp").to_unix();
        let now = crate::clock::SystemClock.now().timestamp();
        assert!(
            now.abs_diff(i64::try_from(seconds).expect("fits")) <= 5,
            "{seconds} vs {now}"
        );
    }

    #[test]
    fn random_bytes_have_the_requested_length_and_differ() {
        let ids = UuidV7;
        assert_eq!(ids.random_bytes(0), Vec::<u8>::new());
        let a = ids.random_bytes(32);
        let b = ids.random_bytes(32);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "two 256-bit draws never collide");
    }

    #[test]
    fn typed_ids_wrap_the_generated_uuid() {
        let ids: Arc<dyn IdGenerator> = Arc::new(UuidV7);
        let tenant: TenantId = ids.new_typed();
        assert_eq!(tenant.as_uuid().get_version_num(), 7);
    }
}
