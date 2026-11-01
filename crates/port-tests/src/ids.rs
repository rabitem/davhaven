//! Contract suite of the `IdGenerator` port.
//!
//! What every generator promises: identifiers are unique UUIDv7 values, typed identifiers wrap them, and random
//! bytes have the requested length and differ between draws. The production generator and `SeqIds` run it.

use std::collections::HashSet;
use std::sync::Arc;

use davhaven_domain::TenantId;
use davhaven_ports::{IdGenerator, IdGeneratorExt as _};

use crate::suite::{Checks, ContractReport, Suite};

/// How many identifiers the uniqueness case draws.
const DRAWS: usize = 2000;

/// Runs the suite against generators built by `factory` and returns the report.
pub fn run<F>(factory: F) -> ContractReport
where
    F: Fn() -> Arc<dyn IdGenerator>,
{
    let mut suite = Suite::new("ids");

    let mut checks = Checks::new("identifiers are unique version 7 UUIDs");
    let ids = factory();
    let mut seen = HashSet::new();
    for draw in 0..DRAWS {
        let id = ids.new_id();
        if id.is_nil() {
            checks.fail(format!("draw {draw} is the nil UUID"));
        }
        if id.get_version_num() != 7 {
            checks.fail(format!("draw {draw} ({id}) is version {}, not 7", id.get_version_num()));
        }
        if !seen.insert(id) {
            checks.fail(format!("draw {draw} repeats {id}"));
        }
    }
    suite.record(checks);

    let mut checks = Checks::new("typed identifiers wrap generated UUIDs");
    let ids = factory();
    let tenant: TenantId = ids.new_typed();
    checks.equal(
        &tenant.as_uuid().get_version_num(),
        &7,
        "the version of a typed identifier",
    );
    let other: TenantId = ids.new_typed();
    checks.differ(&tenant, &other, "two typed identifiers");
    suite.record(checks);

    let mut checks = Checks::new("random bytes have the requested length");
    let ids = factory();
    for len in [0_usize, 1, 7, 8, 15, 16, 17, 32, 33, 64] {
        let bytes = ids.random_bytes(len);
        checks.equal(&bytes.len(), &len, "length of the random bytes");
    }
    suite.record(checks);

    let mut checks = Checks::new("successive random draws differ");
    let ids = factory();
    let first = ids.random_bytes(32);
    let second = ids.random_bytes(32);
    checks.differ(&first, &second, "two draws of 32 bytes");
    suite.record(checks);

    let mut checks = Checks::new("an Arc of a generator is a generator");
    let shared = factory();
    let nested: Arc<dyn IdGenerator> = Arc::new(Arc::clone(&shared));
    let direct = shared.new_id();
    let through = nested.new_id();
    checks.differ(&direct, &through, "an id drawn directly and one drawn through the Arc");
    checks.equal(&nested.random_bytes(5).len(), &5, "length through the Arc");
    suite.record(checks);

    suite.finish()
}

/// Runs the suite and fails the running test when any case fails.
///
/// # Panics
///
/// When a case fails.
#[track_caller]
pub fn run_all<F>(factory: F)
where
    F: Fn() -> Arc<dyn IdGenerator>,
{
    run(factory).assert_ok();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use davhaven_ports::UuidV7;
    use davhaven_ports::testing::SeqIds;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn the_production_generator_and_seq_ids_satisfy_the_contract() {
        run_all(|| Arc::new(UuidV7));
        run_all(|| Arc::new(SeqIds::new()));
        assert_eq!(run(|| Arc::new(UuidV7)).case_count(), 5);
    }

    /// A generator with constant output.
    struct Constant;

    impl IdGenerator for Constant {
        fn new_id(&self) -> Uuid {
            Uuid::from_u128(1)
        }

        fn random_bytes(&self, len: usize) -> Vec<u8> {
            vec![7; len]
        }
    }

    /// A generator of unique but version 4 shaped ids that returns too few bytes.
    struct Sloppy(AtomicU64);

    impl IdGenerator for Sloppy {
        fn new_id(&self) -> Uuid {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            Uuid::from_u128((u128::from(n) << 64) | 0x4000_8000_0000_0000)
        }

        fn random_bytes(&self, len: usize) -> Vec<u8> {
            let fill = u8::try_from(self.0.fetch_add(1, Ordering::SeqCst) % 256).unwrap_or(0);
            vec![fill; len.saturating_sub(1)]
        }
    }

    #[test]
    fn broken_generators_are_caught() {
        let constant = run(|| Arc::new(Constant));
        let failed = constant.failed_cases();
        assert!(failed.contains(&"identifiers are unique version 7 UUIDs"), "{constant}");
        assert!(failed.contains(&"successive random draws differ"), "{constant}");

        let sloppy = run(|| Arc::new(Sloppy(AtomicU64::new(1))));
        let failed = sloppy.failed_cases();
        assert!(failed.contains(&"identifiers are unique version 7 UUIDs"), "{sloppy}");
        assert!(failed.contains(&"random bytes have the requested length"), "{sloppy}");
    }
}
