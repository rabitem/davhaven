//! The `Database` implementation.
//!
//! [`MemoryDatabase`] keeps the whole state behind one async mutex. A transaction takes the lock when it begins and
//! keeps it until it is committed or dropped, so transactions are serial; a read-write transaction works on the
//! live state and puts a snapshot back when it is dropped without committing.
//!
//! A task that begins a second transaction while it holds the first would wait for itself. Rather than hang, `begin`
//! waits for the lock for a bounded time ([`DEFAULT_LOCK_WAIT`], see [`MemoryDatabase::with_lock_wait`]) and then
//! fails with [`StoreError::Internal`] that names the likely cause, so such a use case fails its test.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use davhaven_domain::TenantId;
use davhaven_ports::{Clock, Database, Health, IdGenerator, Lifecycle, StoreError, SystemTx, Tx, TxMode, observe};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::repos::LABEL;
use crate::state::State;
use crate::tx::{MemSystemTx, MemTx};

/// How long `begin` waits for the one transaction slot before it reports a nested or leaked transaction. Legitimate
/// transactions are short, so a wait this long means a task is holding a transaction while it waits for another.
/// Tests with a paused clock (`start_paused`) reach the end of the wait at once.
pub const DEFAULT_LOCK_WAIT: Duration = Duration::from_secs(10);

/// The in-memory implementation of the `Database` port. Clones share the same data.
#[derive(Clone)]
pub struct MemoryDatabase {
    state: Arc<Mutex<State>>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    lock_wait: Duration,
}

impl std::fmt::Debug for MemoryDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryDatabase").finish_non_exhaustive()
    }
}

impl MemoryDatabase {
    /// An empty database that stamps rows with `clock` and draws epochs from `ids`.
    pub fn new(clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            clock,
            ids,
            lock_wait: DEFAULT_LOCK_WAIT,
        }
    }

    /// Sets how long `begin` waits for the transaction slot before it fails (default [`DEFAULT_LOCK_WAIT`]).
    #[must_use]
    pub fn with_lock_wait(mut self, lock_wait: Duration) -> Self {
        self.lock_wait = lock_wait;
        self
    }

    /// Takes the one transaction slot, waiting at most the configured time.
    ///
    /// # Errors
    ///
    /// [`StoreError::Internal`] when the slot stays taken: a task is holding a transaction while it begins another,
    /// or a transaction was leaked (kept alive in a long-lived value).
    async fn lock_state(&self) -> Result<OwnedMutexGuard<State>, StoreError> {
        let state = Arc::clone(&self.state);
        if let Ok(guard) = Arc::clone(&state).try_lock_owned() {
            return Ok(guard);
        }
        tokio::time::timeout(self.lock_wait, state.lock_owned())
            .await
            .map_err(|_| {
                StoreError::internal(format!(
                    "nested transaction: no transaction slot became free within {:?}; a task holds a transaction while \
                     it begins another, or a transaction was leaked (ENGINEERING_RULES: one transaction per task)",
                    self.lock_wait
                ))
            })
    }
}

#[async_trait]
impl Database for MemoryDatabase {
    async fn begin(&self, tenant: TenantId, mode: TxMode) -> Result<Box<dyn Tx>, StoreError> {
        observe(LABEL, "begin", async {
            let guard = self.lock_state().await?;
            let tx: Box<dyn Tx> = Box::new(MemTx::new(
                guard,
                tenant,
                mode,
                Arc::clone(&self.clock),
                Arc::clone(&self.ids),
            ));
            Ok(tx)
        })
        .await
    }

    async fn begin_system(&self) -> Result<Box<dyn SystemTx>, StoreError> {
        observe(LABEL, "begin_system", async {
            let guard = self.lock_state().await?;
            let tx: Box<dyn SystemTx> =
                Box::new(MemSystemTx::new(guard, Arc::clone(&self.clock), Arc::clone(&self.ids)));
            Ok(tx)
        })
        .await
    }

    async fn health(&self) -> Health {
        Health::Healthy
    }
}

#[async_trait]
impl Lifecycle for MemoryDatabase {
    async fn health(&self) -> Health {
        Health::Healthy
    }

    async fn shutdown(&self) {}
}
