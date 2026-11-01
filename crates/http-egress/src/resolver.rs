//! DNS resolution with address filtering.
//!
//! The egress client has exactly one place where a host name becomes an address: [`PolicyResolver`]. reqwest
//! calls it when it opens a connection and connects to the addresses it returns and to no others, so the check
//! and the use cannot be separated by a second lookup (DNS rebinding). The resolver refuses the whole answer when
//! any address in it is denied: a record set that mixes a public and a private address is how rebinding attacks
//! are built, and no legitimate receiver publishes one.
//!
//! The lookup itself is a trait ([`HostLookup`]) so that tests answer with fixed addresses instead of the
//! network.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::sync::Semaphore;

use crate::policy::{EgressPolicy, PolicyViolation, normalize_host};

/// Looks up the addresses of a host name.
#[async_trait]
pub trait HostLookup: Send + Sync {
    /// The addresses of `host` (lowercase, without a trailing dot), in the order the resolver prefers them.
    ///
    /// # Errors
    ///
    /// An I/O error when the name cannot be resolved.
    async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// The blocking function a [`SystemLookup`] runs: `getaddrinfo` unless a test brings its own.
type BlockingLookup = Arc<dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync>;

/// The operating system's resolver (`getaddrinfo`) with a time limit and a limit on how many lookups run at once.
///
/// `getaddrinfo` blocks a thread of the runtime's blocking pool until the resolver answers, and a timeout cannot
/// stop it: the thread is busy for as long as the resolver takes. The permit of a lookup is therefore held by the
/// blocking task itself and not by the future that waits for it, so that names which never answer can occupy at
/// most `max_concurrent` threads, however many requests wait for them or give up.
#[derive(Clone)]
pub struct SystemLookup {
    timeout: Duration,
    permits: Arc<Semaphore>,
    resolve: BlockingLookup,
}

impl core::fmt::Debug for SystemLookup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SystemLookup")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl SystemLookup {
    /// A lookup that gives up after `timeout` (waiting for a free slot included) and runs at most `max_concurrent`
    /// lookups (at least one) at the same time.
    pub fn new(timeout: Duration, max_concurrent: u32) -> Self {
        Self::with_resolver(
            timeout,
            max_concurrent,
            Arc::new(|host: &str| {
                let mut unique = Vec::new();
                for address in (host, 0).to_socket_addrs()? {
                    if !unique.contains(&address.ip()) {
                        unique.push(address.ip());
                    }
                }
                Ok(unique)
            }),
        )
    }

    /// Like [`SystemLookup::new`] with another blocking resolver (tests).
    pub fn with_resolver(timeout: Duration, max_concurrent: u32, resolve: BlockingLookup) -> Self {
        let slots = usize::try_from(max_concurrent).unwrap_or(usize::MAX).max(1);
        Self {
            timeout,
            permits: Arc::new(Semaphore::new(slots)),
            resolve,
        }
    }
}

#[async_trait]
impl HostLookup for SystemLookup {
    async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "the lookup timed out");
        let permit = tokio::time::timeout(self.timeout, Arc::clone(&self.permits).acquire_owned())
            .await
            .map_err(|_| timed_out())?
            .map_err(|_| io::Error::other("the lookup limit was closed"))?;
        let resolve = Arc::clone(&self.resolve);
        let host = host.to_owned();
        let task = tokio::task::spawn_blocking(move || {
            // Held until the resolver has answered, even when nobody waits for the answer any more.
            let _permit = permit;
            resolve(&host)
        });
        tokio::time::timeout(self.timeout, task)
            .await
            .map_err(|_| timed_out())?
            .map_err(|_| io::Error::other("the lookup task failed"))?
    }
}

/// How resolving a host name for an outbound request failed.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The policy refuses an address of the answer.
    #[error(transparent)]
    Denied(#[from] PolicyViolation),
    /// The name has no addresses or the lookup failed.
    #[error("the host name could not be resolved ({0})")]
    Lookup(io::ErrorKind),
}

/// Resolves host names and applies the egress policy to every address of the answer.
#[derive(Clone)]
pub struct PolicyResolver {
    lookup: Arc<dyn HostLookup>,
    policy: Arc<EgressPolicy>,
}

impl PolicyResolver {
    /// A resolver that asks `lookup` and filters with `policy`.
    pub fn new(lookup: Arc<dyn HostLookup>, policy: Arc<EgressPolicy>) -> Self {
        Self { lookup, policy }
    }

    /// The addresses of `host`, all of which the policy permits.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Denied`] when any address of the answer is denied, [`ResolveError::Lookup`] when the name
    /// has no address or cannot be looked up.
    pub async fn resolve_allowed(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let host = normalize_host(host);
        let addresses = self
            .lookup
            .lookup(&host)
            .await
            .map_err(|error| ResolveError::Lookup(error.kind()))?;
        if addresses.is_empty() {
            return Err(ResolveError::Lookup(io::ErrorKind::NotFound));
        }
        for address in &addresses {
            self.policy.check_address(*address, Some(&host))?;
        }
        Ok(addresses)
    }
}

impl core::fmt::Debug for PolicyResolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyResolver").finish_non_exhaustive()
    }
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = resolver.resolve_allowed(&host).await?;
            // Port 0 makes the connector use the port of the URL.
            let addrs: Addrs = Box::new(addresses.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

/// Test doubles shared with the tests of the client.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::BTreeMap;
    use std::io;
    use std::net::IpAddr;
    use std::sync::Arc;

    use async_trait::async_trait;

    use super::HostLookup;

    /// Answers from a table; unknown names do not resolve.
    pub(crate) struct TableLookup(BTreeMap<String, Vec<IpAddr>>);

    impl TableLookup {
        pub(crate) fn of(entries: &[(&str, &[&str])]) -> Arc<dyn HostLookup> {
            Arc::new(Self(
                entries
                    .iter()
                    .map(|(name, addresses)| {
                        (
                            (*name).to_owned(),
                            addresses.iter().map(|address| address.parse().unwrap()).collect(),
                        )
                    })
                    .collect(),
            ))
        }
    }

    #[async_trait]
    impl HostLookup for TableLookup {
        async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
            self.0
                .get(host)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::TableLookup;
    use super::*;
    use crate::config::EgressConfig;
    use crate::policy::AddressClass;

    fn resolver(entries: &[(&str, &[&str])], edit: impl FnOnce(&mut EgressConfig)) -> PolicyResolver {
        let mut config = EgressConfig::default();
        edit(&mut config);
        PolicyResolver::new(TableLookup::of(entries), Arc::new(EgressPolicy::new(&config)))
    }

    #[tokio::test]
    async fn public_answers_pass_unchanged() {
        let resolver = resolver(&[("hooks.example.org", &["93.184.216.34", "2606:2800:21f::1"])], |_| {});
        let addresses = resolver.resolve_allowed("Hooks.Example.org.").await.unwrap();
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0].to_string(), "93.184.216.34");
    }

    #[tokio::test]
    async fn one_denied_address_refuses_the_whole_answer() {
        // The classic rebinding answer: a public address first, the target second.
        for denied in [
            "127.0.0.1",
            "10.0.0.5",
            "169.254.169.254",
            "::1",
            "fd00::1",
            "::ffff:192.168.0.1",
        ] {
            let resolver = resolver(&[("rebind.example.org", &["93.184.216.34", denied])], |_| {});
            let error = resolver.resolve_allowed("rebind.example.org").await.unwrap_err();
            assert!(
                matches!(error, ResolveError::Denied(PolicyViolation::Address(_))),
                "{denied}: {error}"
            );
            let reversed = resolver_with_first(denied);
            let error = reversed.resolve_allowed("rebind.example.org").await.unwrap_err();
            assert!(matches!(error, ResolveError::Denied(_)), "{denied}: {error}");
        }
    }

    fn resolver_with_first(first: &str) -> PolicyResolver {
        resolver(&[("rebind.example.org", &[first, "93.184.216.34"])], |_| {})
    }

    #[tokio::test]
    async fn names_without_answers_do_not_resolve() {
        let resolver = resolver(&[("empty.example.org", &[])], |_| {});
        for host in ["empty.example.org", "missing.example.org"] {
            let error = resolver.resolve_allowed(host).await.unwrap_err();
            assert!(
                matches!(error, ResolveError::Lookup(io::ErrorKind::NotFound)),
                "{host}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn allowed_hosts_and_ranges_apply_to_resolved_addresses() {
        let entries: &[(&str, &[&str])] = &[
            ("hooks.internal.example", &["10.20.30.40"]),
            ("other.internal.example", &["10.20.30.41"]),
            ("meta.internal.example", &["169.254.169.254"]),
        ];
        let by_host = resolver(entries, |config| {
            config.allow_hosts = vec!["hooks.internal.example".to_owned()];
        });
        assert!(by_host.resolve_allowed("hooks.internal.example").await.is_ok());
        assert!(matches!(
            by_host.resolve_allowed("other.internal.example").await.unwrap_err(),
            ResolveError::Denied(PolicyViolation::Address(AddressClass::Private))
        ));
        let by_range = resolver(entries, |config| {
            config.allow_cidrs = vec!["10.20.0.0/16".parse().unwrap()];
        });
        assert!(by_range.resolve_allowed("other.internal.example").await.is_ok());
        for resolver in [&by_host, &by_range] {
            assert!(matches!(
                resolver.resolve_allowed("meta.internal.example").await.unwrap_err(),
                ResolveError::Denied(PolicyViolation::Address(AddressClass::Metadata))
            ));
        }
    }

    #[tokio::test]
    async fn the_reqwest_hook_returns_ports_of_zero_and_carries_the_violation() {
        let resolver = resolver(
            &[
                ("good.example.org", &["93.184.216.34"]),
                ("evil.example.org", &["127.0.0.1"]),
            ],
            |_| {},
        );
        let name: Name = "good.example.org".parse().unwrap();
        let addrs: Vec<SocketAddr> = resolver.resolve(name).await.unwrap().collect();
        assert_eq!(addrs, vec!["93.184.216.34:0".parse().unwrap()]);

        let name: Name = "evil.example.org".parse().unwrap();
        let Err(error) = resolver.resolve(name).await else {
            panic!("a loopback answer must not resolve");
        };
        let refusal = error
            .downcast_ref::<ResolveError>()
            .expect("the refusal travels with the error");
        assert!(
            matches!(
                refusal,
                ResolveError::Denied(PolicyViolation::Address(AddressClass::Loopback))
            ),
            "{refusal}"
        );
    }

    #[expect(
        clippy::disallowed_types,
        reason = "a blocking test double: it runs on the blocking pool"
    )]
    type StdMutex<T> = std::sync::Mutex<T>;

    /// Lookups that block until the test lets them go, and that remember how many ran at the same time.
    struct Gate {
        running: std::sync::atomic::AtomicUsize,
        peak: std::sync::atomic::AtomicUsize,
        release: StdMutex<std::sync::mpsc::Receiver<()>>,
    }

    #[tokio::test]
    async fn only_so_many_lookups_run_at_the_same_time() {
        use std::sync::atomic::Ordering;

        let (release, receiver) = std::sync::mpsc::channel::<()>();
        let gate = Arc::new(Gate {
            running: std::sync::atomic::AtomicUsize::new(0),
            peak: std::sync::atomic::AtomicUsize::new(0),
            release: StdMutex::new(receiver),
        });
        let blocking: BlockingLookup = {
            let gate = Arc::clone(&gate);
            Arc::new(move |_host: &str| {
                let now = gate.running.fetch_add(1, Ordering::SeqCst) + 1;
                gate.peak.fetch_max(now, Ordering::SeqCst);
                gate.release.lock().unwrap().recv().unwrap();
                gate.running.fetch_sub(1, Ordering::SeqCst);
                Ok(vec!["93.184.216.34".parse().unwrap()])
            })
        };
        let lookup = Arc::new(SystemLookup::with_resolver(Duration::from_secs(30), 2, blocking));

        let tasks: Vec<_> = (0..6)
            .map(|n| {
                let lookup = Arc::clone(&lookup);
                tokio::spawn(async move { lookup.lookup(&format!("host{n}.example.org")).await })
            })
            .collect();
        while gate.running.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            gate.running.load(Ordering::SeqCst),
            2,
            "two slots, the other four lookups wait"
        );
        for _ in 0..6 {
            release.send(()).unwrap();
        }
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap().len(), 1);
        }
        assert_eq!(gate.peak.load(Ordering::SeqCst), 2, "never more than the limit at once");
    }

    #[tokio::test]
    async fn a_caller_that_waits_for_a_slot_gives_up_after_the_timeout_and_the_slot_stays_taken() {
        // One slot, held by a lookup that does not answer: the second caller times out instead of waiting for
        // ever, and so does the first (the thread keeps running, and keeps its slot, until the resolver answers).
        let (release, receiver) = std::sync::mpsc::channel::<()>();
        let receiver = Arc::new(StdMutex::new(receiver));
        let blocking: BlockingLookup = Arc::new(move |_host: &str| {
            let _ = receiver.lock().unwrap().recv();
            Ok(Vec::new())
        });
        let lookup = Arc::new(SystemLookup::with_resolver(Duration::from_millis(50), 1, blocking));
        let first = {
            let lookup = Arc::clone(&lookup);
            tokio::spawn(async move { lookup.lookup("a.example.org").await })
        };
        tokio::task::yield_now().await;
        let error = lookup.lookup("b.example.org").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let first_error = first.await.unwrap().unwrap_err();
        assert_eq!(first_error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            lookup.lookup("c.example.org").await.unwrap_err().kind(),
            io::ErrorKind::TimedOut,
            "the slot of the abandoned lookup is still taken"
        );
        drop(release);
    }

    #[test]
    fn the_resolver_does_not_print_its_tables() {
        let resolver = resolver(&[("a.example.org", &["93.184.216.34"])], |_| {});
        assert_eq!(format!("{resolver:?}"), "PolicyResolver { .. }");
    }
}
