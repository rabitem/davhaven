//! The scheduling matrix (PLAN 3.3) over HTTP: organizer surface x attendee x change x reply channel x answer.
//!
//! The cases are those of `SchedulingCase::matrix()` and the expectations those of the decision table
//! (`davhaven_testkit::scheduling::table`). Where `tests/scheduling` drives the services of the application, this
//! binary drives the surfaces people use: a calendar client over DAV, the management API, an MCP tool, the RSVP page of a
//! mail and the inbound endpoint of a mail gateway. See `davhaven_testkit::scheduling::driver` for what a case does.
//!
//! Every case of a surface runs: there is no skipped case, and a surface that cannot be driven is a failure of the run.
//! The exception is PostgreSQL, where every case costs a world of its own: pull requests run a representative subset of the
//! calendar client surface there (every kind of attendee, every change, every reply channel and every answer), and
//! `CONFORMANCE_FULL=1`, which the nightly run sets, runs all 45.

use std::io::Write as _;

use davhaven_testkit::StoreKind;
use davhaven_testkit::scheduling::OrganizerSurface;
use davhaven_testkit::scheduling::driver::{SurfaceReport, run_surface};

/// Five kinds of attendee and nine changes.
const CASES_PER_SURFACE: usize = 45;

fn assert_holds(surface: OrganizerSurface, store: StoreKind, report: &SurfaceReport) {
    drop(writeln!(
        std::io::stderr(),
        "the {surface} surface on {store}: {} cases ran, {} are not in the sample",
        report.ran,
        report.left_out
    ));
    // A case that differed while the application had answered that it was too busy (503) is run again on a new application; the
    // run names those cases, and many of them are not a busy host: a server that is unavailable now and then is a finding.
    if !report.reruns.is_empty() {
        drop(writeln!(
            std::io::stderr(),
            "{} cases were run again because the host was too busy:\n{}",
            report.reruns.len(),
            report.rerun_text()
        ));
    }
    assert!(
        !report.too_many_reruns(),
        "{} of {} cases of the {surface} surface were run again: the server is unavailable too often, which a busy host does not \
         explain:\n{}",
        report.reruns.len(),
        report.ran,
        report.rerun_text()
    );
    assert_eq!(
        report.ran + report.left_out,
        CASES_PER_SURFACE,
        "every case of the {surface} surface must run or be left out of the sample:\n{}",
        report.failure_text()
    );
    if store == StoreKind::Memory {
        assert_eq!(report.left_out, 0, "the memory store runs every case");
    }
    assert!(
        report.failures.is_empty(),
        "{} of {} cases of the {surface} surface differ from the decision table:\n{}",
        report.failures.len(),
        report.ran,
        report.failure_text()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_organizer_writes_with_a_calendar_client() {
    let report = run_surface(OrganizerSurface::Dav, StoreKind::Memory).await;
    assert_holds(OrganizerSurface::Dav, StoreKind::Memory, &report);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_organizer_writes_through_the_management_api() {
    let report = run_surface(OrganizerSurface::Api, StoreKind::Memory).await;
    assert_holds(OrganizerSurface::Api, StoreKind::Memory, &report);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_organizer_writes_through_an_mcp_tool() {
    let report = run_surface(OrganizerSurface::Mcp, StoreKind::Memory).await;
    assert_holds(OrganizerSurface::Mcp, StoreKind::Memory, &report);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_calendar_client_surface_holds_on_postgres() {
    if !davhaven_testkit::postgres::require_database() {
        return;
    }
    let report = run_surface(OrganizerSurface::Dav, StoreKind::Postgres).await;
    assert_holds(OrganizerSurface::Dav, StoreKind::Postgres, &report);
}
