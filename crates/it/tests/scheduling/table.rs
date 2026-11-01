//! The decision table of the scheduling matrix lives in `davhaven_testkit::scheduling::table`, where the driver that talks
//! HTTP uses it too (PLAN 2.8 and 3.3 in executable form, written from the rules of the plan and the iTIP golden set and
//! knowing nothing of the application). This module is the name the driver of this binary imports it under.

pub(crate) use davhaven_testkit::scheduling::table::{Expected, expected, partstat_of};
