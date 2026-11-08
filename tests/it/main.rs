//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`it::<name>::<test>`); `tests/unit` still holds the library's `#[path]` unit tests.
mod admission_v3;
mod balance;
mod beacon;
mod commit_guard;
mod common;
mod configuration;
mod credential_format;
mod current_admission;
mod database;
mod global_passport;
mod key_continuity;
mod membership_facts;
mod multiple_providers;
mod passkey_certificates;
mod policy;
mod presentation_requests;
mod root_board;
mod settlement_settings;
mod snapshot_boundaries;
mod storage_boundaries;
mod turso;
mod writer_reads;
