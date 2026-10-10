//! litebox-organelle-host as a library.
//!
//! The binary (`src/main.rs`) keeps its own module tree untouched (it is
//! mid-hardening by a separate coordinator — see organelles/MAPPING.md).
//! This lib target re-exports the same sandbox modules so the organelle
//! trait impl (`organelle_impl`) and the integration tests can link against
//! them without refactoring `main.rs`.

pub mod guest;
pub mod manifest;
pub mod organelle_impl;
pub mod receipt;
pub mod sandbox;
pub mod syscalls;
pub mod tarball;
