// Re-export modules needed by integration tests and external consumers.
//
// The binary entrypoint remains `main.rs`; this file simply provides a library
// target so that `tests/*.rs` integration tests can `use casdog::...`.

pub mod config;
pub mod diesel_pool;
pub mod error;
pub mod handlers;
pub mod hoops;
pub mod models;
pub mod routes;
pub mod schema;
pub mod services;
