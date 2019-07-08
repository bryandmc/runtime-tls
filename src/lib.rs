//! # Runtime-tls: Async/Await TLS/SSL streams
//!
//! Async TLS streams
//!
#![feature(async_await, existential_type, arbitrary_self_types, pin)]

#[macro_use]
extern crate log;
use pretty_env_logger::{try_init, try_init_timed};

mod errors;
mod server;
pub mod client;

#[cfg(test)]
mod tests {
    use super::*;
    use failure::Error;
    use pretty_env_logger::{try_init, try_init_timed};

    #[runtime::test]
    async fn library_root_test() -> Result<(), Error> {
        try_init();

        Ok(())
    }
    
}
