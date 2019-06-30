

//! Async TLS streams
//!
#![feature(async_await, nll)]

#[macro_use]
extern crate log;
use pretty_env_logger::{try_init, try_init_timed};

mod errors;
mod server;
mod client;

#[cfg(test)]
mod tests {
    use super::*;
    use failure::Error;
    use pretty_env_logger::{try_init, try_init_timed};
    use runtime::net::tcp::{TcpListener, TcpStream};
    use bytes::{Bytes, BytesMut};
    use std::sync::Arc;
    use futures::StreamExt;
    use futures::io::AsyncReadExt;
    use futures::{FutureExt, TryFutureExt};

    #[runtime::test]
    async fn library_root_test() -> Result<(), Error> {
        try_init();

        Ok(())
    }
    
}
