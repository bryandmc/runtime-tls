#![feature(async_await)]

pub mod server;

#[derive(Debug, Copy, Clone)]
pub enum TlsState {
    EarlyData,
    Stream,
    ReadShutdown,
    WriteShutdown,
    FullyShutdown,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
