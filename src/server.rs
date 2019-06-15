use super::*;
use std::fmt::Display;
use std::net::SocketAddr;

use failure::{Error, Fail};
use futures::prelude::*;
use futures::stream::StreamExt;
use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession};
use std::fmt::Debug;
use std::fs;
use std::io;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use rustls::internal::pemfile;
use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
    RootCertStore, Session,
};

use runtime::net::{TcpListener, TcpStream};

#[derive(Clone)]
struct TlsServerConfig(ServerConfig);

#[derive(Debug)]
pub struct TlsTcpListener {
    stream: TcpStream,
    session: ServerSession,
    // config: Arc<TlsServerConfig>,
    state: TlsState,
}

#[allow(clippy::never_loop)]
impl TlsTcpListener {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> Result<TlsTcpListener, Error> {
        for a in addr.to_socket_addrs()? {
            let stream = TcpStream::connect(a).await?;
            return Ok(TlsTcpListener {
                session: ServerSession::new(&Arc::new(ServerConfig::new(NoClientAuth::new()))),
                state: TlsState::Stream,
                stream,
            });
        }
        Err(std::io::Error::new(std::io::ErrorKind::Other, "oh noooo").into())
    }

    pub fn incoming(&mut self) -> TlsIncoming<'_> {
        TlsIncoming { inner: self }
    }

    pub fn accept(&mut self) -> TlsAccept {
        let incoming = self.incoming();
        TlsAccept { inner: incoming }
    }
}

pub struct TlsIncoming<'incoming> {
    inner: &'incoming mut TlsTcpListener,
}

pub struct TlsAccept<'stream> {
    inner: TlsIncoming<'stream>,
}

pub enum TlsConfig {
    Client(Arc<ClientConfig>),
    Server(Arc<ServerConfig>),
}

pub struct TlsConnect<T, F> 
where
    F: Future<Output=T>,
{
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    session: Option<ClientSession>,
    future: Option<F>,
}

impl<T, F> Future for TlsConnect<T, F> 
where
    F: Future<Output=T>
{
    type Output = Result<TcpStream, TlsTcpError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // runtime::net::Connect.
        // let conn_future = TcpStream::connect(self.addr).poll();
        Poll::Pending
    }
}

pub enum TlsSession {
    Client(ClientSession),
    Server(ServerSession),
}

pub struct TlsTcpStream {
    config: TlsConfig,
    session: TlsSession,
    stream: TcpStream,
}

#[derive(Debug, Fail)]
pub enum TlsTcpError {
    ParseAsciiError(&'static str),
    PemParseError(String),
    OpenPemFileError(std::io::Error),
}

impl Display for TlsTcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "({:?})", self)
    }
}

impl std::convert::From<()> for server::TlsTcpError {
    fn from(t: ()) -> Self {
        TlsTcpError::ParseAsciiError("unable to parse DNSNameRef from ascii")
    }
}

impl TlsTcpStream {
    pub fn connect<A, T, F>(addr: A, config: Arc<ClientConfig>) -> Result<TlsConnect<T, F>, TlsTcpError>
    where
        A: ToSocketAddrs,
        F: Future<Output=T>
    {
        let localhost = webpki::DNSNameRef::try_from_ascii_str("localhost")?;
        let mut session = ClientSession::new(&config, localhost);
        Ok(TlsConnect {
            // TODO: revisit a better/safer way to get the first element instead of indexing
            addr: addr.to_socket_addrs()?.take(1).collect::<Vec<SocketAddr>>()[0],
            config,
            session: Some(session),
            future: None,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.stream.shutdown(how)
    }
}

// impl Future for TlsTcpStream {
//     type Output = Result<TlsConnect<>, ()>;

//     fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
//         Poll::Ready(Err(()))
//     }
// }

// impl<'stream> Stream for TlsIncoming<'>stream> {
//     type Item = &'stream TcpStream;

//     fn poll_next(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         let inner = &self.get_mut().inner;
//         Poll::Ready(Some(&inner.stream))
//     }
// }
impl std::convert::From<std::io::Error> for TlsTcpError {
    fn from(t: std::io::Error) -> Self {
        TlsTcpError::OpenPemFileError(t)
    }
}

pub fn load_certs(filename: &str) -> Result<Vec<rustls::Certificate>, TlsTcpError> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    pemfile::certs(&mut reader)
        .map_err(|e| TlsTcpError::PemParseError(format!("could not parse: {}", filename)))
}

impl Debug for TlsServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Suite: {:?}, Mtu: {:?}", self.0.ciphersuites, self.0.mtu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use failure::Error;
    use futures::future::lazy;
    use futures::io::ReadHalf;
    use futures::io::WriteHalf;
    use futures::stream::Stream;
    use futures::stream::StreamExt;
    use runtime::net::tcp::{TcpListener, TcpStream};

    #[test]
    fn test_simple_rustls_blocking_client() {
        let mut config = rustls::ClientConfig::new();
        let rc_config = Arc::new(config);
        let example_com = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
        let mut client = rustls::ClientSession::new(&rc_config, example_com);

        // client.write(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        // let mut socket = connect("example.com", 443);
        // loop {
        //     if client.wants_read() && socket.ready_for_read() {
        //         client.read_tls(&mut socket).unwrap();
        //         client.process_new_packets().unwrap();

        //         let mut plaintext = Vec::new();
        //         client.read_to_end(&mut plaintext).unwrap();
        //         io::stdout().write(&plaintext).unwrap();
        //     }

        //     if client.wants_write() && socket.ready_for_write() {
        //         client.write_tls(&mut socket).unwrap();
        //     }

        //     socket.wait_for_something_to_happen();
        // }
    }

    #[runtime::test]
    async fn it_works() -> Result<(), Error> {
        let mut x = TcpListener::bind("127.0.0.1:8000").unwrap();
        let y = x.incoming();
        while let Some(Ok(stream)) = y.next().await {
            let (r, w) = stream.split();
        }

        let mut tls = TlsTcpListener::bind("127.0.0.1:7000").await?;
        let inc = tls.incoming();
        // while let Some(stream) = inc.next().await {
        //     let (r, w): (ReadHalf<_>, WriteHalf<_>) = stream.split();

        // }

        lazy(|x| Ok(assert_eq!(2 + 2, 4))).await
    }
}
