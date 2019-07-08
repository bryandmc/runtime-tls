//! # Runtime-tls: Async/Await TLS/SSL streams
//!
//! Client TLS
//!

use hashbrown::HashMap;
use rustls::{ClientConfig, ProtocolVersion, RootCertStore, AllowAnyAuthenticatedClient, NoClientAuth, StoresClientSessions, ClientSession};
use std::sync::{Arc, RwLock};
use std::io::{BufReader, Cursor};
use std::fs::File;
use crate::errors::Error;
use std::collections::HashSet;
use std::rc::Rc;
use bytes::{BytesMut, BufMut, Writer, Bytes, Reader};
use std::process::Output;
use std::future::Future;
use base64::{decode, encode};
use std::pin::Pin;
use futures::{AsyncWrite, AsyncRead};
use futures::io::{AsyncWriteExt, WriteAll, ReadUntil, ReadToEnd};
use rustls::Session;
use std::io::Write;
use futures::stream::IntoAsyncRead;


/// HashMapSessionStore - used as a session store for handling secure and sensitive session data. Backed by a
/// `hashbrown` hash map that's put inside a RwLock for thread safety.
/// # Examples
///
/// ```
/// # use std::sync::Arc;
/// # use rustls::StoresClientSessions;
/// # use crate::runtime_tls::client::HashMapSessionStore;
///
/// let store = HashMapSessionStore::new();
/// let key = vec![1 as u8];
/// let key_clone = key.clone();
/// let value = vec![1 as u8];
/// let previous = store.put(key, value);
/// let duplicate_value = store.get(&vec![1 as u8]).unwrap(); // duplicate_value == value
/// assert_eq!(key_clone, duplicate_value);
/// ```
///
#[derive(Debug)]
pub struct HashMapSessionStore(RwLock<HashMap<Vec<u8>, Vec<u8>>>);

/// HashMapSessionStore is a session store backed by hashbrown::HashMap<Vec<u8>, Vec<u8>>
impl HashMapSessionStore {

    /// Creates a new (empty) HashMapSessionStore. The data in this is considered extremely sensitive
    pub fn new() -> HashMapSessionStore {
        HashMapSessionStore(RwLock::new(HashMap::new()))
    }
}

impl StoresClientSessions for HashMapSessionStore {
    /// put: insert into in-memory cache, and perhaps persist to disk.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        if let Some(v) = self.0.write().unwrap().insert(key, value) {
            debug!("Previous value: {:?}", v);
        }
        true
    }

    /// get: from in-memory cache
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.read().unwrap().get(key).cloned()
    }
}


/// loads certificates from file, by name.
///
/// ### Example:
/// ```
/// use runtime_tls::client::load_certs;
/// let certs = load_certs("certs/localhost.crt");
/// ```
///
pub fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

/// loads certificates from file, by name.
///
/// ### Example:
/// ```
/// use runtime_tls::client::{load_private_key, load_key_and_cert, HashMapSessionStore, create_client_config};
/// use std::sync::Arc;
///
/// let cache = HashMapSessionStore::new();
/// let mut config = create_client_config(Arc::new(cache)).unwrap();
/// if let Err(e) = load_key_and_cert(&mut config, "certs/client/ca.key", "certs/client/ca.pem") {
///     panic!("failed to load client key or certs: {}", e); // failed...
/// }
/// // use `config` here...
/// ```
///
pub fn load_key_and_cert(config: &mut ClientConfig, keyfile: &str, certsfile: &str) -> Result<(), Error> {
    let certs = load_certs(certsfile);
    if let Some(private_key) = load_private_key(keyfile) {
        config.set_single_client_cert(certs, private_key);
        return Ok(());
    }
    Err(Error::PlaceholderError)
}

/// loads certificates from file, by name.
///
/// ### Example:
/// ```
/// use runtime_tls::client::load_private_key;
/// let key = load_private_key("certs/localhost.key");
/// ```
///
pub fn load_private_key(filename: &str) -> Option<rustls::PrivateKey> {
    let keyfile = File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader).unwrap();
    if keys.is_empty() {
        return None;
    }
    Some(keys[0].clone())
}


/// generates a rustls::ClientConfig which will usually be a single config for all client connections with the same
/// general settings.
///
/// ### Example:
/// ```
/// use runtime_tls::client::{create_client_config, HashMapSessionStore};
/// use std::io::BufReader;
/// use std::fs::File;
/// use std::sync::Arc;
///
/// let cache = HashMapSessionStore::new();
/// let config = create_client_config(Arc::new(cache)).unwrap();
/// ```
///
pub fn create_client_config<S>(persistence: Arc<S>) -> Result<ClientConfig, Error>
where
    S: StoresClientSessions + 'static
{
    let mut config = ClientConfig::new();
    config.versions = vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.ct_logs = Some(&ct_logs::LOGS);
    config.enable_tickets = false;
    config.enable_sni = true;

    // Store session data
    config.set_persistence(persistence);
    Ok(config)
}

impl From<()> for Error {
    fn from(val: ()) -> Error {
        Error::PlaceholderError
    }
}

trait TlsConnect {
    type ConnectFut;

    fn connect(&self) -> Self::ConnectFut;
    fn handle_handshake();
}

existential type ConnectionFuture<F>: Future<Output=Result<(), Error>>;

//existential type Foo<T>: Default;
fn connect_future<F: Future<Output=Result<(), Error>>>(f: F) -> ConnectionFuture<F> {
    f
}

impl<F> TlsConnect for TlsConnector<F> {
    type ConnectFut = Box<Future<Output=()>>;

    fn connect(&self) -> Self::ConnectFut {
        unimplemented!()
    }

    fn handle_handshake() {
        unimplemented!()
    }
}

/// The TlsWrite trait. It should be generalized for all writes on a tls session, but can also be
/// used during the handshake portion.
///
/// ```
///
/// ```
///
trait TlsWrite {
    fn try_write<'a, A: AsyncWrite + Unpin, S: Session>(&'a mut self, client: &mut S, writer: &'a mut A) -> Result<WriteAll<A>, Error>;
}

pub struct RustlsWrite(Writer<BytesMut>);

impl TlsWrite for RustlsWrite {
    fn try_write<'a, A, S>(&'a mut self, client: &mut S, writer: &'a mut A) -> Result<WriteAll<A>, Error>
    where
        A: AsyncWrite + Unpin,
        S: Session
    {
        if client.wants_write() {
            let res = client.write_tls(&mut self.0)?;
            debug!("wrote {} bytes to tls client cursor_writesession.", res);
            trace!("buffer value: {:?}", String::from_utf8_lossy(self.0.get_ref()));
            return Ok(writer.write_all(self.0.get_ref()));
        }
        Err(Error::PlaceholderError)
    }
}

trait TlsRead {
    fn try_read<A: AsyncRead + Unpin, S: Session>(&self, client: &S) -> Result<ReadToEnd<A>, Error>;
}

pub struct RustlsRead(Reader<Bytes>);

impl TlsRead for RustlsRead {
    fn try_read<A: AsyncRead + Unpin, S: Session>(&self, client: &S) -> Result<ReadToEnd<A>, Error> {
        unimplemented!()
    }
}

pub struct TlsConnector<F> {
    config: Arc<ClientConfig>,
    cursor: Cursor<Vec<u8>>,
    b: BytesMut,
    session: ClientSession,
    conn_fut: ConnectionFuture<F>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Cursor, Write};
    use pretty_env_logger::{try_init, try_init_timed};
    use failure::Error;
    use std::net::ToSocketAddrs;
    use rustls::Session;
    use futures::io::AsyncReadExt;
    use futures::io::AsyncWriteExt;
    use futures::io::WriteAll;
    use futures::AsyncWrite;
    use runtime::net::tcp::TcpStream;

    #[runtime::test]
    async fn start_client() -> Result<(), Error> {
        try_init();

        Ok(())
    }

    #[runtime::test]
    async fn tls_write_test() -> Result<(), Error> {
        let mut r_write = RustlsWrite(BytesMut::with_capacity(1024).writer());
        let google_com = webpki::DNSNameRef::try_from_ascii_str("google.com").unwrap();
        dbg!(&google_com);
        let x = HashMapSessionStore::new();
        let conf = create_client_config(Arc::new(x))?;
        let rc_config = Arc::new(conf);
        let mut client = rustls::ClientSession::new(&rc_config, google_com);
        let mut sock: TcpStream = TcpStream::connect("google.com:443".to_socket_addrs().unwrap().next().unwrap()).await?;

        let res = r_write.try_write(&mut client, &mut sock)?.await?;
        dbg!(res);

//        let res2 =  r_write.try_write(&mut client, &mut sock)?.await?;
//        dbg!(res2);
        Ok(())
    }

    #[runtime::test]
    async fn create_config() -> Result<(), Error> {
        try_init();
        let x = HashMapSessionStore::new();
        let mut cert_file = BufReader::new(File::open("certs/localhost.crt")?);
        let mut conf = create_client_config(Arc::new(x))?;

        let certs_chain = load_certs("certs/client/ca.pem");
        let private_key = load_private_key("certs/client/ca.key").unwrap();
        let mut sock: TcpStream = TcpStream::connect("google.com:443".to_socket_addrs().unwrap().next().unwrap()).await?;
        dbg!(&sock);
        let google_com = webpki::DNSNameRef::try_from_ascii_str("google.com").unwrap();
        dbg!(&google_com);
        let rc_config = Arc::new(conf);
        let mut client = rustls::ClientSession::new(&rc_config, google_com);

        let write_block = client.write(b"GET / HTTP/1.0\r\n\r\n")?;
        info!("client.write(): {}", write_block);
        for i in 0..10 {
            if client.wants_write() {
                info!("wanted write!");
                let mut buf = Vec::with_capacity(1024);
                let mut cursor = Cursor::new(buf);
                let res = client.write_tls(&mut cursor)?;
                debug!("write_tls(): {}", res);
                let mut buf = cursor.into_inner();
                debug!("cursor_write: {:?}", String::from_utf8_lossy(&buf));
                let sock_write: () = sock.write_all(&mut buf[..]).await?;

                debug!("after sock.write_all");
            }

            if client.wants_read() {
                info!("wanted read!");
                let mut buf = Vec::with_capacity(1024);
                let sock_read = sock.read_to_end(&mut buf).await?;
                debug!("read_to_end(): {:?}", encode(&buf));

                let mut cursor = Cursor::new(buf);
                let res = client.read_tls(&mut cursor)?;
                debug!("read_tls: {}", res);
                debug!("read_tls(): {:?}", encode(&cursor.into_inner()));

                client.process_new_packets()?;

                let mut outbuf = vec![];
                let read_plaintext = client.read_to_end(&mut outbuf)?;
                debug!("plaintext[{}]: {:?}", read_plaintext, &outbuf);
            }

            if !client.is_handshaking() {
                info!("Finished handshake!!!!");
                let ciphers = client.get_negotiated_ciphersuite();
                debug!("ciphersuites: {:?}", ciphers);
                let server_cert = client.get_peer_certificates();
                debug!("server cert-chain: {:?}", server_cert);
                let version = client.get_protocol_version();
                debug!("running TLS version: {:?}", version);
                return Ok(());
            }
        }


        dbg!(&client);
        Ok(())
    }

    #[test]
    fn test_dns_lookup() {
        try_init();
        let res = "google.com:80".to_socket_addrs().unwrap().next().unwrap();
        info!("DNS: {:?}", res);
    }

    #[test]
    fn test_client_session_store() {
        try_init();
        let x = HashMapSessionStore::new();
        let a = vec![1 as u8];
        let b = vec![1 as u8];
        let y = x.put(a, b);
        info!("HashMapSessionStore: {:?}", x);
        info!("Stored?: {}", y);

        let w = x.get(&vec![1]);
        debug!("HashMapSessionStore: {:?}", w);

        let c = x.put(vec![1, 2, 3], vec![1, 2, 3]);
        debug!("Was found? {}", c);
        debug!("HashMapSessionStore: {:?}", x);
    }

}
