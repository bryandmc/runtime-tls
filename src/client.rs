//! # Runtime-tls: Async/Await TLS/SSL streams
//!
//! Client TLS
//!

use hashbrown::HashMap;
use rustls::{ClientConfig, ProtocolVersion, RootCertStore, AllowAnyAuthenticatedClient, NoClientAuth, StoresClientSessions};
use std::sync::{Arc, RwLock};
use std::io::BufReader;
use std::fs::File;
use crate::errors::Error;
use std::collections::HashSet;
use std::rc::Rc;


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
//    let (added, _) = config.root_store.add_pem_file(reader)?;
//    debug!("Added: {}", added);
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.ct_logs = Some(&ct_logs::LOGS);
    config.enable_tickets = false;
    config.enable_sni = false;

    // Store session data
    config.set_persistence(persistence);
    Ok(config)
}

impl From<()> for Error {
    fn from(val: ()) -> Error {
        Error::PlaceholderError
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use pretty_env_logger::{try_init, try_init_timed};
    use failure::Error;
    use std::path::Prefix::Verbatim;


    #[runtime::test]
    async fn start_client() -> Result<(), Error> {
        try_init();

        Ok(())
    }

    #[test]
    fn create_config() -> Result<(), Error> {
        try_init();
        let x = HashMapSessionStore::new();
        let mut cert_file = BufReader::new(File::open("certs/localhost.crt")?);
        let conf = create_client_config(Arc::new(x));
        debug!("Output: {:?}", conf.unwrap().root_store);
        Ok(())
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
