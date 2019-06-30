use hashbrown::HashMap;
use rustls::{ClientConfig, ProtocolVersion, RootCertStore, AllowAnyAuthenticatedClient, NoClientAuth, StoresClientSessions};
use std::sync::{Arc, RwLock};
use std::io::BufReader;
use std::fs::File;
use crate::errors::Error;
use std::collections::HashSet;

#[derive(Debug)]
pub struct HashMapSessionStore(RwLock<HashMap<Vec<u8>, Vec<u8>>>);

impl HashMapSessionStore {
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


fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let keys = rustls::internal::pemfile::rsa_private_keys(&mut reader).unwrap();
    assert_eq!(keys.len(), 1);
    keys[0].clone()
}

fn load_key_and_cert(config: &mut ClientConfig, keyfile: &str, certsfile: &str) {
    let certs = load_certs(certsfile);
    let privkey = load_private_key(keyfile);
    config.set_single_client_cert(certs, privkey);
}


pub fn create_client_config(reader: &mut BufReader<File>) -> Result<Arc<ClientConfig>, Error> {
    let mut config = ClientConfig::new();
    config.versions = vec![ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2];
    let (added, _) = config.root_store.add_pem_file(reader)?;
    debug!("Added: {}", added);
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.ct_logs = Some(&ct_logs::LOGS);
    config.enable_tickets = false;
    config.enable_sni = false;
    let persist = Arc::new(HashMapSessionStore::new());
    Ok(Arc::new(config))
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
        let mut cert_file = BufReader::new(File::open("certs/localhost.crt")?);
        let conf = create_client_config(&mut cert_file);
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
