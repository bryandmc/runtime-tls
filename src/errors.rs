use failure::Fail;
use std::io::Error as IOError;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="Placeholder Error")]
    PlaceholderError,
    #[fail(display="Could not find private key in the provided file")]
    NoPrivateKeyFoundError,
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}
