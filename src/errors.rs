use failure::Fail;
use std::io::Error as IOError;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="Placeholder Error")]
    PlaceholderError,
    #[fail(display="Could not find private key in the provided file")]
    NoPrivateKeyFoundError,

    #[fail(display="Std::io error has occurred.")]
    StdIOError(IOError)
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}

impl From<IOError> for Error {
    fn from(io_err: IOError) -> Self {
        Error::StdIOError(io_err)
    }
}