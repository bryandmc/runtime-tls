use failure::Fail;
use std::io::Error as IOError;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="Placeholder Error")]
    PlaceholderError,
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}
