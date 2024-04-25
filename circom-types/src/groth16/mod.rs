pub mod witness;

pub(crate) mod reader_utils {
    use std::{io, str::Utf8Error};

    use ark_serialize::Read;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum ParserError {
        #[error(transparent)]
        Utf8Error(#[from] Utf8Error),
        #[error(transparent)]
        IoError(#[from] io::Error),
        #[error("Wrong header. Expected {0} but got {1}")]
        WrongHeader(String, String),
    }

    pub(crate) fn read_header<R: Read>(
        mut reader: R,
        should_header: &str,
    ) -> Result<(), ParserError> {
        let mut buf = [0_u8; 4];
        reader.read_exact(&mut buf)?;
        let is_header = std::str::from_utf8(&buf[..])?;
        if is_header == should_header {
            Ok(())
        } else {
            Err(ParserError::WrongHeader(
                should_header.to_owned(),
                is_header.to_owned(),
            ))
        }
    }
}
