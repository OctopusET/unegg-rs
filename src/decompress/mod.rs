pub mod azo;
pub mod bzip2;
pub mod deflate;
pub mod lzma;
pub mod store;

use std::io::Cursor;

use crate::archive::CompressionMethod;
use crate::error::{EggError, EggResult};

/// Decompress a solid stream (concatenated compressed data from all blocks).
/// Returns the full uncompressed output.
pub fn decompress_solid(method: CompressionMethod, data: &[u8]) -> EggResult<Vec<u8>> {
    match method {
        CompressionMethod::Store => Ok(data.to_vec()),
        CompressionMethod::Deflate => {
            let mut output = Vec::new();
            let mut cursor = Cursor::new(data);
            deflate::extract_deflate(&mut cursor, &mut output, data.len() as u64, None)?;
            Ok(output)
        }
        CompressionMethod::Bzip2 => {
            let mut output = Vec::new();
            let mut cursor = Cursor::new(data);
            bzip2::extract_bzip2(&mut cursor, &mut output, data.len() as u64, None)?;
            Ok(output)
        }
        CompressionMethod::Lzma => {
            let mut output = Vec::new();
            let mut cursor = Cursor::new(data);
            lzma::extract_lzma(&mut cursor, &mut output, data.len() as u64, None)?;
            Ok(output)
        }
        CompressionMethod::Azo => {
            let mut output = Vec::new();
            let mut cursor = Cursor::new(data);
            azo::extract_azo(&mut cursor, &mut output, data.len() as u64, None)?;
            Ok(output)
        }
        CompressionMethod::Unknown(n) => Err(EggError::UnknownCompressionMethod(n)),
    }
}
