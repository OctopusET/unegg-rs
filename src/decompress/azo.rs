use std::io::{Read, Write};

use crate::crypto::Decryptor;
use crate::error::{EggError, EggResult};

pub fn extract_azo<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    compressed_size: u64,
    crypto: Option<&mut dyn Decryptor>,
) -> EggResult<u32> {
    let mut decrypt_fn;
    let callback: Option<libazo::DecryptFn<'_>> = match crypto {
        Some(c) => {
            decrypt_fn = |data: &mut [u8]| c.decrypt(data);
            Some(&mut decrypt_fn)
        }
        None => None,
    };
    libazo::extract_azo(reader, writer, compressed_size, callback)
        .map_err(|e| EggError::AzoFailed(e.to_string()))
}
