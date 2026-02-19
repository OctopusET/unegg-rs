use std::io::{Cursor, Read, Write};

use crate::crypto::Decryptor;
use crate::error::{EggError, EggResult};

pub fn extract_lzma<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    compressed_size: u64,
    mut crypto: Option<&mut dyn Decryptor>,
) -> EggResult<u32> {
    if compressed_size < 9 {
        return Err(EggError::LzmaFailed(
            "block too small for LZMA header".into(),
        ));
    }

    // Read EGG's 9-byte LZMA header
    let mut header = [0u8; 9];
    reader.read_exact(&mut header)?;
    if let Some(ref mut c) = crypto {
        c.decrypt(&mut header);
    }

    // Bytes 0..4: reserved (discard)
    // Bytes 4..9: LZMA properties
    let lzma_props = &header[4..9];

    // Read remaining compressed data
    let data_size = compressed_size - 9;
    let mut compressed_data = vec![0u8; data_size as usize];
    reader.read_exact(&mut compressed_data)?;
    if let Some(ref mut c) = crypto {
        c.decrypt(&mut compressed_data);
    }

    // Build standard LZMA header: 5 props + 8 bytes uncompressed size (-1 = unknown)
    let mut full_stream = Vec::with_capacity(13 + compressed_data.len());
    full_stream.extend_from_slice(lzma_props);
    full_stream.extend_from_slice(&u64::MAX.to_le_bytes());
    full_stream.extend_from_slice(&compressed_data);

    let mut cursor = Cursor::new(full_stream);
    let mut output = Vec::new();
    lzma_rs::lzma_decompress(&mut cursor, &mut output)
        .map_err(|e| EggError::LzmaFailed(e.to_string()))?;

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&output);
    writer.write_all(&output)?;

    Ok(hasher.finalize())
}
