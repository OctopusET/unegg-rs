use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::aes_ctr::AesCtrDecryptor;
use crate::archive::{CompressionMethod, EggArchive, EggBlock, EggFileEntry, EncryptionMethod};
use crate::crypto::{Decryptor, ZipCrypto};
use crate::decompress;
use crate::error::{EggError, EggResult};
use crate::lea::LeaCtrDecryptor;

fn setup_decryptor(
    entry: &EggFileEntry,
    password: Option<&str>,
) -> EggResult<Option<Box<dyn Decryptor>>> {
    let ei = match entry.encrypt_info {
        Some(ref ei) => ei,
        None => return Ok(None),
    };
    let pwd = password.ok_or(EggError::PasswordNotSet)?;
    match ei.method {
        EncryptionMethod::ZipCrypto => {
            let mut zc = ZipCrypto::new(pwd.as_bytes());
            if ei.data.len() < 16 {
                return Err(EggError::CorruptedFile);
            }
            let verify: [u8; 12] = ei.data[..12].try_into().unwrap();
            let stored_crc = u32::from_le_bytes(ei.data[12..16].try_into().unwrap());
            if !zc.check_password(&verify, stored_crc) {
                return Err(EggError::InvalidPassword);
            }
            Ok(Some(Box::new(zc)))
        }
        EncryptionMethod::Aes128 => {
            let (salt_size, mode) = (8, 1);
            if ei.data.len() < salt_size + 2 {
                return Err(EggError::CorruptedFile);
            }
            let salt = &ei.data[..salt_size];
            let verifier: [u8; 2] = ei.data[salt_size..salt_size + 2].try_into().unwrap();
            Ok(Some(Box::new(AesCtrDecryptor::new(
                mode, pwd, salt, &verifier,
            )?)))
        }
        EncryptionMethod::Aes256 => {
            let (salt_size, mode) = (16, 3);
            if ei.data.len() < salt_size + 2 {
                return Err(EggError::CorruptedFile);
            }
            let salt = &ei.data[..salt_size];
            let verifier: [u8; 2] = ei.data[salt_size..salt_size + 2].try_into().unwrap();
            Ok(Some(Box::new(AesCtrDecryptor::new(
                mode, pwd, salt, &verifier,
            )?)))
        }
        EncryptionMethod::Lea128 => {
            let (salt_size, mode) = (8, 1);
            if ei.data.len() < salt_size + 2 {
                return Err(EggError::CorruptedFile);
            }
            let salt = &ei.data[..salt_size];
            let verifier: [u8; 2] = ei.data[salt_size..salt_size + 2].try_into().unwrap();
            Ok(Some(Box::new(LeaCtrDecryptor::new(
                mode, pwd, salt, &verifier,
            )?)))
        }
        EncryptionMethod::Lea256 => {
            let (salt_size, mode) = (16, 3);
            if ei.data.len() < salt_size + 2 {
                return Err(EggError::CorruptedFile);
            }
            let salt = &ei.data[..salt_size];
            let verifier: [u8; 2] = ei.data[salt_size..salt_size + 2].try_into().unwrap();
            Ok(Some(Box::new(LeaCtrDecryptor::new(
                mode, pwd, salt, &verifier,
            )?)))
        }
        EncryptionMethod::Unknown(n) => Err(EggError::UnsupportedEncryption(n)),
    }
}

pub fn extract_entry<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    entry: &EggFileEntry,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
) -> EggResult<()> {
    if entry.file_name.contains("../") || entry.file_name.contains("..\\") {
        return Err(EggError::PathTraversal(entry.file_name.clone()));
    }

    if entry.is_directory() {
        if !pipe_mode {
            let dir_path = dest_dir.join(&entry.file_name);
            fs::create_dir_all(&dir_path).map_err(EggError::CantOpenDestFile)?;
        }
        return Ok(());
    }

    if entry.uncompressed_size == 0 && entry.blocks.is_empty() {
        if !pipe_mode {
            let file_path = dest_dir.join(&entry.file_name);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).map_err(EggError::CantOpenDestFile)?;
            }
            fs::File::create(&file_path).map_err(EggError::CantOpenDestFile)?;
        }
        return Ok(());
    }

    let mut crypto = setup_decryptor(entry, password)?;

    let mut writer: Box<dyn Write> = if pipe_mode {
        Box::new(io::stdout())
    } else {
        let file_path = dest_dir.join(&entry.file_name);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).map_err(EggError::CantOpenDestFile)?;
        }
        Box::new(fs::File::create(&file_path).map_err(EggError::CantOpenDestFile)?)
    };

    for block in &entry.blocks {
        archive.reader.seek(SeekFrom::Start(block.data_pos))?;
        let mut bounded = (&mut archive.reader).take(block.compressed_size as u64);

        let crypto_ref = crypto.as_mut().map(|c| &mut **c as &mut dyn Decryptor);
        let crc = decompress_block(&mut bounded, &mut writer, block, crypto_ref)?;

        if crc != block.crc32 {
            return Err(EggError::InvalidFileCrc {
                expected: block.crc32,
                got: crc,
            });
        }
    }

    drop(writer);

    if !pipe_mode && let Some(ft) = entry.file_time {
        set_file_time(dest_dir.join(&entry.file_name).as_path(), ft);
    }

    Ok(())
}

pub fn extract_all<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
) -> EggResult<()> {
    let entries: Vec<EggFileEntry> = archive.entries.clone();
    if archive.is_solid {
        extract_all_solid(archive, &entries, dest_dir, password, pipe_mode, None)
    } else {
        for entry in &entries {
            extract_entry(archive, entry, dest_dir, password, pipe_mode)?;
        }
        Ok(())
    }
}

pub fn extract_files<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
    files: &[String],
) -> EggResult<()> {
    let entries: Vec<EggFileEntry> = archive.entries.clone();
    if archive.is_solid {
        extract_all_solid(
            archive,
            &entries,
            dest_dir,
            password,
            pipe_mode,
            Some(files),
        )
    } else {
        for entry in &entries {
            if files.iter().any(|f| entry.file_name.contains(f.as_str())) {
                extract_entry(archive, entry, dest_dir, password, pipe_mode)?;
            }
        }
        Ok(())
    }
}

/// Solid archive extraction: decompress all blocks as one continuous stream,
/// then distribute output to individual files.
fn extract_all_solid<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    entries: &[EggFileEntry],
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
    filter: Option<&[String]>,
) -> EggResult<()> {
    // Track blocks with their parent file index
    struct SolidBlock {
        file_idx: usize,
        uncompressed_size: u32,
        compressed_size: u32,
        crc32: u32,
        data_pos: u64,
    }

    let mut solid_blocks: Vec<SolidBlock> = Vec::new();

    for (fi, entry) in entries.iter().enumerate() {
        // Create directories regardless of filter (needed for file paths)
        if entry.is_directory() {
            if !pipe_mode {
                if entry.file_name.contains("../") || entry.file_name.contains("..\\") {
                    return Err(EggError::PathTraversal(entry.file_name.clone()));
                }
                let dir_path = dest_dir.join(&entry.file_name);
                fs::create_dir_all(&dir_path).map_err(EggError::CantOpenDestFile)?;
            }
            continue;
        }

        for block in &entry.blocks {
            solid_blocks.push(SolidBlock {
                file_idx: fi,
                uncompressed_size: block.uncompressed_size,
                compressed_size: block.compressed_size,
                crc32: block.crc32,
                data_pos: block.data_pos,
            });
        }
    }

    if solid_blocks.is_empty() {
        return Ok(());
    }

    // Read and decrypt all compressed data, maintaining per-file decryptor state
    let mut all_compressed = Vec::new();
    let mut current_file_idx = usize::MAX;
    let mut crypto: Option<Box<dyn Decryptor>> = None;

    for sb in &solid_blocks {
        if sb.file_idx != current_file_idx {
            current_file_idx = sb.file_idx;
            crypto = setup_decryptor(&entries[sb.file_idx], password)?;
        }

        archive.reader.seek(SeekFrom::Start(sb.data_pos))?;
        let mut buf = vec![0u8; sb.compressed_size as usize];
        archive.reader.read_exact(&mut buf)?;

        if let Some(ref mut c) = crypto {
            c.decrypt(&mut buf);
        }

        all_compressed.extend_from_slice(&buf);
    }

    // Decompress the entire stream at once
    let method = entries
        .iter()
        .flat_map(|e| e.blocks.iter())
        .next()
        .map(|b| b.compression_method)
        .unwrap_or(CompressionMethod::Store);

    let all_output = decompress::decompress_solid(method, &all_compressed)?;

    // Distribute output to files, verify per-block CRC
    let mut offset = 0;
    let mut current_file_idx = usize::MAX;
    let mut writer: Option<Box<dyn Write>> = None;

    for sb in &solid_blocks {
        // Open new file when file index changes
        if sb.file_idx != current_file_idx {
            drop(writer.take());
            current_file_idx = sb.file_idx;
            let entry = &entries[sb.file_idx];

            if should_extract(entry, filter) {
                if entry.file_name.contains("../") || entry.file_name.contains("..\\") {
                    return Err(EggError::PathTraversal(entry.file_name.clone()));
                }

                writer = if pipe_mode {
                    Some(Box::new(io::stdout()))
                } else {
                    let file_path = dest_dir.join(&entry.file_name);
                    if let Some(parent) = file_path.parent() {
                        fs::create_dir_all(parent).map_err(EggError::CantOpenDestFile)?;
                    }
                    Some(Box::new(
                        fs::File::create(&file_path).map_err(EggError::CantOpenDestFile)?,
                    ))
                };
            } else {
                writer = None;
            }
        }

        let end = offset + sb.uncompressed_size as usize;
        if end > all_output.len() {
            return Err(EggError::CorruptedFile);
        }
        let chunk = &all_output[offset..end];

        let crc = crc32fast::hash(chunk);
        if crc != sb.crc32 {
            return Err(EggError::InvalidFileCrc {
                expected: sb.crc32,
                got: crc,
            });
        }

        if let Some(ref mut w) = writer {
            w.write_all(chunk)?;
        }

        offset = end;
    }

    drop(writer);

    // Set file times
    if !pipe_mode {
        for entry in entries {
            if should_extract(entry, filter)
                && !entry.is_directory()
                && let Some(ft) = entry.file_time
            {
                set_file_time(dest_dir.join(&entry.file_name).as_path(), ft);
            }
        }
    }

    Ok(())
}

fn should_extract(entry: &EggFileEntry, filter: Option<&[String]>) -> bool {
    match filter {
        None => true,
        Some(files) => files.iter().any(|f| entry.file_name.contains(f.as_str())),
    }
}

fn decompress_block<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    block: &EggBlock,
    crypto: Option<&mut dyn Decryptor>,
) -> EggResult<u32> {
    match block.compression_method {
        CompressionMethod::Store => {
            decompress::store::extract_store(reader, writer, block.compressed_size as u64, crypto)
        }
        CompressionMethod::Deflate => decompress::deflate::extract_deflate(
            reader,
            writer,
            block.compressed_size as u64,
            crypto,
        ),
        CompressionMethod::Bzip2 => {
            decompress::bzip2::extract_bzip2(reader, writer, block.compressed_size as u64, crypto)
        }
        CompressionMethod::Lzma => {
            decompress::lzma::extract_lzma(reader, writer, block.compressed_size as u64, crypto)
        }
        CompressionMethod::Azo => {
            decompress::azo::extract_azo(reader, writer, block.compressed_size as u64, crypto)
        }
        CompressionMethod::Unknown(n) => Err(EggError::UnknownCompressionMethod(n)),
    }
}

/// Convert Windows FILETIME to Unix timestamp and set file mtime.
fn set_file_time(path: &Path, filetime_val: u64) {
    const EPOCH_DIFF: u64 = 11644473600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    if filetime_val < EPOCH_DIFF * TICKS_PER_SEC {
        return;
    }

    let unix_secs = (filetime_val / TICKS_PER_SEC).saturating_sub(EPOCH_DIFF);
    let nanos = ((filetime_val % TICKS_PER_SEC) * 100) as u32;
    let ft = filetime::FileTime::from_unix_time(unix_secs as i64, nanos);
    let _ = filetime::set_file_mtime(path, ft);
}
