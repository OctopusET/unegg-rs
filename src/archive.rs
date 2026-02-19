use std::io::{self, Read, Seek, SeekFrom};

use crate::encoding;
use crate::error::{EggError, EggResult};

// Signatures
const SIG_EGG_HEADER: u32 = 0x41474745;
const SIG_SPLIT_INFO: u32 = 0x24F5A262;
const SIG_SOLID_INFO: u32 = 0x24E5A060;
const SIG_FILE_HEADER: u32 = 0x0A8590E3;
const SIG_FILENAME: u32 = 0x0A8591AC;
const SIG_COMMENT: u32 = 0x04C63672;
const SIG_WINDOWS_FILE_INFO: u32 = 0x2C86950B;
const SIG_ENCRYPT_INFO: u32 = 0x08D1470F;
const SIG_BLOCK_HEADER: u32 = 0x02B50C13;
const SIG_DUMMY: u32 = 0x07463307;
const SIG_END_MARKER: u32 = 0x08E28222;
const SIG_SKIP: u32 = 0xFFFF0000;
const SIG_GLOBAL_ENCRYPT: u32 = 0x08D144A8;
const SIG_POSIX_FILE_INFO: u32 = 0x1EE922E5;

pub const ATTR_DIRECTORY: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Store,
    Deflate,
    Bzip2,
    Azo,
    Lzma,
    Unknown(u8),
}

impl CompressionMethod {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Store,
            1 => Self::Deflate,
            2 => Self::Bzip2,
            3 => Self::Azo,
            4 => Self::Lzma,
            n => Self::Unknown(n),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Store => "Store",
            Self::Deflate => "Deflate",
            Self::Bzip2 => "Bzip2",
            Self::Azo => "AZO",
            Self::Lzma => "LZMA",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl std::fmt::Display for CompressionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    ZipCrypto,
    Aes128,
    Aes256,
    Lea128,
    Lea256,
    Unknown(u8),
}

impl EncryptionMethod {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::ZipCrypto,
            1 => Self::Aes128,
            2 => Self::Aes256,
            5 => Self::Lea128,
            6 => Self::Lea256,
            n => Self::Unknown(n),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ZipCrypto => "ZipCrypto",
            Self::Aes128 => "AES-128",
            Self::Aes256 => "AES-256",
            Self::Lea128 => "LEA-128",
            Self::Lea256 => "LEA-256",
            Self::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptInfo {
    pub method: EncryptionMethod,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EggBlock {
    pub compression_method: CompressionMethod,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub crc32: u32,
    pub data_pos: u64,
}

#[derive(Debug, Clone)]
pub struct EggFileEntry {
    pub file_name: String,
    pub file_id: u32,
    pub uncompressed_size: u64,
    pub blocks: Vec<EggBlock>,
    pub encrypt_info: Option<EncryptInfo>,
    pub file_time: Option<u64>,
    pub file_attr: u8,
}

impl EggFileEntry {
    pub fn is_directory(&self) -> bool {
        self.file_attr & ATTR_DIRECTORY != 0
    }
}

pub struct SplitInfo {
    pub prev_id: u32,
    pub next_id: u32,
}

pub struct EggArchive<R: Read + Seek> {
    pub reader: R,
    pub entries: Vec<EggFileEntry>,
    pub is_encrypted: bool,
    pub is_solid: bool,
    pub header_id: u32,
    pub split_info: Option<SplitInfo>,
}

impl<R: Read + Seek> EggArchive<R> {
    pub fn open(mut reader: R) -> EggResult<Self> {
        // Read EGG Header signature
        let sig = read_u32(&mut reader)?;
        if sig != SIG_EGG_HEADER {
            return Err(EggError::NotEggFile);
        }

        let _version = read_u16(&mut reader)?;
        let header_id = read_u32(&mut reader)?;
        let _reserved = read_u32(&mut reader)?;

        let mut is_solid = false;
        let mut split_info = None;
        let mut is_encrypted = false;
        let mut entries = Vec::new();

        // Parse prefix section until End Marker
        loop {
            let sig = read_u32(&mut reader)?;
            match sig {
                SIG_SPLIT_INFO => {
                    let (_flags, _size) = read_extra_field(&mut reader)?;
                    let prev_id = read_u32(&mut reader)?;
                    let next_id = read_u32(&mut reader)?;
                    split_info = Some(SplitInfo { prev_id, next_id });
                }
                SIG_SOLID_INFO => {
                    let (_flags, size) = read_extra_field(&mut reader)?;
                    skip(&mut reader, size as u64)?;
                    is_solid = true;
                }
                SIG_SKIP => {
                    let (_flags, _size) = read_extra_field(&mut reader)?;
                    let _prev_id = read_u32(&mut reader)?;
                    let _next_id = read_u32(&mut reader)?;
                }
                SIG_GLOBAL_ENCRYPT => {
                    let (_flags, size) = read_extra_field(&mut reader)?;
                    skip(&mut reader, size as u64)?;
                }
                SIG_END_MARKER => break,
                _ => return Err(EggError::CorruptedFile),
            }
        }

        // Parse file entries
        loop {
            let sig = read_u32(&mut reader)?;
            match sig {
                SIG_FILE_HEADER => {
                    let entry = parse_file_entry(&mut reader, &mut is_encrypted)?;
                    entries.push(entry);
                }
                SIG_COMMENT => {
                    // Archive-level comment, skip it
                    let (_flags, size) = read_extra_field(&mut reader)?;
                    skip(&mut reader, size as u64)?;
                }
                SIG_DUMMY => {
                    let (_flags, size) = read_extra_field(&mut reader)?;
                    skip(&mut reader, size as u64)?;
                }
                SIG_END_MARKER => {
                    // In multi-volume archives, this may be a volume boundary
                    // rather than the true end. Peek at the next signature.
                    match read_u32(&mut reader) {
                        Ok(next)
                            if next == SIG_FILE_HEADER
                                || next == SIG_COMMENT
                                || next == SIG_DUMMY =>
                        {
                            reader.seek(SeekFrom::Current(-4))?;
                        }
                        Ok(_) => {
                            reader.seek(SeekFrom::Current(-4))?;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                _ => return Err(EggError::CorruptedFile),
            }
        }

        Ok(EggArchive {
            reader,
            entries,
            is_encrypted,
            is_solid,
            header_id,
            split_info,
        })
    }
}

fn parse_file_entry<R: Read + Seek>(
    reader: &mut R,
    is_encrypted: &mut bool,
) -> EggResult<EggFileEntry> {
    let file_id = read_u32(reader)?;
    let uncompressed_size = read_u64(reader)?;

    let mut file_name = String::new();
    let mut file_time: Option<u64> = None;
    let mut file_attr: u8 = 0;
    let mut encrypt_info: Option<EncryptInfo> = None;

    // Parse sub-headers until End Marker
    loop {
        let sig = read_u32(reader)?;
        match sig {
            SIG_FILENAME => {
                let (flags, size) = read_extra_field(reader)?;
                let mut remaining = size as usize;
                let use_area_code = flags & 0x10 != 0;
                let is_relative = flags & 0x20 != 0;

                let locale_code = if use_area_code {
                    let lc = read_u16(reader)?;
                    remaining -= 2;
                    Some(lc)
                } else {
                    None
                };

                if is_relative {
                    let _parent_id = read_u32(reader)?;
                    remaining -= 4;
                }

                let mut name_buf = vec![0u8; remaining];
                reader.read_exact(&mut name_buf)?;

                let decoded = encoding::decode_filename(flags, locale_code, &name_buf);
                file_name = encoding::normalize_path(&decoded);
            }
            SIG_COMMENT => {
                let (_flags, size) = read_extra_field(reader)?;
                skip(reader, size as u64)?;
            }
            SIG_WINDOWS_FILE_INFO => {
                let (_flags, _size) = read_extra_field(reader)?;
                file_time = Some(read_u64(reader)?);
                file_attr = read_u8(reader)?;
            }
            SIG_POSIX_FILE_INFO => {
                let (_flags, size) = read_extra_field(reader)?;
                skip(reader, size as u64)?;
            }
            SIG_ENCRYPT_INFO => {
                let (_flags, size) = read_extra_field(reader)?;
                let method_byte = read_u8(reader)?;
                let data_len = (size as usize).saturating_sub(1);
                let mut data = vec![0u8; data_len];
                reader.read_exact(&mut data)?;

                let method = EncryptionMethod::from_byte(method_byte);
                if let EncryptionMethod::Unknown(n) = method {
                    return Err(EggError::UnsupportedEncryption(n));
                }
                *is_encrypted = true;
                encrypt_info = Some(EncryptInfo { method, data });
            }
            SIG_END_MARKER => break,
            _ => return Err(EggError::CorruptedFile),
        }
    }

    // Parse blocks
    let mut blocks = Vec::new();
    loop {
        let sig = read_u32(reader)?;
        match sig {
            SIG_BLOCK_HEADER => {
                let block = parse_block(reader)?;
                blocks.push(block);
            }
            SIG_COMMENT | SIG_FILE_HEADER | SIG_END_MARKER | SIG_DUMMY => {
                // Unread the signature
                reader.seek(SeekFrom::Current(-4))?;
                break;
            }
            _ => return Err(EggError::CorruptedFile),
        }
    }

    Ok(EggFileEntry {
        file_name,
        file_id,
        uncompressed_size,
        blocks,
        encrypt_info,
        file_time,
        file_attr,
    })
}

fn parse_block<R: Read + Seek>(reader: &mut R) -> EggResult<EggBlock> {
    let method_byte = read_u8(reader)?;
    let _hint = read_u8(reader)?;
    let uncompressed_size = read_u32(reader)?;
    let compressed_size = read_u32(reader)?;
    let crc32 = read_u32(reader)?;

    // End Marker must follow
    let end_sig = read_u32(reader)?;
    if end_sig != SIG_END_MARKER {
        return Err(EggError::CorruptedFile);
    }

    let data_pos = reader.stream_position()?;

    // Skip over compressed data
    skip(reader, compressed_size as u64)?;

    Ok(EggBlock {
        compression_method: CompressionMethod::from_byte(method_byte),
        uncompressed_size,
        compressed_size,
        crc32,
        data_pos,
    })
}

/// Read the extra field prefix: flags byte + size (u16 or u32).
fn read_extra_field<R: Read>(reader: &mut R) -> EggResult<(u8, u32)> {
    let flags = read_u8(reader)?;
    let size = if flags & 0x01 != 0 {
        read_u32(reader)?
    } else {
        read_u16(reader)? as u32
    };
    Ok((flags, size))
}

fn skip<R: Read + Seek>(reader: &mut R, n: u64) -> EggResult<()> {
    reader.seek(SeekFrom::Current(n as i64))?;
    Ok(())
}

fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}
