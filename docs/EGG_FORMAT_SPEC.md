# EGG Archive Format Specification

Version 1.0 -- Reverse-engineered specification

All multi-byte integers are little-endian unless stated otherwise.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Archive Layout](#2-archive-layout)
3. [Signatures](#3-signatures)
4. [Extra Field](#4-extra-field)
5. [EGG Header](#5-egg-header)
6. [Prefix Section](#6-prefix-section)
7. [File Header](#7-file-header)
8. [File Sub-Headers](#8-file-sub-headers)
9. [Block Header](#9-block-header)
10. [End Marker](#10-end-marker)
11. [Compression Methods](#11-compression-methods)
12. [Encryption](#12-encryption)
13. [Split Archives](#13-split-archives)
14. [Solid Archives](#14-solid-archives)
15. [CRC-32](#15-crc-32)
16. [Parsing Notes](#16-parsing-notes)

Appendix:

- [A. AZO Compression Algorithm](#a-azo-compression-algorithm)

---

## 1. Overview

The EGG format is an archive format that supports multiple compression algorithms, multiple encryption
methods, split (multi-volume) archives, solid compression, and per-file
comments.

File extension: `.egg`

Byte order: Little-endian throughout, except AZO block headers (Appendix A.2).

---

## 2. Archive Layout

An EGG archive is a sequence of tagged records identified by 4-byte signatures.
The overall structure is:

```
[EGG Header]
[Prefix Section]
  [Split Info]        0 or more
  [Solid Info]        0 or 1
[End Marker]

[File Header 0]
  [Filename]          1 or more
  [Comment]           0 or more
  [Windows File Info] 0 or more
  [Encrypt Info]      0 or 1
[End Marker]
  [Block 0]
    [Block Header]
    [End Marker]
    [Compressed Data]
  [Block 1 ...]

[File Header 1 ...]

[Comment]             0 or more  (archive-level)

[End Marker]          final
```

Every section of sub-headers is terminated by an End Marker (`0x08E28222`).
Blocks follow immediately after the file sub-header End Marker. The archive
itself ends with a final End Marker.

---

## 3. Signatures

Every structural element begins with a 4-byte little-endian signature:

| Name               | Hex          | Description                    |
|--------------------|--------------|--------------------------------|
| EGG Header         | `0x41474745` | Archive magic (`EGGA` in ASCII)|
| Split Info         | `0x24F5A262` | Split archive info             |
| Solid Info         | `0x24E5A060` | Solid archive flag             |
| Global Encrypt     | `0x08D144A8` | Global encryption header       |
| File Header        | `0x0A8590E3` | File entry                     |
| Filename           | `0x0A8591AC` | Filename sub-header            |
| Comment            | `0x04C63672` | Comment sub-header             |
| Windows File Info  | `0x2C86950B` | Windows file information       |
| Posix File Info    | `0x1EE922E5` | POSIX file information         |
| Encrypt Info       | `0x08D1470F` | Encryption sub-header          |
| Block Header       | `0x02B50C13` | Compressed data block          |
| Dummy              | `0x07463307` | Padding/dummy block            |
| Skip               | `0xFFFF0000` | Ignored split info             |
| End Marker         | `0x08E28222` | Section terminator             |

Notes:
- Global Encrypt (`0x08D144A8`) and Posix File Info (`0x1EE922E5`) are defined
  in the format but not used in practice. Implementations should skip
  unrecognized extra-field-based sub-headers by reading their extra field
  prefix and advancing past `size` bytes.

---

## 4. Extra Field

Several sub-headers are wrapped in an "extra field" prefix. This prefix encodes
flags and the byte size of the data that follows.

```
Offset  Size  Description
+0      1     Flags byte
+1      2|4   Data size (UInt16 if flags bit 0 is 0; UInt32 if bit 0 is 1)
```

If `flags & 0x01 == 0`: the size field is 2 bytes (UInt16). Total prefix = 3 bytes.
If `flags & 0x01 == 1`: the size field is 4 bytes (UInt32). Total prefix = 5 bytes.

Remaining bits of the flags byte have sub-header-specific meanings (see
sections 8.1 and 8.2). For most sub-headers, flags is `0x00`.

Sub-headers that use this prefix: Split Info, Solid Info, Filename, Comment,
Windows File Info, Posix File Info, Encrypt Info, Dummy.

Sub-headers that do NOT use this prefix: File Header, Block Header.

---

## 5. EGG Header

The archive begins with the 4-byte magic signature `0x41474745`, followed by:

```
Offset  Size  Type    Description
+0      2     UInt16  Version (e.g. 0x0100 for v1.0)
+2      4     UInt32  Header ID (random non-zero value; used as volume ID)
+6      4     UInt32  Reserved (0x00000000)
```

Total: 4 (signature) + 10 (header) = 14 bytes.

The Header ID field serves as the volume identifier in split archives. Each
volume has a unique Header ID, and volumes reference each other by ID.

---

## 6. Prefix Section

After the EGG Header, a sequence of optional sub-headers may appear, terminated
by an End Marker. Valid sub-headers in this section:

- Split Info (`0x24F5A262`)
- Solid Info (`0x24E5A060`)
- Skip (`0xFFFF0000`) -- parsed like Split Info but ignored
- Global Encrypt (`0x08D144A8`) -- reserved, not implemented

### 6.1 Split Info

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size=8)
Offset  Size  Type    Description
+0      4     UInt32  Previous volume ID (0 = this is the first volume)
+4      4     UInt32  Next volume ID (0 = this is the last volume)
```

See section 13 for full split archive details.

### 6.2 Solid Info

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size=0)
```

The presence of this sub-header marks the archive as using solid compression.
No additional data beyond the extra field prefix.

---

## 7. File Header

Signature: `0x0A8590E3`

Immediately after the signature (no extra field prefix):

```
Offset  Size  Type    Description
+0      4     UInt32  File ID (unique index, starting from 0)
+4      8     UInt64  Uncompressed file size
```

Total: 4 (signature) + 12 (data) = 16 bytes.

After the File Header, a sequence of sub-headers follows (section 8), terminated
by an End Marker. After the End Marker, one or more Block entries follow
(section 9).

Files larger than 4 GB are split across multiple blocks.

Directory entries have file size 0, the directory attribute set (section 8.3),
and zero blocks.

---

## 8. File Sub-Headers

These appear between the File Header and its End Marker.

### 8.1 Filename (`0x0A8591AC`)

```
[Extra Field]             3 bytes
  Flags byte:
    Bit 3: 0=not encrypted, 1=encrypted
    Bit 4: 0=UTF-8, 1=area code (locale-specific encoding)
    Bit 5: 0=absolute path, 1=relative path
  Size: UInt16
[Locale]                  0 or 2 bytes (present when bit 4 is set)
                          UInt16 locale code:
                            0 = system default
                            932 = Japanese (Shift-JIS)
                            949 = Korean (EUC-KR)
[Parent Path ID]          0 or 4 bytes (present when bit 5 is set)
                          UInt32 File ID of the entry containing the parent path
[Filename]                remaining bytes (no null terminator)
```

In practice, the flags byte is always `0x00` and the filename is UTF-8. Path separators may be `/` or `\`;
implementations should normalize to the platform convention.

### 8.2 Comment (`0x04C63672`)

```
[Extra Field]             3 bytes
  Flags byte:
    Bit 3: 0=not encrypted, 1=encrypted
    Bit 4: 0=UTF-8, 1=area code
  Size: UInt16
[Comment text]            UTF-8, no null terminator
```

Can appear as a file sub-header or at the archive level (between file entries).

### 8.3 Windows File Info (`0x2C86950B`)

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size=9)
Offset  Size  Type    Description
+0      8     UInt64  Last modified time (Windows FILETIME: 100-nanosecond
                      intervals since 1601-01-01 00:00:00 UTC)
+8      1     BYTE    File attributes
```

Attribute bits:

| Bit | Mask | Meaning       |
|-----|------|---------------|
| 0   | 0x01 | Read-only     |
| 1   | 0x02 | Hidden        |
| 2   | 0x04 | System        |
| 3   | 0x08 | Symbolic link |
| 7   | 0x80 | Directory     |

These are EGG-specific attribute bits, not raw Windows `FILE_ATTRIBUTE_*`
values. Implementations must map them to platform equivalents.

### 8.4 POSIX File Info (`0x1EE922E5`)

Defined in the format but not used in practice. Included here for
completeness.

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size=20)
Offset  Size  Type    Description
+0      4     UInt32  POSIX mode (file type + permissions, see stat(2))
+4      4     UInt32  User ID (UID)
+8      4     UInt32  Group ID (GID)
+12     8     UInt64  Last modified time (seconds since 1970-01-01 00:00:00 UTC)
```

The mode field uses standard POSIX bit layout:
- `0170000`: file type mask (socket, symlink, regular, block, directory, char, FIFO)
- `04000`: setuid, `02000`: setgid, `01000`: sticky
- `00700`/`00070`/`00007`: owner/group/other rwx permissions

### 8.5 Encrypt Info (`0x08D1470F`)

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size)
Offset  Size  Type    Description
+0      1     BYTE    Encryption method
+1      var   BYTE[]  Method-specific data
```

The extra field's UInt16 size declares the total method-specific payload size
(including the method byte itself). However, for validation purposes, the
expected size is determined by the method. The data to read is always
`size - 1` bytes after the method byte. Expected total sizes by method:

| Method | Total size field | Data after method byte |
|--------|-----------------|------------------------|
| 0      | 17              | 16 bytes               |
| 1      | 21              | 20 bytes               |
| 2      | 29              | 28 bytes               |
| 5      | 21              | 20 bytes               |
| 6      | 29              | 28 bytes               |

Unknown encryption methods are a fatal error.

See section 12 for encryption details.

### 8.6 Dummy (`0x07463307`)

```
[Extra Field]             3 bytes (flags=0x00, UInt16 size)
[Padding data]            `size` bytes (skipped)
```

Used for alignment and padding in split archives. In a split archive, the
compressor may insert a Dummy sub-header to fill remaining space in a volume
before starting a new file in the next volume. Readers should skip the padding
data (read `size` bytes and discard) if they encounter this signature.
Dummy may appear between file entries in split archives but does not appear
within a file's sub-header group (between Filename/Comment/Encrypt Info).

---

## 9. Block Header

Signature: `0x02B50C13`

One file may consist of multiple blocks. After a file's sub-header End Marker,
block signatures are read in a loop. When a Comment (`0x04C63672`), File Header
(`0x0A8590E3`), or End Marker (`0x08E28222`) signature is encountered instead
of a Block signature, the reader seeks back 4 bytes to unread the signature and
stops reading blocks. Any other unexpected signature is a format error.

Immediately after the signature (no extra field prefix):

```
Offset  Size  Type    Description
+0      1     BYTE    Compression method (see section 11)
+1      1     BYTE    Compression hint (method-specific, currently unused)
+2      4     UInt32  Uncompressed size of this block
+6      4     UInt32  Compressed (packed) size of this block
+10     4     UInt32  CRC-32 of uncompressed data
```

Total header: 14 bytes.

Immediately after the header, an End Marker (`0x08E28222`, 4 bytes) MUST
appear, followed by `packSize` bytes of compressed data.

Complete block layout:

```
[Block signature]     4 bytes   0x02B50C13
[Block header]       14 bytes
[End marker]          4 bytes   0x08E28222
[Compressed data]     packSize bytes
```

The CRC-32 is computed over the decompressed (and decrypted) output of this
block, not the compressed data.

---

## 10. End Marker

The End Marker `0x08E28222` (4 bytes) terminates:

1. The prefix section (after EGG Header sub-headers)
2. Each file's sub-header sequence
3. Each block (between block header and compressed data)
4. The archive (final End Marker after all entries)

---

## 11. Compression Methods

| Value | Name    | Algorithm                                     |
|-------|---------|-----------------------------------------------|
| 0     | Store   | No compression (raw copy)                     |
| 1     | Deflate | Raw DEFLATE (RFC 1951, no zlib/gzip wrapper)  |
| 2     | Bzip2   | Standard bzip2                                |
| 3     | AZO     | Proprietary LZ77 + range coder (see Appendix A)|
| 4     | LZMA    | LZMA with 9-byte header (see 11.1)            |

### 11.1 LZMA Framing

LZMA compressed data in EGG blocks starts with a 9-byte header:

```
Offset  Size  Description
+0      4     Reserved (read and discarded)
+4      5     LZMA properties (standard LZMA SDK format):
              Byte 0: lc/lp/pb packed as (pb * 45 + lp * 9 + lc)
              Bytes 1-4: dictionary size (UInt32, little-endian)
```

The remaining `packSize - 9` bytes are the LZMA compressed bitstream.

When encryption is active, the entire block data (including this 9-byte header)
is encrypted. The header must be decrypted before parsing the LZMA properties.

### 11.2 Deflate Details

Uses raw DEFLATE without zlib or gzip wrapper. Equivalent to
`inflateInit2(stream, -MAX_WBITS)` in zlib.

### 11.3 Bzip2 Details

Standard bzip2 stream with standard stream header (`BZh[1-9]`), block magic,
and CRC. No modifications from standard bzip2.

### 11.4 Compression Hint Byte

The 1-byte compression hint in the Block Header is not used by any decoder.
It was likely reserved for algorithm-specific parameters (e.g., compression
level, dictionary size). Implementations should read and ignore it.

### 11.5 Unknown Compression Methods

Values outside {0, 1, 2, 3, 4} are not defined. Implementations should treat
unknown compression methods as a fatal error and abort extraction of the
affected file.

---

## 12. Encryption

### 12.1 Encryption Methods

| Value | Name      | Key size | Salt size | Verify size | Footer size |
|-------|-----------|----------|-----------|-------------|-------------|
| 0     | ZipCrypto | n/a      | n/a       | 12          | n/a         |
| 1     | AES-128   | 16       | 8         | 2           | 10          |
| 2     | AES-256   | 32       | 16        | 2           | 10          |
| 3     | (reserved)|          |           |             |             |
| 4     | (reserved)|          |           |             |             |
| 5     | LEA-128   | 16       | 8         | 2           | 10          |
| 6     | LEA-256   | 32       | 16        | 2           | 10          |

Methods 3 and 4 are deprecated/reserved and must not be used.

### 12.2 Encrypt Info Data Layout

All encryption data is stored in the Encrypt Info sub-header, not in the
compressed data stream. The footer (HMAC tag) for AES/LEA is also stored in
the sub-header, not appended to the block data.

**ZipCrypto (method 0) -- 16 bytes:**

```
Offset  Size  Description
+0      12    Encryption verify data (12-byte random header)
+12     4     UInt32 CRC-32 (for password verification)
```

**AES-128 / LEA-128 (methods 1, 5) -- 20 bytes:**

```
Offset  Size  Description
+0      8     Salt
+8      2     Password verifier
+10     10    Authentication footer (HMAC-SHA1 tag)
```

**AES-256 / LEA-256 (methods 2, 6) -- 28 bytes:**

```
Offset  Size  Description
+0      16    Salt
+16     2     Password verifier
+18     10    Authentication footer (HMAC-SHA1 tag)
```

### 12.3 ZipCrypto (method 0)

Traditional PKZIP stream cipher, identical to ZIP 2.0 encryption.

**Key state**: Three 32-bit unsigned integers, initialized to:

```
key[0] = 0x12345678
key[1] = 0x23456789
key[2] = 0x34567890
```

**UpdateKeys(c):**

```
key[0] = CRC32_TABLE[(key[0] ^ c) & 0xFF] ^ (key[0] >> 8)
key[1] = (key[1] + (key[0] & 0xFF)) * 134775813 + 1
key[2] = CRC32_TABLE[(key[2] ^ (key[1] >> 24)) & 0xFF] ^ (key[2] >> 8)
```

The constant 134775813 is `0x08088405` in hexadecimal. `CRC32_TABLE` is the
standard CRC-32 lookup table with polynomial `0xEDB88320`.

**Initialization**: Process each byte of the password through UpdateKeys.

**DecryptByte():**

```
temp = key[2] | 2           (32-bit, no truncation)
return ((temp * (temp ^ 1)) >> 8) as BYTE
```

Note: `temp` is a full 32-bit value. The multiplication `temp * (temp ^ 1)` is
performed at 32-bit width (overflow wraps). The result is shifted right by 8
and truncated to a byte. This differs from the standard PKZIP specification
which truncates to 16-bit before the multiply.

**Decryption**: For each ciphertext byte:

```
plain = cipher ^ DecryptByte()
UpdateKeys(plain)
```

**Password verification**: Initialize keys with the password. Decrypt the
12-byte verify data. If `decrypted[11] != (storedCRC >> 24)`, the password is
wrong. If the password is correct, the keys are already in the correct state
for data decryption (the 12-byte header decryption both validates the password
and advances the key state). No re-initialization or re-decryption is needed.

For subsequent files using the same password, the keys are restored to their
post-password initialization state (before any verify data was processed), then
the new file's 12-byte verify data is decrypted to set up keys for that file.

### 12.4 AES-128 / AES-256 (methods 1, 2)

AES in CTR mode with HMAC-SHA1 authentication, compatible with the WinZip AE-2
encryption scheme.

**Mode mapping**: AES-128 uses fcrypt mode 1; AES-256 uses fcrypt mode 3.

**Key derivation (PBKDF2-HMAC-SHA1):**

- Password: UTF-8 encoded
- Salt: from Encrypt Info header (8 bytes for AES-128, 16 bytes for AES-256)
- Iterations: 1000
- Output length: `keySize * 2 + 2` bytes
  - Bytes `[0, keySize)`: AES encryption key
  - Bytes `[keySize, keySize*2)`: HMAC-SHA1 authentication key
  - Bytes `[keySize*2, keySize*2+2)`: Password verifier (2 bytes)

**Password verification**: Compare derived verifier bytes with the stored
password verifier. If they do not match, the password is wrong.

**Decryption**: AES in CTR mode (counter mode), using the WinZip AE-2 counter
convention:

- **Initial counter**: 1 (little-endian: `[0x01, 0x00, ..., 0x00]`)
- **Counter increment**: little-endian (increment byte 0, carry to byte 1, etc.)
- The nonce/counter state is maintained across the entire file's data (all
  blocks)

Note: This differs from the LEA CTR mode (section 12.5.6) which uses a counter
starting at 0 with big-endian increment.

**Authentication footer**: The 10-byte footer is the first 10 bytes of the
HMAC-SHA1 tag (truncated from the full 20-byte HMAC output) computed over the
ciphertext. Verification of this tag is optional but recommended.

### 12.5 LEA-128 / LEA-256 (methods 5, 6)

LEA (Lightweight Encryption Algorithm) is a 128-bit block cipher standardized
as KS X 3246 and TTAK.KO-12.0223 (South Korea). It uses only ARX operations
(Addition mod 2^32, Rotation, XOR) on 32-bit words -- no S-boxes.

The EGG format uses LEA-128 (method 5) and LEA-256 (method 6) in CTR mode.

#### 12.5.1 EGG Integration

**Mode mapping**: LEA-128 uses mode 1; LEA-256 uses mode 3.

**Key derivation (PBKDF2-HMAC-SHA1):**

Same as AES (section 12.4):
- Salt: from Encrypt Info header (8 bytes for LEA-128, 16 bytes for LEA-256)
- Iterations: 1000
- Output length: `keySize * 2 + 2` bytes
- Same key/auth-key/verifier split as AES

**Password verification**: Same as AES.

**Decryption**: LEA in CTR mode with a zero IV (16 bytes of `0x00`). See
12.5.6 for CTR mode details.

**Authentication footer**: Same 10-byte layout as AES. Verification is
optional.

#### 12.5.2 Notation and Byte Order

All operations are on 32-bit unsigned integers (words). Overflow wraps
(mod 2^32).

| Symbol      | Meaning                                            |
|-------------|----------------------------------------------------|
| `x + y`     | Addition mod 2^32                                  |
| `x - y`     | Subtraction mod 2^32                               |
| `x ^ y`     | Bitwise XOR                                        |
| `ROL_n(x)`  | Left-rotate x by n bits: `(x << n) | (x >> (32-n))` |
| `ROR_n(x)`  | Right-rotate x by n bits: `(x >> n) | (x << (32-n))`|

**Byte-to-word conversion** (little-endian):

A 16-byte plaintext/ciphertext block `B[0..15]` maps to 4 words:

```
X[0] = B[0] | (B[1] << 8) | (B[2] << 16) | (B[3] << 24)
X[1] = B[4] | (B[5] << 8) | (B[6] << 16) | (B[7] << 24)
X[2] = B[8] | (B[9] << 8) | (B[10] << 16) | (B[11] << 24)
X[3] = B[12] | (B[13] << 8) | (B[14] << 16) | (B[15] << 24)
```

Keys are converted the same way: a 16-byte key becomes 4 words, a 24-byte
key becomes 6 words, a 32-byte key becomes 8 words.

#### 12.5.3 Delta Constants

The key schedule uses 8 constant words derived from the hexadecimal expansion
of sqrt(766995), where 76/69/95 are ASCII codes for 'L','E','A':

```
delta[0] = 0xc3efe9db
delta[1] = 0x44626b02
delta[2] = 0x79e27c8a
delta[3] = 0x78df30ec
delta[4] = 0x715ea49e
delta[5] = 0xc785da0a
delta[6] = 0xe04ef22a
delta[7] = 0xe5c40957
```

#### 12.5.4 Key Schedule

The key schedule produces `Nr` round keys, each consisting of 6 words
(192 bits). `Nr` depends on key size:

| Key size | Nr (rounds) | Key words | Delta mod |
|----------|-------------|-----------|-----------|
| 128-bit  | 24          | 4 (T[0..3]) | `i mod 4` |
| 192-bit  | 28          | 6 (T[0..5]) | `i mod 6` |
| 256-bit  | 32          | 8 (T[0..7]) | `i mod 8` |

**LEA-128 key schedule** (K = 4 words from key bytes):

```
T = K  (copy 4 words)
for i = 0 to 23:
    T[0] = ROL_1(T[0] + ROL_i(delta[i mod 4]))
    T[1] = ROL_3(T[1] + ROL_(i+1)(delta[i mod 4]))
    T[2] = ROL_6(T[2] + ROL_(i+2)(delta[i mod 4]))
    T[3] = ROL_11(T[3] + ROL_(i+3)(delta[i mod 4]))
    RK[i] = (T[0], T[1], T[2], T[1], T[3], T[1])
```

Note: `ROL_i(delta[j])` means left-rotate `delta[j]` by `i` bits (mod 32).

**LEA-192 key schedule** (K = 6 words from key bytes):

```
T = K  (copy 6 words)
for i = 0 to 27:
    T[0] = ROL_1(T[0] + ROL_i(delta[i mod 6]))
    T[1] = ROL_3(T[1] + ROL_(i+1)(delta[i mod 6]))
    T[2] = ROL_6(T[2] + ROL_(i+2)(delta[i mod 6]))
    T[3] = ROL_11(T[3] + ROL_(i+3)(delta[i mod 6]))
    T[4] = ROL_13(T[4] + ROL_(i+4)(delta[i mod 6]))
    T[5] = ROL_17(T[5] + ROL_(i+5)(delta[i mod 6]))
    RK[i] = (T[0], T[1], T[2], T[3], T[4], T[5])
```

**LEA-256 key schedule** (K = 8 words from key bytes):

```
T = K  (copy 8 words)
for i = 0 to 31:
    T[6i mod 8]     = ROL_1(T[6i mod 8]     + ROL_i(delta[i mod 8]))
    T[(6i+1) mod 8] = ROL_3(T[(6i+1) mod 8] + ROL_(i+1)(delta[i mod 8]))
    T[(6i+2) mod 8] = ROL_6(T[(6i+2) mod 8] + ROL_(i+2)(delta[i mod 8]))
    T[(6i+3) mod 8] = ROL_11(T[(6i+3) mod 8] + ROL_(i+3)(delta[i mod 8]))
    T[(6i+4) mod 8] = ROL_13(T[(6i+4) mod 8] + ROL_(i+4)(delta[i mod 8]))
    T[(6i+5) mod 8] = ROL_17(T[(6i+5) mod 8] + ROL_(i+5)(delta[i mod 8]))
    RK[i] = (T[6i mod 8], T[(6i+1) mod 8], T[(6i+2) mod 8],
             T[(6i+3) mod 8], T[(6i+4) mod 8], T[(6i+5) mod 8])
```

#### 12.5.5 Encryption and Decryption Round Functions

**Encryption** (Nr rounds):

```
X = plaintext as 4 words
for i = 0 to Nr-1:
    tmp[0] = ROL_9((X[0] ^ RK[i][0]) + (X[1] ^ RK[i][1]))
    tmp[1] = ROR_5((X[1] ^ RK[i][2]) + (X[2] ^ RK[i][3]))
    tmp[2] = ROR_3((X[2] ^ RK[i][4]) + (X[3] ^ RK[i][5]))
    tmp[3] = X[0]
    X = tmp
ciphertext = X as 16 bytes
```

**Decryption** (Nr rounds, round keys applied in reverse):

```
X = ciphertext as 4 words
for i = Nr-1 downto 0:
    tmp[0] = X[3]
    tmp[1] = (ROR_9(X[0]) - (tmp[0] ^ RK[i][0])) ^ RK[i][1]
    tmp[2] = (ROL_5(X[1]) - (tmp[1] ^ RK[i][2])) ^ RK[i][3]
    tmp[3] = (ROL_3(X[2]) - (tmp[2] ^ RK[i][4])) ^ RK[i][5]
    X = tmp
plaintext = X as 16 bytes
```

Note: In CTR mode, only the encrypt function is used (CTR encrypts the
counter block, then XORs the result with the data). Decryption of data =
encryption of counter block, then XOR.

#### 12.5.6 CTR Mode

The EGG format uses LEA-CTR with a 16-byte (128-bit) counter block:

- **Initial counter**: 16 bytes of `0x00`
- **Counter increment**: The counter is treated as a 128-bit big-endian
  integer. After each block encryption, it is incremented by 1 starting from
  the least significant byte (byte index 15):

```
def ctr128_inc(counter):
    for i = 15 downto 0:
        counter[i] += 1
        if counter[i] != 0:   // no overflow
            break
```

- **Encryption/Decryption**: For each 16-byte chunk of data, encrypt the
  current counter block with LEA-ECB to produce a keystream block, then XOR
  it with the data. Increment the counter. For the final partial block
  (< 16 bytes), only XOR with the first N bytes of the keystream.

```
counter = [0x00] * 16
for each 16-byte chunk of plaintext/ciphertext:
    keystream = LEA_ECB_Encrypt(key, counter)
    output = chunk ^ keystream
    ctr128_inc(counter)
```

#### 12.5.7 Test Vectors (from KS X 3246 Appendix A)

**LEA-128 encryption**:

```
Key (16 bytes):  0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0
Plaintext:       10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
Ciphertext:      9f c8 4e 35 28 c6 c6 18 55 32 c7 a7 04 64 8b fd
```

Intermediate state (X_i as 4 words, round-by-round):

| Round | X[0]     | X[1]     | X[2]     | X[3]     |
|-------|----------|----------|----------|----------|
| X_0   | 13121110 | 17161514 | 1b1a1918 | 1f1e1d1c |
| X_1   | 0f079051 | 693d668d | e5edcfd4 | 13121110 |
| X_2   | 3fc44a2d | f767ea2a | a0b67cf0 | 0f079051 |
| X_3   | 99e912cd | 906fd05d | 4d293e55 | 3fc44a2d |
| ...   | ...      | ...      | ...      | ...      |
| X_24  | 354ec89f | 18c6c628 | a7c73255 | fd8b6404 |
| C     | 9f c8 4e 35 28 c6 c6 18 55 32 c7 a7 04 64 8b fd |

Round keys (encryption, first 4 shown):

```
RK0enc:  003a0fd4 02497010 194f7db1 02497010 090d0883 02497010
RK1enc:  11fdcbb1 9e98e0c8 18b570cf 9e98e0c8 9dc53a79 9e98e0c8
RK2enc:  f30f7bb5 6d6628db b74e5dad 6d6628db a65e46d0 6d6628db
RK3enc:  74120631 dac9bd17 cd1ecf34 dac9bd17 540f76f1 dac9bd17
```

**LEA-192 encryption**:

```
Key (24 bytes):  0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0
                 f0 e1 d2 c3 b4 a5 96 87
Plaintext:       20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
Ciphertext:      6f b9 5e 32 5a ad 1b 87 8c dc f5 35 76 74 c6 f2
```

**LEA-256 encryption**:

```
Key (32 bytes):  0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0
                 f0 e1 d2 c3 b4 a5 96 87 78 69 5a 4b 3c 2d 1e 0f
Plaintext:       30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
Ciphertext:      d6 51 af f6 47 b1 89 c1 3a 89 00 ca 27 f9 e1 97
```

### 12.6 Decryption Pipeline

Encryption is applied at the stream level. The decoder reads compressed data
from the input stream, decrypts it in-place, then feeds the result to the
decompressor. CRC-32 is computed on the decompressed output.

**Buffer-at-a-time flow**: Each decoder allocates two 1 MB buffers (one for
input, one for output). The decode loop for each block is:

```
1. Read a chunk from the input stream into the input buffer
2. If a decryptor is active, decrypt the input buffer in-place:
     decryptor->Decrypt(inBuffer, bytesRead)
3. Feed the decrypted data to the decompressor (inflate, LZMA decode, etc.)
4. CRC32Update on the decompressed output bytes
5. Write decompressed output to the output stream
6. Repeat until the block's packSize bytes are consumed
7. CRC32Finish and compare against the block's stored CRC
```

**Per-block decoder, shared decryptor**: Each block creates a fresh decoder
instance (new inflate state, new LZMA state, etc.), but the decryptor is
shared across all blocks of a single file. The decryptor maintains its
internal counter/key state continuously across block boundaries.

**LZMA special case**: The LZMA decoder reads and decrypts the 9-byte header
(section 11.1) separately before entering the main decode loop. The header
bytes are read via `inStream->Read(header, 9, &read)`, then decrypted in-place
if a decryptor is active. After parsing the LZMA properties from the decrypted
header, the remaining `packSize - 9` bytes are processed through the standard
buffer loop.

**Store special case**: For Store (method 0), the "decompression" is a direct
copy. The CRC-32 is computed on the data after decryption (which IS the output
data). There is no separate decompression step.

**Decryptor lifecycle**:
- ZipCrypto: keys are restored to post-password state before each file, then
  the 12-byte verify data is decrypted (which sets up keys for that file's data)
- AES/LEA: a new decryptor is created for each encrypted file (each file has
  its own salt and password verifier in its Encrypt Info sub-header)

---

## 13. Split Archives

Split (multi-volume) archives use the Split Info sub-header in the prefix
section. Each volume is a standalone EGG file with its own EGG Header.

### 13.1 Volume Linking

- First volume: `previous = 0`, `next = <Header ID of next volume>`
- Middle volumes: `previous = <ID>`, `next = <ID>`
- Last volume: `next = 0`

The Header ID field in the EGG Header serves as the volume ID. To locate the
next volume, scan files in the same directory for EGG files whose Header ID
matches the expected next ID.

### 13.2 Continuation Volumes

When opening a continuation volume (not the first), the reader expects an End
Marker (`0x08E28222`) as the first signature after the Split Info. This End
Marker is mandatory. After it, the data stream continues from where the
previous volume left off.

To read continuation volumes, skip past the EGG Header + Split Info + End
Marker, then treat the remaining data as a continuation of the previous
volume's stream. This makes the multi-volume archive appear as a single
contiguous stream.

### 13.3 Split Rules

- File headers and sub-headers must not be split across volumes. Only compressed
  block data may span volume boundaries.
- If a file header would not fit in the remaining space, a Dummy sub-header is
  inserted as padding, and the file header begins in the next volume.
- Split archives support up to 2^32 - 1 volumes.
- The Skip signature (`0xFFFF0000`) may be used in place of Split Info to
  indicate a volume that should be ignored.

---

## 14. Solid Archives

When the Solid Info sub-header is present in the prefix section, the archive
uses solid compression. In solid mode, the compressor treats the concatenation
of all files as a single continuous stream, maintaining dictionary/state across
file boundaries.

### 14.1 Extraction Requirements

- Files MUST be decompressed sequentially in archive order.
- You cannot extract a single file from a solid archive without decompressing
  all preceding files first (because the decompressor may reference data from
  earlier files in the combined stream).
- Each block still has its own Block Header with packSize, unpackSize, and CRC.
  The CRC is per-block, not per-file or per-archive.

### 14.2 Decompression Semantics

In a solid archive, the compressed data for all files is laid out as a single
contiguous stream. The decompressor state (LZ77 dictionary, LZMA dictionary,
Deflate sliding window, AZO probability models) is maintained continuously
across block and file boundaries -- it is NOT reset between files.

Each block still has its own Block Header specifying packSize and unpackSize.
The extraction loop processes files in index order, reading blocks
sequentially. A new decoder instance is NOT created per block in solid mode;
instead, the same decoder continues across all blocks.

Bzip2 is the exception: bzip2 blocks are self-contained (the dictionary is
reset at each bzip2 block boundary), so solid mode has no effect on bzip2
decompression.

---

## 15. CRC-32

Standard CRC-32 with polynomial `0xEDB88320` (reflected representation of
`0x04C11DB7`).

**Algorithm:**

```
Initialize: crc = 0xFFFFFFFF
For each byte b:
    crc = CRC32_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
Finalize: crc = crc ^ 0xFFFFFFFF  (bitwise NOT)
```

The CRC-32 lookup table is generated from the polynomial:

```
for i in 0..256:
    c = i
    for j in 0..8:
        if c & 1:
            c = 0xEDB88320 ^ (c >> 1)
        else:
            c = c >> 1
    CRC32_TABLE[i] = c
```

CRC-32 is computed over decompressed (and decrypted) data and verified against
the `crc` field in each Block Header.

---

## 16. Parsing Notes

### 16.1 Error Handling

When an unknown signature is encountered during parsing, it should be treated
as a format error. The archive open operation should return a "not recognized"
status rather than a hard failure, allowing the caller to try other format
handlers.

### 16.2 Empty Files and Directories

Files with size 0 are skipped during extraction (no decompression occurs).
Directories have zero blocks; the block reading loop simply reads zero
iterations.

### 16.3 Block Reading Termination

After a file's sub-header End Marker, signatures are read in a loop. The loop
terminates when:
- A Block signature (`0x02B50C13`) is read: parse the block and continue.
- A Comment, File Header, or End Marker signature is read: seek back 4 bytes
  (unread the signature) and stop. The parent parser will re-read it.
- Any other signature: format error.

### 16.4 Sub-Header Ordering

Within a file's sub-header section, the following signatures are recognized:
Filename, Comment, Windows File Info, Encrypt Info, End Marker. Any other
signature is a format error. The End Marker terminates the section.

### 16.5 Forward Compatibility

Implementations should handle unrecognized extra-field-based sub-headers by
reading the extra field prefix (to get the size) and skipping `size` bytes.
Sub-headers without extra field prefixes (File Header, Block Header) cannot
be skipped this way.

---

## A. AZO Compression Algorithm

AZO is the compression algorithm used in the EGG format. It is an
LZ77-based scheme using a binary arithmetic (range) coder with adaptive
probability models. This appendix provides sufficient detail to implement a
complete AZO decompressor.

### A.1 Stream Structure

AZO compressed data has a 2-byte stream header followed by one or more blocks:

```
[Stream Header]     2 bytes
[Block 0]           variable
[Block 1 ...]
[Terminal Block]    12 bytes (all zeros)
```

**Stream Header:**

```
Offset  Size  Description
+0      1     Version: ASCII '0' + version number (version 1 = '1' = 0x31)
+1      1     Flags: bit 0 = x86 filter enabled
```

The only defined version is 1 (byte value `0x31`). Any other value is a fatal
error (`AZO_DATA_ERROR_VERSION`).

### A.2 Block Structure

Each block has a 12-byte header. **All three fields are big-endian**, unlike the
rest of the EGG format which is little-endian:

```
Offset  Size  Type    Description
+0      4     UInt32  Uncompressed size (blockSize) [big-endian]
+4      4     UInt32  Compressed size (compressSize) [big-endian]
+8      4     UInt32  Check value (blockSize XOR compressSize) [big-endian]
```

Validation: `(blockSize ^ compressSize) == checkValue`, otherwise
`AZO_DATA_ERROR_BLOCKSIZE`. This check is optional; skipping it is safe.

When `blockSize == 0 && compressSize == 0`, the stream is complete
(`AZO_STREAM_END`).

If `compressSize == blockSize`, the block is stored uncompressed (raw copy).
Otherwise, the block is compressed with the range coder.

After decompressing a block, if the x86 filter flag is set, apply the x86
filter (section A.12) to the decompressed output.

### A.3 Decompression Algorithm

Each compressed block is decoded as follows:

```
1. Create an EntropyCode (range decoder) over the compressed data.
2. Call entropy.Initialize() -- reads 4 bytes to seed the tag.
3. Decode the first byte as a literal with context byte = 0.
4. For position i = 1 to blockSize - 1:
   a. Decode a match/literal flag via BoolState (section A.5).
   b. If literal (flag == 0):
      - Decode an 8-bit value using buf[i-1] as context (section A.9).
      - Store it at buf[i]. Advance i by 1.
   c. If match (flag == 1):
      - Decode distance and length via MatchCode (section A.10).
      - Copy `length` bytes from buf[i - distance] to buf[i].
        The copy is byte-by-byte (overlapping copies are valid).
      - Advance i by length.
5. Call entropy.Finalize().
6. Verify that the entropy decoder consumed exactly compressSize bytes.
```

### A.4 Range Decoder

32-bit arithmetic range coder reading bits MSB-first from a byte buffer.

**Types:** The range values (`low`, `up`, `tag`) should be stored in 64-bit
unsigned integers (`uint64_t`) to avoid overflow when computing
`(up - low + 1)` at full range. Constants are 32-bit:
- `MSB = 0x80000000`
- `sMSB = 0x40000000` (second most significant bit)

Alternatively, 32-bit variables may be used with a special case: when
`low == 0 && up == 0xFFFFFFFF`, compute `t = 1 << (32 - totalBit)` directly
instead of `(up - low + 1) >> totalBit` (which would overflow to 0).
Both approaches produce identical output.

**State:**
- `low`: lower bound (uint64_t, initialized to `0x00000000`)
- `up`: upper bound (uint64_t, initialized to `0xFFFFFFFF`)
- `tag`: current value from bitstream (uint64_t)

**Initialize:** Read 32 bits MSB-first from the bitstream into `tag`:

```
tag = 0
for i in 0..31:
    tag = (tag << 1) | ReadBit()
```

(Equivalently: read 4 bytes in big-endian order.)

**Decode uniform symbol** (given `totalBit` -- log2 of the alphabet size):

```
t = (up - low + 1) >> totalBit
value = (tag - low) / t
up = low + t * (value + 1) - 1
low = low + t * value
Rescale()
return value
```

This is used to decode `N`-bit raw values (e.g., extra bits for distance/length
codes).

**Decode boolean** (given `cumCount` = probability of 0, and `totalBit`):

```
t = (up - low + 1) >> totalBit
v = (tag - low) / t
if v >= cumCount:
    low += t * cumCount
    Rescale()
    return 1
else:
    up = low + t * cumCount - 1
    Rescale()
    return 0
```

**Rescale:**

All shifts are masked to 32 bits (MASK = 0xFFFFFFFF):

```
// Phase 1: MSB convergence
while (low & MSB) == (up & MSB):
    bit = ReadBit()
    tag = ((tag << 1) & MASK) | bit
    low = (low << 1) & MASK
    up = ((up << 1) & MASK) | 1

// Phase 2: Underflow resolution
while (low & sMSB) != 0 and (up & sMSB) == 0:
    bit = ReadBit()
    tag = (((tag << 1) | bit) ^ MSB) & MASK
    low = (low << 1) & (MASK >> 1)
    up = ((up << 1) | 1 | MSB) & MASK
```

**Bit reader:** Reads bits MSB-first from the byte buffer. Maintains a pointer
into the compressed data and a remaining-bits counter for the current byte.
Reading beyond the buffer is an error.

### A.5 BoolState -- Adaptive Binary Model

Used for match/literal decisions and other boolean flags. Parameterized by
`N` (number of context bits, default 8).

**State:**
- `state`: unsigned integer in range `[0, 2^N)`, initialized to 0
- `prob[2^N]`: array of 32-bit probabilities, each initialized to 2048
  (= TOTAL_COUNT / 2 = 4096 / 2, representing 50% initial probability)

**Constants:**
- `TOTAL_BIT = 12`
- `TOTAL_COUNT = 4096` (= 2^12)
- `SHIFT_BIT = 6` (= TOTAL_BIT - 6)

**Decode:**

```
bit = entropy.DecodeBoolean(prob[state], TOTAL_BIT)
// Update probability:
if bit == 0:
    prob[state] += (TOTAL_COUNT - prob[state]) >> SHIFT_BIT
else:
    prob[state] -= prob[state] >> SHIFT_BIT
// Update state:
state = ((state << 1) | bit) & (2^N - 1)
return bit
```

The match/literal flag in the block decoder uses `BoolState<8>` (256 states).

### A.6 EntropyBitProb -- Adaptive Multi-Bit Tree Model

Used for decoding multi-bit symbols (distance codes, length codes, dictionary
indices, history indices) as a binary tree with per-node adaptive probabilities.

Parameterized by `N` (alphabet size).

**Constants:**
- `BIT_N = ceil(log2(N))` (number of bits to encode a symbol)
- `ARRAY_N = 2^BIT_N` (number of tree nodes)
- `TOTAL_BIT = 10`
- `TOTAL_COUNT = 1024`
- `SHIFT_BIT = 4` (= TOTAL_BIT - 6)

**State:**
- `prob[ARRAY_N]`: per-node probabilities, each initialized to 512
  (= TOTAL_COUNT / 2 = 1024 / 2, representing 50% initial probability)

**Decode:**

```
value = 0
pre = 1                         // tree node index, starts at root
for i in (BIT_N - 1) downto 0:
    bit = entropy.DecodeBoolean(prob[pre], TOTAL_BIT)

    // Update probability inline (each node is independent):
    if bit == 0:
        prob[pre] += (TOTAL_COUNT - prob[pre]) >> SHIFT_BIT
    else:
        prob[pre] -= prob[pre] >> SHIFT_BIT

    if bit: value |= (1 << i)
    pre = (pre << 1) | bit      // descend left (0) or right (1)

return value
```

Note: probability updates can be done inline (single pass) or in a separate
pass after decoding -- both produce identical results since each tree node's
probability is independent.

**Update (passive, no decoding):** Updates probabilities for a known value
without reading from the range coder. Used by PredictProb (A.7) to keep the
inactive model in sync.

```
Update(value):
    pre = 1
    for i in (BIT_N - 1) downto 0:
        v = (value >> i) & 1
        if v == 0:
            prob[pre] += (TOTAL_COUNT - prob[pre]) >> SHIFT_BIT
        else:
            prob[pre] -= prob[pre] >> SHIFT_BIT
        pre = (pre << 1) | v
```

### A.7 PredictProb -- Dual-Model Adaptive Predictor

Used for literals (AlphaCode) and lengths (LengthCode). Selects between two
EntropyBitProb models based on a "luckiness" counter that tracks which model
is more accurate.

Parameterized by `KEY` (number of contexts), `N` (alphabet size), `SHIFT`.

**State:**
- `prob1[KEY]`: array of `EntropyBitProb<N>` (fine-grained, indexed by full context)
- `prob2[KEY >> SHIFT]`: array of `EntropyBitProb<N>` (coarse, indexed by context >> SHIFT)
- `lucky[KEY]`: array of `int`, each initialized to 0

**Decode (given context `pre`):**

```
if lucky[pre] >= 0:
    value = prob1[pre].Decode(entropy)     // use fine model
    prob2[pre >> SHIFT].Update(value)      // update coarse model passively
else:
    value = prob2[pre >> SHIFT].Decode(entropy)  // use coarse model
    prob1[pre].Update(value)               // update fine model passively

// Compare which model would have been better:
r = Compare(prob1[pre], prob2[pre >> SHIFT], value)
if r > 0: lucky[pre] += 1    // fine model was better
if r < 0: lucky[pre] -= 1    // coarse model was better

return value
```

**Compare function:** Compares which model better predicted the decoded value by
computing the product of per-bit probabilities along the decoding path.

```
Compare(model1, model2, value):
    prod1 = 1
    prod2 = 1
    pre = 1
    for i in (BIT_N - 1) downto 0:
        p1 = model1.prob[pre]
        p2 = model2.prob[pre]
        v = (value >> i) & 1

        // Overflow guard: if either product has bits in the upper
        // TOTAL_BIT positions of a 32-bit word, right-shift both.
        // For TOTAL_BIT=10: mask is (1023 << 22) = 0xFFC00000.
        if (prod1 | prod2) & ((TOTAL_COUNT - 1) << (32 - TOTAL_BIT)):
            prod1 >>= TOTAL_BIT
            prod2 >>= TOTAL_BIT

        prod1 *= (v ? (TOTAL_COUNT - p1) : p1)
        prod2 *= (v ? (TOTAL_COUNT - p2) : p2)

        pre = (pre << 1) | v

    if prod1 > prod2: return +1    // model1 was better
    if prod1 < prod2: return -1    // model2 was better
    return 0
```

All arithmetic is 32-bit unsigned (overflow wraps). The TOTAL_BIT and
TOTAL_COUNT values are those of the EntropyBitProb model (TOTAL_BIT=10,
TOTAL_COUNT=1024).

### A.8 HistoryList -- MRU Cache

A fixed-size most-recently-used list. Used for distance history (size 2) and
dictionary history (size 2).

Parameterized by type `T`, size `N`.

**State:**
- `rep[N]`: array of values, initialized to `[init, init+1, ..., init+N-1]`

For distance history: `init = MATCH_MIN_DIST = 1`, so `rep = [1, 2]`.

**Operations:**

- `Add(value)`: Shift all entries right by 1 (last entry is lost), insert
  `value` at index 0.
- `Add(value, delIdx)`: Shift entries `[0..delIdx-1]` right to
  `[1..delIdx]`, insert `value` at index 0. The entry at `delIdx` is
  overwritten.

**Decode (using BoolState + EntropyBitProb):**

```
if boolState.Decode(entropy):        // hit?
    idx = entropyBitProb.Decode(entropy)  // which entry?
    value = rep[idx]
    Add(value, idx)                  // move to front
    return (true, value)
else:
    return (false, _)                // not in history
```

### A.9 AlphaCode -- Literal Byte Decoding

Decodes a single literal byte using the previous byte as context.

Uses `PredictProb<256, 256, 5>`:
- 256 contexts (one per possible previous byte value)
- 256-symbol alphabet (one per possible byte value)
- SHIFT = 5 (coarse context uses previous byte >> 5, giving 8 groups)

```
byte = PredictProb.Decode(entropy, previousByte)
```

At position 0 (first byte of block), `previousByte = 0`.

### A.10 MatchCode -- Match Decoding

When the BoolState indicates a match, the match decoder runs:

```
1. Try dictionary (section A.10.1):
   - If hit: get (position, length) from dictionary, compute
     distance = currentPos - storedPos. Done.
2. If not in dictionary:
   a. Decode distance (section A.10.2)
   b. Decode length (section A.10.3), using the distance code as context
   c. Add (currentPos, length) to the dictionary
```

#### A.10.1 Dictionary Table

A 128-entry MRU cache of recent match (position, length) pairs.

**Initialization:** `data[i] = { pos: 0, len: MATCH_MIN_LENGTH + i }` for
`i` in `0..127`. (Lengths 2, 3, 4, ..., 129.)

**Decode:**

```
if findBoolState.Decode(entropy):           // dictionary hit?
    idx = symbolCode.Decode(entropy)        // which entry? (0..127)
    if idx >= 128: return miss              // invalid index
    (pos, length) = data[idx]
    // MRU update: shift [0..idx-1] right to [1..idx], insert at [0]
    data[1..idx] = data[0..idx-1]
    data[0] = { pos, length }
    return (pos, length)
else:
    return miss
```

**Add (on non-dictionary match):**

```
// MRU update: shift [0..126] right to [1..127], insert at [0]
data[1..127] = data[0..126]
data[0] = { pos, length }
```

The SymbolCode used for dictionary index selection is:
`SymbolCode<uint, 128, 2>` -- a HistoryList of size 2 followed by
EntropyBitProb<128> for new indices.

#### A.10.2 Distance Decoding

```
1. Try distance history (HistoryList<uint, 2>, init=1):
   - If hit: return the stored distance. Done.
2. Decode distance code index (0..127) via EntropyBitProb<128>.
3. Look up base distance: dist = DIST_CODE_TABLE[index]
4. If DIST_EXTRABIT_TABLE[index] > 0:
   dist += entropy.DecodeUniform(DIST_EXTRABIT_TABLE[index])
5. Add dist to distance history.
6. Return dist.
```

#### A.10.3 Length Decoding

```
1. Compute distCode = GetDistCode(distance) -- the code index for the distance.
2. Decode length code index (0..127) via PredictProb<128, 128, 4>,
   using distCode as context.
3. Look up base length: length = LENGTH_CODE_TABLE[index]
4. If LENGTH_EXTRABIT_TABLE[index] > 0:
   length += entropy.DecodeUniform(LENGTH_EXTRABIT_TABLE[index])
5. Return length.
```

`PredictProb<128, 128, 4>` means:
- 128 contexts (one per distance code)
- 128-symbol alphabet (length codes)
- SHIFT = 4 (coarse context = distCode >> 4, giving 8 groups)

### A.11 Code Tables

The distance and length code tables map code indices to base values with
optional extra bits.

#### A.11.1 Length Code Table (128 entries)

**Extra bits formula:**
```
ExtraBit(N) = 0                          if N < 32
ExtraBit(N) = (N - 32) / 8              otherwise
```

**Code table formula (recursive):**
```
LengthCode(0) = 2                       (= MATCH_MIN_LENGTH)
LengthCode(N) = LengthCode(N-1) + (1 << ExtraBit(N-1))
```

**First entries:**

| Index | Base Length | Extra Bits |
|-------|-----------|------------|
| 0     | 2         | 0          |
| 1     | 3         | 0          |
| ...   | ...       | 0          |
| 31    | 33        | 0          |
| 32    | 34        | 0          |
| 33    | 35        | 0          |
| ...   | ...       | 0          |
| 39    | 41        | 0          |
| 40    | 42        | 1          |
| 41    | 44        | 1          |
| ...   | ...       | ...        |
| 48    | 58        | 2          |
| ...   | ...       | ...        |

The maximum representable length is `LengthCode(128) - 1`.

**Reverse lookup** (value to code index, needed for A.10.3):

```
GetLengthCode(value):
    value -= MATCH_MIN_LENGTH          // subtract 2
    if value < MATCH_LENGTH_SGAP:      // < 32
        return value
    value -= MATCH_LENGTH_SGAP
    extraBit = floor(log2(value / MATCH_LENGTH_GAP + 1))
    return MATCH_LENGTH_SGAP + extraBit * MATCH_LENGTH_GAP
           + (value - ((1 << extraBit) - 1) * MATCH_LENGTH_GAP) / (1 << extraBit)
```

#### A.11.2 Distance Code Table (128 entries)

**Extra bits formula:**
```
ExtraBit(N) = 0                          if N < 16
ExtraBit(N) = (N - 16) / 4              otherwise
```

**Code table formula (recursive):**
```
DistCode(0) = 1                          (= MATCH_MIN_DIST)
DistCode(N) = DistCode(N-1) + (1 << ExtraBit(N-1))
```

**First entries:**

| Index | Base Distance | Extra Bits |
|-------|--------------|------------|
| 0     | 1            | 0          |
| 1     | 2            | 0          |
| ...   | ...          | 0          |
| 15    | 16           | 0          |
| 16    | 17           | 0          |
| 17    | 18           | 0          |
| 18    | 19           | 0          |
| 19    | 20           | 0          |
| 20    | 21           | 1          |
| 21    | 23           | 1          |
| ...   | ...          | ...        |

The maximum representable distance is `DistCode(128) - 1`.

**Reverse lookup** (value to code index, needed for A.10.3):

```
GetDistCode(value):
    value -= MATCH_MIN_DIST            // subtract 1
    if value < MATCH_DIST_SGAP:        // < 16
        return value
    value -= MATCH_DIST_SGAP
    extraBit = floor(log2(value / MATCH_DIST_GAP + 1))
    return MATCH_DIST_SGAP + extraBit * MATCH_DIST_GAP
           + (value - ((1 << extraBit) - 1) * MATCH_DIST_GAP) / (1 << extraBit)
```

### A.12 x86 Filter

When the stream header filter flag is set, apply this filter to each
decompressed block. The filter reverses x86 CALL/JMP address transformations
that the compressor applied to improve compression of executable code.

x86 CALL (`0xE8`) and JMP (`0xE9`) instructions use relative 32-bit addresses.
The compressor converts these to absolute addresses (better for compression).
This filter converts them back to relative.

The check `buf[i+4] == 0x00 or buf[i+4] == 0xFF` tests the high byte of the
address to filter only addresses that are "near" (within ~16 MB), avoiding
false positives on non-address data that happens to follow a `0xE8`/`0xE9`.

```
if size < 5: return

i = 0
while i < size - 4:
    if buf[i] == 0xE8 or buf[i] == 0xE9:   // CALL or JMP
        if buf[i+4] == 0x00 or buf[i+4] == 0xFF:
            addr = read_le32(buf[i+1])      // 4 bytes, little-endian
            addr -= i                        // absolute -> relative
            if (addr >> 24) & 1:             // test bit 24
                addr |= 0xFF000000          // sign-extend: negative 24-bit
            else:
                addr &= 0x00FFFFFF          // positive 24-bit
            write_le32(buf[i+1], addr)
        i += 5
    else:
        i += 1
```

### A.13 Constants Summary

| Name                       | Value |
|----------------------------|-------|
| AZO_PRIVATE_VERSION        | 1     |
| COMPRESSION_REDUCE_MIN_SIZE| 8     |
| ALPHA_SIZE                 | 256   |
| ALPHACODE_PREDICT_SHIFT    | 5     |
| LENGTHCODE_PREDICT_SHIFT   | 4     |
| MATCH_MIN_LENGTH           | 2     |
| MATCH_MIN_DIST             | 1     |
| MATCH_LENGTH_CODE_SIZE     | 128   |
| MATCH_DIST_CODE_SIZE       | 128   |
| MATCH_LENGTH_SGAP          | 32    |
| MATCH_LENGTH_GAP           | 8     |
| MATCH_DIST_SGAP            | 16    |
| MATCH_DIST_GAP             | 4     |
| DICTIONARY_SIZE            | 128   |
| DICTIONARY_HISTORY_SIZE    | 2     |
| DISTANCE_HISTORY_SIZE      | 2     |

### A.14 Error Codes

| Value | Name                     |
|-------|--------------------------|
| 0     | AZO_OK                  |
| 1     | AZO_STREAM_END          |
| -1    | AZO_PARAM_ERROR         |
| -2    | AZO_MEM_ERROR           |
| -3    | AZO_OUTBUFF_FULL        |
| -4    | AZO_DATA_ERROR          |
| -5    | AZO_DATA_ERROR_VERSION  |
| -6    | AZO_DATA_ERROR_BLOCKSIZE|

---

## References

- **LEA block cipher**: KS X 3246, TTAK.KO-12.0223 (South Korean standard)
- **PBKDF2**: RFC 8018 (PKCS #5 v2.1)
- **HMAC-SHA1**: RFC 2104
- **CRC-32**: ISO 3309, ITU-T V.42 (polynomial 0xEDB88320)
- **DEFLATE**: RFC 1951
- **bzip2**: Julian Seward, https://sourceware.org/bzip2/
- **LZMA**: Igor Pavlov, LZMA SDK
- **WinZip AE-2**: WinZip AES encryption specification
