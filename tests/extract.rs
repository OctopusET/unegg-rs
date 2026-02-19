/// Integration tests against real EGG archives.
/// These tests are skipped if the test archives don't exist.
use std::path::Path;

const SOURCE_DIR: &str = "testdata/source";
const EGG_DIR: &str = "testdata/egg";
const PASSWORD: &str = "test1234";

/// Files expected in all non-split archives.
const EXPECTED_FILES: &[&str] = &[
    "hello.txt",
    "repeated.txt",
    "binary.bin",
    "empty.txt",
    "euckr_content.txt",
    "large.txt",
    "subdir/inner.txt",
    "subdir/nested/deep.txt",
];

/// Files with Korean filenames (UTF-8 in EGG).
const KOREAN_FILES: &[&str] = &[
    "\u{BDC1}\u{D14C}\u{C2A4}\u{D2B8}.txt", // 뷁테스트.txt
    "\u{D55C}\u{AE00}\u{D30C}\u{C77C}.txt", // 한글파일.txt
];

fn skip_if_missing(path: &str) -> bool {
    if !Path::new(path).exists() {
        eprintln!("SKIP: {path} not found");
        return true;
    }
    false
}

fn extract_and_verify(egg_path: &str, password: Option<&str>) {
    if skip_if_missing(egg_path) {
        return;
    }

    let tmpdir = std::env::temp_dir().join(format!(
        "unegg_real_{}",
        Path::new(egg_path).file_stem().unwrap().to_str().unwrap()
    ));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let file = std::fs::File::open(egg_path).unwrap();
    let mut archive = unegg_rs::archive::EggArchive::open(file).unwrap();
    unegg_rs::extract::extract_all(&mut archive, &tmpdir, password, false).unwrap();

    // Verify all expected files
    for &name in EXPECTED_FILES.iter().chain(KOREAN_FILES.iter()) {
        let src = Path::new(SOURCE_DIR).join(name);
        let dst = tmpdir.join(name);
        assert!(dst.exists(), "missing: {name} in {egg_path}");
        let src_data = std::fs::read(&src).unwrap();
        let dst_data = std::fs::read(&dst).unwrap();
        assert_eq!(src_data, dst_data, "content mismatch: {name} in {egg_path}");
    }

    let _ = std::fs::remove_dir_all(&tmpdir);
}

// --- Compression methods ---

#[test]
fn test_real_store() {
    extract_and_verify(&format!("{EGG_DIR}/store.egg"), None);
}

#[test]
fn test_real_optimal() {
    // Optimal uses Bzip2 for text, Deflate for binary
    extract_and_verify(&format!("{EGG_DIR}/optimal.egg"), None);
}

#[test]
fn test_real_max() {
    // Max uses LZMA
    extract_and_verify(&format!("{EGG_DIR}/max.egg"), None);
}

#[test]
fn test_real_normal() {
    // Normal uses Deflate
    extract_and_verify(&format!("{EGG_DIR}/normal.egg"), None);
}

#[test]
fn test_real_low() {
    // Low uses Deflate
    extract_and_verify(&format!("{EGG_DIR}/low.egg"), None);
}

// --- Solid archives ---

#[test]
fn test_real_solid_low() {
    extract_and_verify(&format!("{EGG_DIR}/solid_low.egg"), None);
}

#[test]
fn test_real_solid_max() {
    extract_and_verify(&format!("{EGG_DIR}/solid_max.egg"), None);
}

// --- Encryption ---

#[test]
fn test_real_zip20() {
    extract_and_verify(&format!("{EGG_DIR}/zip20.egg"), Some(PASSWORD));
}

#[test]
fn test_real_aes128() {
    extract_and_verify(&format!("{EGG_DIR}/aes128.egg"), Some(PASSWORD));
}

#[test]
fn test_real_aes256() {
    extract_and_verify(&format!("{EGG_DIR}/aes256.egg"), Some(PASSWORD));
}

#[test]
fn test_real_lea128() {
    extract_and_verify(&format!("{EGG_DIR}/lea128.egg"), Some(PASSWORD));
}

#[test]
fn test_real_lea256() {
    extract_and_verify(&format!("{EGG_DIR}/lea256.egg"), Some(PASSWORD));
}

// --- Split archive ---

#[test]
fn test_real_split() {
    let vol1 = format!("{EGG_DIR}/split.vol1.egg");
    if skip_if_missing(&vol1) {
        return;
    }

    let tmpdir = std::env::temp_dir().join("unegg_real_split");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let mvr = unegg_rs::volume::MultiVolumeReader::try_open(Path::new(&vol1))
        .unwrap()
        .expect("should detect split archive");
    assert!(mvr.volume_count() > 1);

    let mut archive = unegg_rs::archive::EggArchive::open(mvr).unwrap();
    unegg_rs::extract::extract_all(&mut archive, &tmpdir, None, false).unwrap();

    // Split archive contains large_10M.txt
    let src = Path::new(SOURCE_DIR).join("large_10M.txt");
    let dst = tmpdir.join("large_10M.txt");
    assert!(dst.exists(), "missing: large_10M.txt in split archive");
    let src_data = std::fs::read(&src).unwrap();
    let dst_data = std::fs::read(&dst).unwrap();
    assert_eq!(src_data, dst_data, "content mismatch: large_10M.txt");

    let _ = std::fs::remove_dir_all(&tmpdir);
}
