use std::fs;
use std::io::{self, BufReader, Read, Seek};
use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;

use unegg_rs::archive::EggArchive;
use unegg_rs::extract;
use unegg_rs::volume::MultiVolumeReader;

#[derive(Parser)]
#[command(name = "unegg", about = "EGG archive extractor", version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// List contents of archive
    #[arg(short = 'l', long = "list")]
    list: bool,

    /// Extract files to pipe (stdout), suppress messages
    #[arg(short = 'p')]
    pipe: bool,

    /// Set output directory
    #[arg(short = 'd', value_name = "DIR")]
    dest_dir: Option<String>,

    /// Set password
    #[arg(long = "pwd", value_name = "PASSWORD")]
    password: Option<String>,

    /// Archive file (.egg), or "-" for stdin
    archive: String,

    /// Files to extract (if empty, extract all)
    files: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(&cli) {
        eprintln!("unegg: {e}");
        process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.archive == "-" {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        let reader = io::Cursor::new(data);
        let mut archive = EggArchive::open(reader)?;
        return run_archive(&mut archive, cli);
    }

    let path = Path::new(&cli.archive);

    // Check for multi-volume archive
    if let Some(mvr) = MultiVolumeReader::try_open(path)? {
        let vol_count = mvr.volume_count();
        let mut archive = EggArchive::open(mvr)?;
        if !cli.pipe {
            eprintln!("split archive: {vol_count} volumes");
        }
        return run_archive(&mut archive, cli);
    }

    let file = fs::File::open(path).map_err(unegg_rs::error::EggError::CantOpenFile)?;
    let reader = BufReader::new(file);
    let mut archive = EggArchive::open(reader)?;
    run_archive(&mut archive, cli)
}

fn run_archive<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    if cli.list {
        list_archive(archive);
        return Ok(());
    }

    let dest_dir = PathBuf::from(cli.dest_dir.as_deref().unwrap_or("."));
    let password = cli.password.as_deref();
    let pipe_mode = cli.pipe;

    if cli.files.is_empty() {
        extract::extract_all(archive, &dest_dir, password, pipe_mode)?;
    } else {
        extract::extract_files(archive, &dest_dir, password, pipe_mode, &cli.files)?;
    }

    if !pipe_mode {
        eprintln!("extracted {} entries", archive.entries.len());
    }
    Ok(())
}

fn list_archive<R: io::Read + io::Seek>(archive: &EggArchive<R>) {
    if archive.is_solid {
        eprintln!("[solid archive]");
    }
    if archive.split_info.is_some() {
        eprintln!("[split archive]");
    }

    for entry in &archive.entries {
        let method = if entry.blocks.is_empty() {
            "-".to_string()
        } else {
            entry.blocks[0].compression_method.name().to_string()
        };

        let enc = if entry.encrypt_info.is_some() {
            "*"
        } else {
            " "
        };

        let time_str = match entry.file_time {
            Some(ft) => format_filetime(ft),
            None => "                   ".to_string(),
        };

        let dir_marker = if entry.is_directory() { "D" } else { " " };

        println!(
            "{dir_marker}{enc} {size:>12}  {method:<7}  {time}  {name}",
            size = entry.uncompressed_size,
            method = method,
            time = time_str,
            name = entry.file_name,
        );
    }
}

fn format_filetime(filetime_val: u64) -> String {
    const EPOCH_DIFF: u64 = 11644473600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    if filetime_val < EPOCH_DIFF * TICKS_PER_SEC {
        return "                   ".to_string();
    }

    let unix_secs = (filetime_val / TICKS_PER_SEC).saturating_sub(EPOCH_DIFF);

    let days = unix_secs / 86400;
    let time_of_day = unix_secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
