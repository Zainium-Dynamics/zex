//! Universal package extraction engine for ZEX.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageFormat {
    /// Native `.zex`: zexc (magic ZEX1) wrapping tar
    Zex,
    /// `.tar.zst` / `.tzst` / Void `.xbps` (zstd)
    TarZst,
    /// `.tar.gz` / `.tgz` / Alpine `.apk`
    TarGz,
    /// `.tar.xz` / `.txz` / some `.xbps`
    TarXz,
    /// Plain `.tar`
    Tar,
}

impl std::fmt::Display for PackageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zex => write!(f, "zex"),
            Self::TarZst => write!(f, "tar.zst"),
            Self::TarGz => write!(f, "tar.gz"),
            Self::TarXz => write!(f, "tar.xz"),
            Self::Tar => write!(f, "tar"),
        }
    }
}

pub struct ExtractionResult {
    pub format: PackageFormat,
    #[allow(dead_code)]
    pub output_dir: PathBuf,
    pub files_extracted: usize,
}

/// Called from main.rs: `zex -e <file> [-o <dir>]`
pub fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Usage: zex extract <file> [--output <dir>]".into());
    }

    let file_path = Path::new(&args[0]);
    if !file_path.exists() {
        return Err(format!("File not found: {}", file_path.display()));
    }

    let output_dir = parse_output_dir(args).unwrap_or_else(|| {
        let stem = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("extracted");
        let clean = stem.strip_suffix(".tar").unwrap_or(stem);
        let parent = file_path.parent().unwrap_or(Path::new("."));
        parent.join(format!("{}_extracted", clean))
    });

    let format = detect_format(file_path).map_err(|e| format!("Format detection failed: {}", e))?;

    println!("  ▶ Detected format: {}", format);
    println!("  ▶ Extracting to: {}", output_dir.display());

    let result =
        extract(file_path, &output_dir).map_err(|e| format!("Extraction failed: {}", e))?;

    println!(
        "  ✓ Extracted {} files ({})",
        result.files_extracted, result.format
    );
    Ok(())
}

fn parse_output_dir(args: &[String]) -> Option<PathBuf> {
    for i in 0..args.len() {
        if matches!(args[i].as_str(), "-o" | "--out" | "--output") && i + 1 < args.len() {
            return Some(PathBuf::from(&args[i + 1]));
        }
    }
    None
}

/// Detect package format by extension first, then validate with magic bytes.
pub fn detect_format(path: &Path) -> io::Result<PackageFormat> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if name.ends_with(".zex") {
        return Ok(PackageFormat::Zex);
    }
    if name.ends_with(".tar.zst") || name.ends_with(".tzst") {
        return Ok(PackageFormat::TarZst);
    }
    if name.ends_with(".xbps") {
        return Ok(PackageFormat::TarZst);
    }
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".apk") {
        return Ok(PackageFormat::TarGz);
    }
    if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        return Ok(PackageFormat::TarXz);
    }
    if name.ends_with(".tar") {
        return Ok(PackageFormat::Tar);
    }

    let mut magic = [0u8; 8];
    let mut f = File::open(path)?;
    let n = f.read(&mut magic)?;
    if n < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File too small"));
    }

    if crate::zex_codec::is_zex_magic(&magic) {
        return Ok(PackageFormat::Zex);
    }
    if magic[0] == 0x28 && magic[1] == 0xB5 && magic[2] == 0x2F && magic[3] == 0xFD {
        return Ok(PackageFormat::TarZst);
    }
    if magic[0] == 0x1F && magic[1] == 0x8B {
        return Ok(PackageFormat::TarGz);
    }
    if n >= 6
        && magic[0] == 0xFD
        && magic[1] == 0x37
        && magic[2] == 0x7A
        && magic[3] == 0x58
        && magic[4] == 0x5A
        && magic[5] == 0x00
    {
        return Ok(PackageFormat::TarXz);
    }

    let mut ustar = [0u8; 5];
    f.seek(SeekFrom::Start(257))?;
    if f.read(&mut ustar).is_ok() && &ustar == b"ustar" {
        return Ok(PackageFormat::Tar);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Unknown package format: {}", path.display()),
    ))
}

pub fn extract(path: &Path, output_dir: &Path) -> io::Result<ExtractionResult> {
    let format = detect_format(path)?;
    fs::create_dir_all(output_dir)?;

    let files = match format {
        PackageFormat::Zex => extract_zex(path, output_dir)?,
        PackageFormat::TarZst => extract_tar_zst(path, output_dir)?,
        PackageFormat::TarGz => extract_tar_gz(path, output_dir)?,
        PackageFormat::TarXz => extract_tar_xz(path, output_dir)?,
        PackageFormat::Tar => extract_tar(path, output_dir)?,
    };

    Ok(ExtractionResult {
        format,
        output_dir: output_dir.to_path_buf(),
        files_extracted: files,
    })
}

fn extract_zex(path: &Path, output_dir: &Path) -> io::Result<usize> {
    let decoder = crate::zex_codec::open_decoder(path)?;
    unpack_tar(decoder, output_dir)
}

fn extract_tar_zst(path: &Path, output_dir: &Path) -> io::Result<usize> {
    let file = File::open(path)?;
    let decoder =
        zstd::stream::read::Decoder::new(BufReader::new(file)).map_err(io::Error::other)?;
    unpack_tar(decoder, output_dir)
}

fn extract_tar_gz(path: &Path, output_dir: &Path) -> io::Result<usize> {
    let file = File::open(path)?;
    let decoder = flate2::read::MultiGzDecoder::new(BufReader::new(file));
    unpack_tar(decoder, output_dir)
}

fn extract_tar_xz(path: &Path, output_dir: &Path) -> io::Result<usize> {
    let file = File::open(path)?;
    let decoder = xz2::read::XzDecoder::new(BufReader::new(file));
    unpack_tar(decoder, output_dir)
}

fn extract_tar(path: &Path, output_dir: &Path) -> io::Result<usize> {
    let file = File::open(path)?;
    unpack_tar(BufReader::new(file), output_dir)
}

fn unpack_tar<R: Read>(reader: R, output_dir: &Path) -> io::Result<usize> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    let confined = crate::archive_safety::ConfinedRoot::open(output_dir).ok();
    #[cfg(not(unix))]
    let confined: Option<()> = None;

    let mut archive = tar::Archive::new(reader);
    archive.set_overwrite(true);

    let mut count = 0usize;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.as_os_str().is_empty() || path == Path::new(".") {
            continue;
        }

        let clean =
            crate::archive_safety::sanitize_archive_path(&path).map_err(io::Error::other)?;

        let dest =
            crate::archive_safety::safe_join_under(output_dir, &clean).map_err(io::Error::other)?;

        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            fs::create_dir_all(&dest)?;
            continue;
        }

        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
        }

        if entry_type.is_file() {
            #[cfg(unix)]
            let tar_mode = entry.header().mode().unwrap_or(0o644);

            #[cfg(unix)]
            if let Some(ref root) = confined {
                root.write_file(&clean, &mut entry)
                    .map_err(io::Error::other)?;
            } else {
                crate::archive_safety::write_archive_file(&dest, &mut entry)
                    .map_err(io::Error::other)?;
            }
            #[cfg(not(unix))]
            crate::archive_safety::write_archive_file(&dest, &mut entry)
                .map_err(io::Error::other)?;
            #[cfg(unix)]
            {
                let mut perms = fs::metadata(&dest)?.permissions();
                perms.set_mode(tar_mode & !0o6000);
                fs::set_permissions(&dest, perms)?;
            }
            count += 1;
            continue;
        }

        #[cfg(unix)]
        if entry_type.is_symlink() {
            let link_target = entry.link_name()?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "symlink missing target")
            })?;
            let safe_target = crate::archive_safety::sanitize_link_target(&path, &link_target)
                .map_err(io::Error::other)?;
            crate::archive_safety::create_sanitized_symlink(&safe_target, &dest)
                .map_err(io::Error::other)?;
            count += 1;
            continue;
        }

        if entry_type.is_hard_link() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "hard links are not supported in extract: {}",
                    path.display()
                ),
            ));
        }
    }

    Ok(count)
}
