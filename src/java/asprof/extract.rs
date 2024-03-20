use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const EXTRACT_PERM: u32 = 0o755;

fn read_tar_gz(buf: &[u8], cb: impl FnMut(&str, &fs::Metadata, &[u8]) -> io::Result<()>) -> io::Result<()> {
    let mut gzip_reader = flate2::read::GzDecoder::new(buf);
    let mut tar_reader = tar::Archive::new(gzip_reader);
    for entry in tar_reader.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        let metadata = entry.header().entry().unwrap();
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        cb(&path, metadata, &data)?;
    }
    Ok(())
}

fn write_file(dir: &Path, path: &str, data: &[u8], do_ownership_checks: bool) -> io::Result<()> {
    let mut parts = path.split('/');
    let file_name = parts.next_back().unwrap();
    let dir_path = parts.collect::<PathBuf>();
    let mut it = File::open(&dir_path)?;
    if !dir_path.exists() {
        fs::create_dir_all(&dir_path)?;
    }
    let mut it = it;
    for part in parts {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(&dir_path.join(part))?;
        it = f;
    }

    if do_ownership_checks {
        check_extract_file(&it, dir)?;
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(EXTRACT_PERM)
        .open(dir.join(file_name))?;

    if do_ownership_checks {
        check_extract_file(&file, dir)?;
    }

    file.write_all(data)?;
    Ok(())
}

fn check_extract_file(file: &File, parent: &Path) -> io::Result<()> {
    let file_metadata = file.metadata()?;
    let parent_metadata = parent.metadata()?;

    let file_uid = file_metadata.uid();
    let file_perms = file_metadata.permissions().mode();
    let parent_dev = parent_metadata.dev();

    if file_uid == Some(users::get_current_uid()) as u32 && file_perms == EXTRACT_PERM {
        Ok(())
    } else if users::get_current_uid() == 0 && parent_metadata.permissions().mode() & 0o1000 != 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Invalid permissions or ownership for file: {:?}, parent: {:?}",
                file_metadata, parent_metadata
            ),
        ))
    }
}

fn check_temp_dir_permissions(tmp_dir_file: &Path) -> io::Result<()> {
    let tmp_dir_file_metadata = tmp_dir_file.metadata()?;
    let tmp_dir_file_uid = tmp_dir_file_metadata.uid();
    let tmp_dir_file_perms = tmp_dir_file_metadata.permissions().mode();

    if tmp_dir_file_metadata.is_dir() {
        if tmp_dir_file_uid == Some(users::get_current_uid()) as u32 && tmp_dir_file_perms == EXTRACT_PERM {
            Ok(())
        } else if users::get_current_uid() == 0 && tmp_dir_file_metadata.permissions().mode() & 0o1000 != 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Invalid permissions or ownership for temp directory: {:?}",
                    tmp_dir_file_metadata
                ),
            ))
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "Temporary directory is not a directory",
        ))
    }
}