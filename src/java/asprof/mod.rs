mod asprof;
mod extract;

use std::{
    fs::{self, File},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

struct Distribution {
    extracted_dir: String,
    version: i32,
}

impl Distribution {
    fn new(extracted_dir: String, version: i32) -> Self {
        Distribution {
            extracted_dir,
            version,
        }
    }

    fn binary_launcher(&self) -> bool {
        self.version >= 210
    }

    fn lib_path(&self) -> String {
        if self.binary_launcher() {
            format!("{}/lib/libasyncProfiler.so", self.extracted_dir)
        } else {
            format!("{}/build/libasyncProfiler.so", self.extracted_dir)
        }
    }

    fn jattach_path(&self) -> String {
        if self.binary_launcher() {
            String::new()
        } else {
            format!("{}/build/jattach", self.extracted_dir)
        }
    }

    fn launcher_path(&self) -> String {
        if self.binary_launcher() {
            format!("{}/bin/asprof", self.extracted_dir)
        } else {
            format!("{}/profiler.sh", self.extracted_dir)
        }
    }
}

struct Profiler {
    tmp_dir: String,
    glibc_dist: Distribution,
    musl_dist: Distribution,
    tmp_dir_marker: String,
    archive_hash: String,
    archive_data: Vec<u8>,
}

impl Profiler {
    fn new(tmp_dir: String, archive_data: Vec<u8>, version: i32) -> Self {
        let archive_hash = format!("{:x}", sha1::Sha1::from(archive_data));
        Profiler {
            tmp_dir,
            glibc_dist: Distribution::new(format!("{}-glibc-{}", tmp_dir, archive_hash), version),
            musl_dist: Distribution::new(format!("{}-musl-{}", tmp_dir, archive_hash), version),
            tmp_dir_marker: "grafana-agent-asprof".to_string(),
            archive_hash,
            archive_data,
        }
    }

    fn execute(&self, dist: &Distribution, argv: Vec<&str>) -> io::Result<(String, String)> {
        let exe = &dist.launcher_path();
        let mut cmd = Command::new(exe);
        for arg in argv {
            cmd.arg(arg);
        }
        let output = cmd.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok((stdout, stderr))
    }

    fn copy_lib(&self, dist: &Distribution, pid: i32) -> io::Result<()> {
        let lib_data = fs::read(&dist.lib_path())?;
        let launcher_data = fs::read(&dist.launcher_path())?;
        let proc_root = process_path("/", pid);
        let mut proc_root_file = File::open(proc_root)?;
        let dst_lib_path = dist.lib_path().replace("/", "");
        let dst_launcher_path = dist.launcher_path().replace("/", "");
        write_file(&mut proc_root_file, &dst_lib_path, &lib_data, false)?;
        write_file(&mut proc_root_file, &dst_launcher_path, &launcher_data, false)?;
        Ok(())
    }

    fn distribution_for_process(&self, pid: i32) -> io::Result<Distribution> {
        let maps = proc_maps(pid)?;
        let mut musl = false;
        let mut glibc = false;
        for m in maps {
            if is_musl_mapping(&m) {
                musl = true;
            }
            if is_glibc_mapping(&m) {
                glibc = true;
            }
        }
        if musl && glibc {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to select dist for pid {}: both musl and glibc found", pid),
            ));
        }
        if musl {
            Ok(self.musl_dist.clone())
        } else if glibc {
            Ok(self.glibc_dist.clone())
        } else if Path::new(&process_path("/lib/ld-musl-x86_64.so.1", pid)).exists() {
            Ok(self.musl_dist.clone())
        } else if Path::new(&process_path("/lib/ld-musl-aarch64.so.1", pid)).exists() {
            Ok(self.musl_dist.clone())
        } else if Path::new(&process_path("/lib64/ld-linux-x86-64.so.2", pid)).exists() {
            Ok(self.glibc_dist.clone())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to select dist for pid {}: neither musl nor glibc found", pid),
            ))
        }
    }

    fn extract_distributions(&self) -> io::Result<()> {
        unimplemented!()
    }
}

fn process_path(path: &str, pid: i32) -> String {
    format!("/proc/{}/root{}", pid, path)
}

fn proc_maps(pid: i32) -> io::Result<Vec<ProcMap>> {
    let file = File::open(format!("/proc/{}/maps", pid))?;
    let reader = BufReader::new(file);
    let mut maps = Vec::new();
    for line in reader.lines() {
        let line = line?;
        maps.push(ProcMap { pathname: line });
    }
    Ok(maps)
}

struct ProcMap {
    pathname: String,
}

fn is_musl_mapping(map: &ProcMap) -> bool {
    map.pathname.contains("/lib/ld-musl-x86_64.so.1") || map.pathname.contains("/lib/ld-musl-aarch64.so.1")
}

fn is_glibc_mapping(map: &ProcMap) -> bool {
    map.pathname.ends_with("/libc.so.6") || map.pathname.contains("x86_64-linux-gnu/libc-")
}

fn write_file(file: &mut File, path: &str, data: &[u8], _flag: bool) -> io::Result<()> {
    let full_path = format!("{}/{}", file.path().display(), path);
    let mut new_file = File::create(full_path)?;
    new_file.write_all(data)?;
    Ok(())
}

fn main() {
    // main 함수에서는 프로파일러 및 배포 관련 작업을 수행합니다.
}
