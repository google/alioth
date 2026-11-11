// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! End-to-end integration test harness for `wasm-vmm` (`alioth-vmm`).
//!
//! External VM guest artifacts live outside the `alioth-vmm` git repository and are
//! referenced relative to the workspace root (`..`):
//! - `../linux-blobs/`: `bzImage`, `initramfs.cpio.gz`, and `alpine.raw`.
//! - `../motor-dev/motor-os/`: Motor OS checkout inside a `$MOTORH` (`../motor-dev`)
//!   workspace, whose release build populates `vm_images/release/{kloader,initrd,motor-os.qcow2}`.
//!   See <https://github.com/moturus/motor-os/blob/main/docs/build.md> for how this
//!   directory layout and its VM artifacts are built.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmmMode {
    Cwasm,
    Wasm,
}

impl VmmMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cwasm => "cwasm",
            Self::Wasm => "wasm",
        }
    }
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests crate must live directly under workspace root")
        .to_path_buf()
}

pub fn linux_blobs_dir() -> PathBuf {
    let raw = std::env::var_os("LINUX_BLOBS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("../linux-blobs"));
    fs::canonicalize(&raw).unwrap_or_else(|e| {
        panic!(
            "Linux blobs directory '{}' not found (override with LINUX_BLOBS_DIR): {e}",
            raw.display()
        )
    })
}

/// Resolves the Motor OS release artifacts directory (`../motor-dev/motor-os/vm_images/release`).
///
/// Motor OS builds inside a `$MOTORH` workspace directory (`../motor-dev`) alongside this
/// repository; see <https://github.com/moturus/motor-os/blob/main/docs/build.md>.
pub fn motor_os_release_dir() -> PathBuf {
    let raw = if let Some(dir) = std::env::var_os("MOTO_DIR") {
        PathBuf::from(dir)
    } else {
        let moto_root = std::env::var_os("MOTO_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| repo_root().join("../motor-dev/motor-os"));
        moto_root.join("vm_images/release")
    };
    fs::canonicalize(&raw).unwrap_or_else(|e| {
        panic!(
            "Motor OS release directory '{}' not found (see https://github.com/moturus/motor-os/blob/main/docs/build.md): {e}",
            raw.display()
        )
    })
}

pub fn ensure_vmm_artifacts() -> &'static Path {
    static ARTIFACT_DIR: OnceLock<PathBuf> = OnceLock::new();
    ARTIFACT_DIR.get_or_init(|| {
        let root = repo_root();
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let status = Command::new(&cargo)
            .arg("build")
            .arg("--manifest-path")
            .arg(root.join("Cargo.toml"))
            .arg("-p")
            .arg("vmm-core-host")
            .arg("-p")
            .arg("vmm-io-host")
            .arg("--release")
            .arg("--target=x86_64-unknown-linux-musl")
            .status()
            .expect("failed to invoke cargo build for wasm-vmm host/guest artifacts");
        assert!(
            status.success(),
            "cargo build for x86_64-unknown-linux-musl release artifacts failed"
        );

        let target_dir = root.join("target/x86_64-unknown-linux-musl/release");
        for artifact in [
            "vmm-io-host-cwasm",
            "vmm-io-host-wasm",
            "vmm-core-host-cwasm",
            "vmm-core-host-wasm",
            "vmm-io.cwasm",
            "vmm-io.wasm",
            "vmm-core.cwasm",
            "vmm-core.wasm",
        ] {
            let p = target_dir.join(artifact);
            assert!(
                p.is_file(),
                "expected built artifact '{}' missing",
                p.display()
            );
        }
        target_dir
    })
}

pub struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    pub fn new(prefix: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("wasm-vmm-test-{prefix}-{pid}-{id}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("failed to create temporary test directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct HostLock {
    _guard: MutexGuard<'static, ()>,
    lock_file: File,
}

impl HostLock {
    fn acquire(mutex: &'static Mutex<()>, lock_path: &Path) -> Self {
        let guard = mutex.lock().unwrap_or_else(|e| e.into_inner());
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)
            .unwrap_or_else(|e| panic!("failed to open lock file '{}': {e}", lock_path.display()));
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        assert_eq!(
            rc,
            0,
            "flock('{}') failed: {}",
            lock_path.display(),
            std::io::Error::last_os_error()
        );
        Self {
            _guard: guard,
            lock_file: file,
        }
    }
}

impl Drop for HostLock {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::flock(self.lock_file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn acquire_linux_lock() -> HostLock {
    static LINUX_MUTEX: Mutex<()> = Mutex::new(());
    let uid = unsafe { libc::getuid() };
    let path = std::env::var_os("LINUX_VM_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/tmp/wasm-vmm-linux.{uid}.lock")));
    HostLock::acquire(&LINUX_MUTEX, &path)
}

pub fn acquire_motor_os_lock() -> HostLock {
    static MOTOR_MUTEX: Mutex<()> = Mutex::new(());
    let uid = unsafe { libc::getuid() };
    let path = std::env::var_os("MOTO_QEMU_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/tmp/motor-os-qemu.{uid}.lock")));
    HostLock::acquire(&MOTOR_MUTEX, &path)
}

pub fn use_network_tap(tap_name: &str, setup_hint: &str) -> bool {
    if std::env::var_os("VMM_TEST_NO_NET").is_some() {
        return false;
    }
    let sysfs = Path::new("/sys/class/net").join(tap_name);
    assert!(
        sysfs.exists(),
        "host TAP interface '{tap_name}' not found ({setup_hint}); create the TAP device or set VMM_TEST_NO_NET=1"
    );
    true
}

pub fn copy_sparse_raw(src: &Path, dst: &Path) {
    let status = Command::new("cp")
        .arg("--reflink=auto")
        .arg("--sparse=always")
        .arg(src)
        .arg(dst)
        .status()
        .expect("failed to execute cp for sparse raw disk image");
    assert!(
        status.success(),
        "cp failed copying '{}' -> '{}'",
        src.display(),
        dst.display()
    );
}

pub fn convert_qcow2_to_raw(src_qcow2: &Path, dst_raw: &Path) {
    let status = Command::new("qemu-img")
        .arg("convert")
        .arg("-f")
        .arg("qcow2")
        .arg("-O")
        .arg("raw")
        .arg(src_qcow2)
        .arg(dst_raw)
        .status()
        .expect("failed to execute qemu-img (must be on PATH to convert Motor OS qcow2)");
    assert!(
        status.success(),
        "qemu-img convert failed for '{}' -> '{}'",
        src_qcow2.display(),
        dst_raw.display()
    );
}

struct ProcessGroupGuard {
    child: Child,
    armed: bool,
}

impl ProcessGroupGuard {
    fn new(child: Child) -> Self {
        Self { child, armed: true }
    }

    fn kill_group(&mut self) {
        let pgid = self.child.id() as libc::pid_t;
        if pgid > 0 {
            unsafe {
                let _ = libc::kill(-pgid, libc::SIGKILL);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            self.kill_group();
        }
    }
}

struct SerialCapture {
    buf: Vec<u8>,
    eof: bool,
}

/// Boots `wasm-vmm` in `mode` using `config_body`, waits until `expected_banner` appears
/// on the guest serial console, immediately sends `Ctrl-a q` (`\x01q`) to shut down the
/// VM cleanly, and asserts exit status `0`.
pub fn boot_and_shutdown(
    test_name: &str,
    mode: VmmMode,
    tmp: &TempTestDir,
    config_body: &str,
    expected_banner: &str,
    boot_timeout: Duration,
) {
    let target_dir = ensure_vmm_artifacts();
    let config_path = tmp.path().join("vm.toml");
    let log_path = tmp.path().join("vmm.log");
    let full_config = format!(
        "log_file = \"{}\"\nlog_level = \"info\"\n{config_body}",
        log_path.display()
    );
    fs::write(&config_path, &full_config).expect("failed to write test vm.toml");

    let (io_host, io_mod, core_host, core_mod) = match mode {
        VmmMode::Cwasm => (
            target_dir.join("vmm-io-host-cwasm"),
            target_dir.join("vmm-io.cwasm"),
            target_dir.join("vmm-core-host-cwasm"),
            target_dir.join("vmm-core.cwasm"),
        ),
        VmmMode::Wasm => (
            target_dir.join("vmm-io-host-wasm"),
            target_dir.join("vmm-io.wasm"),
            target_dir.join("vmm-core-host-wasm"),
            target_dir.join("vmm-core.wasm"),
        ),
    };

    let mut cmd = Command::new(&io_host);
    cmd.current_dir(tmp.path())
        .arg("-c")
        .arg(&config_path)
        .arg("-w")
        .arg(&io_mod)
        .arg("--core-host")
        .arg(&core_host)
        .arg("--core-wasm")
        .arg(&core_mod)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);

    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn '{}': {e}", io_host.display()));
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let mut guard = ProcessGroupGuard::new(child);

    let state = Arc::new((
        Mutex::new(SerialCapture {
            buf: Vec::with_capacity(8192),
            eof: false,
        }),
        Condvar::new(),
    ));
    let state_reader = Arc::clone(&state);
    let stdout_handle = thread::spawn(move || {
        let mut chunk = [0u8; 512];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) => {
                    let (lock, cvar) = &*state_reader;
                    lock.lock().unwrap().eof = true;
                    cvar.notify_all();
                    break;
                }
                Ok(n) => {
                    let (lock, cvar) = &*state_reader;
                    lock.lock().unwrap().buf.extend_from_slice(&chunk[..n]);
                    cvar.notify_all();
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    let (lock, cvar) = &*state_reader;
                    lock.lock().unwrap().eof = true;
                    cvar.notify_all();
                    break;
                }
            }
        }
    });

    let stderr_handle = thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stderr.read_to_end(&mut out);
        out
    });

    let deadline = Instant::now() + boot_timeout;
    let banner_bytes = expected_banner.as_bytes();
    let booted = {
        let (lock, cvar) = &*state;
        let mut cap = lock.lock().unwrap();
        loop {
            if cap
                .buf
                .windows(banner_bytes.len())
                .any(|w| w == banner_bytes)
            {
                break true;
            }
            if cap.eof {
                break false;
            }
            let now = Instant::now();
            if now >= deadline {
                break false;
            }
            let (next_cap, _) = cvar.wait_timeout(cap, deadline - now).unwrap();
            cap = next_cap;
        }
    };

    let format_diag = |reason: &str, serial: &[u8], stderr_bytes: &[u8]| -> String {
        let vmm_log = fs::read_to_string(&log_path).unwrap_or_default();
        format!(
            "[{test_name} ({})] {reason}\n--- vm.toml ---\n{full_config}\n--- serial stdout ---\n{}\n--- stderr ---\n{}\n--- vmm.log ---\n{vmm_log}",
            mode.as_str(),
            String::from_utf8_lossy(serial),
            String::from_utf8_lossy(stderr_bytes),
        )
    };

    if !booted {
        guard.kill_group();
        guard.armed = false;
        drop(stdin);
        let _ = stdout_handle.join();
        let stderr_bytes = stderr_handle.join().unwrap_or_default();
        let serial = state.0.lock().unwrap().buf.clone();
        panic!(
            "{}",
            format_diag(
                &format!(
                    "did not observe expected banner {expected_banner:?} within {boot_timeout:?}"
                ),
                &serial,
                &stderr_bytes,
            )
        );
    }

    // Immediately send `Ctrl-a q` to request clean VMM shutdown.
    let _ = stdin.write_all(b"\x01q");
    let _ = stdin.flush();
    drop(stdin);

    let shutdown_deadline = Instant::now() + Duration::from_secs(10);
    let exit_status = loop {
        match guard.child.try_wait().expect("try_wait failed") {
            Some(status) => {
                guard.armed = false;
                break Some(status);
            }
            None if Instant::now() >= shutdown_deadline => break None,
            None => thread::sleep(Duration::from_millis(20)),
        }
    };

    if exit_status.is_none() {
        guard.kill_group();
        guard.armed = false;
    }
    let _ = stdout_handle.join();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();
    let serial = state.0.lock().unwrap().buf.clone();

    let Some(status) = exit_status else {
        panic!(
            "{}",
            format_diag(
                "VM failed to exit within 10s after Ctrl-a q",
                &serial,
                &stderr_bytes
            )
        );
    };

    assert!(
        status.success(),
        "{}",
        format_diag(
            &format!("VM exited with non-zero status: {status}"),
            &serial,
            &stderr_bytes,
        )
    );
}
