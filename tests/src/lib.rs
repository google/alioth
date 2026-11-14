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

/// Magic constant at offset 0 of Motor OS's 512-byte `InitrdHeader`.
pub const INITRD_HEADER_MAGIC: u32 = 0xf402_100f;

/// 4 KiB page-aligned start offset of the `sys-io` (`test-init`) ELF inside `initrd-test-guest`.
///
/// Satisfies `kernel/src/init.rs`: `initrd.len() > 4096` and 4 KiB alignment for zero-copy
/// `place_sys_io` (`vmem_map_reserved_pages`).
pub const INITRD_SYS_IO_START: u32 = 4096;

/// Packs a stripped Motor OS PID 2 (`test-init`) ELF into a standalone `initrd-test-guest` image.
pub fn pack_test_guest_initrd(test_init_elf: &[u8]) -> Vec<u8> {
    assert!(
        !test_init_elf.is_empty(),
        "test-init ELF payload must not be empty"
    );
    let total_len = (INITRD_SYS_IO_START as usize)
        .checked_add(test_init_elf.len())
        .expect("initrd size overflow");
    let sys_io_end: u32 = total_len
        .try_into()
        .expect("initrd-test-guest exceeds u32::MAX bytes");

    let mut buf = vec![0u8; total_len];
    buf[0..4].copy_from_slice(&INITRD_HEADER_MAGIC.to_le_bytes());
    // Offsets [4..20] (`kloader_start`, `kloader_end`, `kernel_start`, `kernel_end`) stay 0:
    // PVH boot loads `kloader` (and its embedded `.kernel_image`) directly from the `kloader` ELF.
    buf[20..24].copy_from_slice(&INITRD_SYS_IO_START.to_le_bytes());
    buf[24..28].copy_from_slice(&sys_io_end.to_le_bytes());
    buf[INITRD_SYS_IO_START as usize..].copy_from_slice(test_init_elf);
    buf
}

pub fn write_test_guest_initrd(test_init_path: &Path, output_path: &Path) {
    let elf_bytes = fs::read(test_init_path).unwrap_or_else(|e| {
        panic!(
            "failed to read test-init ELF '{}': {e}",
            test_init_path.display()
        )
    });
    let initrd = pack_test_guest_initrd(&elf_bytes);
    fs::write(output_path, &initrd).unwrap_or_else(|e| {
        panic!(
            "failed to write initrd-test-guest '{}': {e}",
            output_path.display()
        )
    });
}

#[derive(Debug, Clone)]
pub struct TestGuestArtifacts {
    pub dir: PathBuf,
    pub kernel: PathBuf,
    pub kloader: PathBuf,
    pub test_init: PathBuf,
    pub initrd: PathBuf,
    pub vmm_core_motor_cwasm: PathBuf,
    pub nested_test_init: PathBuf,
    pub nested_initrd: PathBuf,
}

fn clear_host_rustup_env(cmd: &mut Command) {
    // Allow `tests/{kernel,kloader,test-init}/rust-toolchain.toml` to select the Motor OS
    // toolchain even when invoked from a host `stable` `cargo test` or `cargo run` process.
    cmd.env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("RUSTUP_TOOLCHAIN");
}

/// Builds `tests/kernel`, `tests/kloader`, `tests/test-init` (both leaf and nested Ring-3 VMM
/// bootstrap), and packs `initrd-test-guest` + `initrd-test-guest-nested` under `target/test-guest/`.
pub fn build_test_guest() -> TestGuestArtifacts {
    let vmm_dir = ensure_vmm_artifacts();
    let root = repo_root();
    let tests_dir = root.join("tests");
    let out_dir = root.join("target/test-guest");
    let obj_dir = out_dir.join("obj");
    fs::create_dir_all(&obj_dir).expect("failed to create target/test-guest/obj");

    let vmm_core_motor_cwasm = out_dir.join("vmm-core-motor.cwasm");
    fs::copy(vmm_dir.join("vmm-core-motor.cwasm"), &vmm_core_motor_cwasm)
        .expect("failed to copy vmm-core-motor.cwasm into target/test-guest");

    let mut kernel_cmd = Command::new(tests_dir.join("kernel/build.sh"));
    clear_host_rustup_env(&mut kernel_cmd);
    let status = kernel_cmd
        .arg("--release")
        .env("CARGO_TARGET_DIR", obj_dir.join("kernel"))
        .env("MOTO_BIN", &out_dir)
        .status()
        .expect("failed to execute tests/kernel/build.sh");
    assert!(status.success(), "tests/kernel/build.sh --release failed");

    let mut kloader_cmd = Command::new(tests_dir.join("kloader/build.sh"));
    clear_host_rustup_env(&mut kloader_cmd);
    let status = kloader_cmd
        .arg("--release")
        .env("CARGO_TARGET_DIR", obj_dir.join("kloader"))
        .env("MOTO_BIN", &out_dir)
        .status()
        .expect("failed to execute tests/kloader/build.sh");
    assert!(status.success(), "tests/kloader/build.sh --release failed");

    let test_init_dir = tests_dir.join("test-init");
    let test_init_obj = obj_dir.join("test-init");
    let mut init_cmd = Command::new("cargo");
    clear_host_rustup_env(&mut init_cmd);
    let status = init_cmd
        .current_dir(&test_init_dir)
        .arg("build")
        .arg("--offline")
        .arg("--release")
        .arg("--target")
        .arg("x86_64-unknown-motor")
        .env("CARGO_TARGET_DIR", &test_init_obj)
        .status()
        .expect("failed to invoke cargo build for tests/test-init");
    assert!(status.success(), "cargo build for tests/test-init failed");

    let unstripped_init = test_init_obj.join("x86_64-unknown-motor/release/test-init");
    let stripped_init = out_dir.join("test-init");
    let status = Command::new("strip")
        .arg("-o")
        .arg(&stripped_init)
        .arg(&unstripped_init)
        .status()
        .expect("failed to execute strip on test-init");
    assert!(status.success(), "strip failed for test-init");

    let initrd = out_dir.join("initrd-test-guest");
    write_test_guest_initrd(&stripped_init, &initrd);

    // Build nested `test-init` (`--features nested`), embedding `kloader`, leaf `initrd-test-guest`,
    // and `vmm-core-motor.cwasm` compiled from the byte-identical `vmm-core.wasm`.
    let nested_init_obj = obj_dir.join("test-init-nested");
    let mut nested_cmd = Command::new("cargo");
    clear_host_rustup_env(&mut nested_cmd);
    let status = nested_cmd
        .current_dir(&test_init_dir)
        .arg("build")
        .arg("--offline")
        .arg("--release")
        .arg("--features")
        .arg("nested")
        .arg("--target")
        .arg("x86_64-unknown-motor")
        .env("CARGO_TARGET_DIR", &nested_init_obj)
        .status()
        .expect("failed to invoke cargo build --features nested for tests/test-init");
    assert!(
        status.success(),
        "cargo build --features nested for tests/test-init failed"
    );

    let unstripped_nested = nested_init_obj.join("x86_64-unknown-motor/release/test-init");
    let stripped_nested = out_dir.join("test-init-nested");
    let status = Command::new("strip")
        .arg("-o")
        .arg(&stripped_nested)
        .arg(&unstripped_nested)
        .status()
        .expect("failed to execute strip on test-init-nested");
    assert!(status.success(), "strip failed for test-init-nested");

    let nested_initrd = out_dir.join("initrd-test-guest-nested");
    write_test_guest_initrd(&stripped_nested, &nested_initrd);

    let kernel = out_dir.join("kernel");
    let kloader = out_dir.join("kloader");
    for artifact in [
        &kernel,
        &kloader,
        &stripped_init,
        &initrd,
        &vmm_core_motor_cwasm,
        &stripped_nested,
        &nested_initrd,
    ] {
        assert!(
            artifact.is_file(),
            "expected test-guest artifact '{}' missing",
            artifact.display()
        );
    }

    TestGuestArtifacts {
        dir: out_dir,
        kernel,
        kloader,
        test_init: stripped_init,
        initrd,
        vmm_core_motor_cwasm,
        nested_test_init: stripped_nested,
        nested_initrd,
    }
}

pub fn ensure_test_guest_artifacts() -> &'static TestGuestArtifacts {
    static ARTIFACTS: OnceLock<TestGuestArtifacts> = OnceLock::new();
    ARTIFACTS.get_or_init(build_test_guest)
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
            "vmm-core-motor.cwasm",
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

/// Boots `wasm-vmm` in `mode` using `config_body` WITHOUT sending `Ctrl-a q`, waiting for the
/// guest to shut itself down autonomously (e.g. via ACPI S5), asserts exit status `0`, and
/// returns the captured serial console output.
pub fn boot_until_autonomous_exit(
    test_name: &str,
    mode: VmmMode,
    tmp: &TempTestDir,
    config_body: &str,
    timeout: Duration,
) -> String {
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
    let _stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let mut guard = ProcessGroupGuard::new(child);

    let stdout_handle = thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        out
    });
    let stderr_handle = thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stderr.read_to_end(&mut out);
        out
    });

    let deadline = Instant::now() + timeout;
    let exit_status = loop {
        match guard.child.try_wait().expect("try_wait failed") {
            Some(status) => {
                guard.armed = false;
                break Some(status);
            }
            None if Instant::now() >= deadline => break None,
            None => thread::sleep(Duration::from_millis(10)),
        }
    };

    if exit_status.is_none() {
        guard.kill_group();
        guard.armed = false;
    }
    drop(_stdin);
    let serial_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();

    let format_diag = |reason: &str| -> String {
        let vmm_log = fs::read_to_string(&log_path).unwrap_or_default();
        format!(
            "[{test_name} ({})] {reason}\n--- vm.toml ---\n{full_config}\n--- serial stdout ---\n{}\n--- stderr ---\n{}\n--- vmm.log ---\n{vmm_log}",
            mode.as_str(),
            String::from_utf8_lossy(&serial_bytes),
            String::from_utf8_lossy(&stderr_bytes),
        )
    };

    let Some(status) = exit_status else {
        panic!(
            "{}",
            format_diag(&format!(
                "VM did not shut down autonomously within {timeout:?}"
            ))
        );
    };

    assert!(
        status.success(),
        "{}",
        format_diag(&format!("VM exited with non-zero status: {status}"))
    );

    String::from_utf8_lossy(&serial_bytes).into_owned()
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_pack_test_guest_initrd_header_and_alignment() {
        let fake_elf = b"\x7fELFtest-init-payload";
        let image = pack_test_guest_initrd(fake_elf);

        assert!(image.len() > 4096);
        assert_eq!(image.len(), 4096 + fake_elf.len());

        let magic = u32::from_le_bytes(image[0..4].try_into().unwrap());
        let kloader_start = u32::from_le_bytes(image[4..8].try_into().unwrap());
        let kloader_end = u32::from_le_bytes(image[8..12].try_into().unwrap());
        let kernel_start = u32::from_le_bytes(image[12..16].try_into().unwrap());
        let kernel_end = u32::from_le_bytes(image[16..20].try_into().unwrap());
        let sys_io_start = u32::from_le_bytes(image[20..24].try_into().unwrap());
        let sys_io_end = u32::from_le_bytes(image[24..28].try_into().unwrap());

        assert_eq!(magic, INITRD_HEADER_MAGIC);
        assert_eq!(kloader_start, 0);
        assert_eq!(kloader_end, 0);
        assert_eq!(kernel_start, 0);
        assert_eq!(kernel_end, 0);
        assert_eq!(sys_io_start, INITRD_SYS_IO_START);
        assert_eq!(sys_io_start % 4096, 0);
        assert_eq!(sys_io_end as usize, image.len());
        assert!(image[28..4096].iter().all(|&b| b == 0));
        assert_eq!(&image[4096..], fake_elf);
    }
}
