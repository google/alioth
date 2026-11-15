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
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr::null_mut;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L0Engine {
    Wasm(VmmMode),
    Chv,
}

impl L0Engine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wasm(VmmMode::Cwasm) => "wasm-cwasm",
            Self::Wasm(VmmMode::Wasm) => "wasm-wasm",
            Self::Chv => "chv",
        }
    }
}

pub fn find_chv_binary() -> PathBuf {
    if let Some(env_p) = std::env::var_os("CHV_BIN") {
        let p = PathBuf::from(env_p);
        assert!(
            p.is_file(),
            "CHV_BIN='{}' does not point to an existing binary",
            p.display()
        );
        return p;
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let cand = dir.join("cloud-hypervisor-static");
            if cand.is_file() {
                return cand;
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let cand = PathBuf::from(home).join("bin/cloud-hypervisor-static");
        if cand.is_file() {
            return cand;
        }
    }
    panic!("cloud-hypervisor-static not found in PATH or ~/bin (set CHV_BIN)");
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

pub const INITRD_BUNDLE_MAGIC: [u8; 8] = *b"MVMMBNDL";
pub const INITRD_BUNDLE_VERSION: u32 = 1;
pub const INITRD_BUNDLE_HEADER_SIZE: usize = 64;

/// Packs a stripped PID 2 (`test-init`) ELF plus a 4 KiB-aligned `InitrdBundle`
/// trailer (`vm.toml` + `vmm-core-motor.cwasm` + L2 `kernel` + optional L2 `initramfs`)
/// into a standalone `initrd-passthrough` image (4 KiB-padded).
pub fn pack_passthrough_initrd(
    test_init_elf: &[u8],
    vm_toml: &[u8],
    core_cwasm: &[u8],
    l2_kernel: &[u8],
    l2_initramfs: &[u8],
) -> Vec<u8> {
    let mut buf = pack_test_guest_initrd(test_init_elf);
    let bundle_off = buf.len().next_multiple_of(4096);
    buf.resize(bundle_off, 0);

    let mut hdr = [0u8; INITRD_BUNDLE_HEADER_SIZE];
    hdr[0..8].copy_from_slice(&INITRD_BUNDLE_MAGIC);
    hdr[8..12].copy_from_slice(&INITRD_BUNDLE_VERSION.to_le_bytes());
    hdr[16..24].copy_from_slice(&(vm_toml.len() as u64).to_le_bytes());
    hdr[24..32].copy_from_slice(&(core_cwasm.len() as u64).to_le_bytes());
    hdr[32..40].copy_from_slice(&(l2_kernel.len() as u64).to_le_bytes());
    hdr[40..48].copy_from_slice(&(l2_initramfs.len() as u64).to_le_bytes());

    buf.extend_from_slice(&hdr);
    buf.extend_from_slice(vm_toml);
    buf.extend_from_slice(core_cwasm);
    buf.extend_from_slice(l2_kernel);
    buf.extend_from_slice(l2_initramfs);

    let final_len = buf.len().next_multiple_of(4096);
    buf.resize(final_len, 0);
    buf
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
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("CARGO_NET_OFFLINE", "true");
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

#[derive(Debug, Clone)]
pub struct LinuxAirlockArtifacts {
    pub dir: PathBuf,
    pub bzimage: PathBuf,
    pub airlock_ko: PathBuf,
    pub irqbypass_ko: PathBuf,
    pub kvm_ko: PathBuf,
    pub kvm_amd_ko: PathBuf,
    pub ioctl_check: PathBuf,
}

/// Builds the out-of-tree L1 Linux kernel (`target/linux-kbuild` from `../linux-stable`,
/// leaving `../linux-stable` untouched) plus out-of-tree `airlock.ko` (`vmm-core-kmod/`).
pub fn build_linux_airlock() -> LinuxAirlockArtifacts {
    let _ = ensure_vmm_artifacts();
    let root = repo_root();
    let out_dir = root.join("target/airlock");
    let build_script = root.join("vmm-core-kmod/build.sh");

    let mut cmd = Command::new(&build_script);
    clear_host_rustup_env(&mut cmd);
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to execute '{}': {e}", build_script.display()));
    assert!(status.success(), "vmm-core-kmod/build.sh failed");

    let bzimage = out_dir.join("bzImage");
    let airlock_ko = out_dir.join("airlock.ko");
    let irqbypass_ko = out_dir.join("irqbypass.ko");
    let kvm_ko = out_dir.join("kvm.ko");
    let kvm_amd_ko = out_dir.join("kvm-amd.ko");
    let ioctl_check = out_dir.join("airlock-ioctl-check");

    for artifact in [
        &bzimage,
        &airlock_ko,
        &irqbypass_ko,
        &kvm_ko,
        &kvm_amd_ko,
        &ioctl_check,
    ] {
        assert!(
            artifact.is_file(),
            "expected Linux airlock artifact '{}' missing",
            artifact.display()
        );
    }

    LinuxAirlockArtifacts {
        dir: out_dir,
        bzimage,
        airlock_ko,
        irqbypass_ko,
        kvm_ko,
        kvm_amd_ko,
        ioctl_check,
    }
}

pub fn ensure_linux_airlock_artifacts() -> &'static LinuxAirlockArtifacts {
    static AIRLOCK_ARTIFACTS: OnceLock<LinuxAirlockArtifacts> = OnceLock::new();
    AIRLOCK_ARTIFACTS.get_or_init(build_linux_airlock)
}

pub enum CpioEntry<'a> {
    Dir { path: &'a str, mode: u32 },
    File { path: &'a str, mode: u32, data: &'a [u8] },
}

/// Packs a sequence of directories and files into a standard SVR4 `newc` (`070701`) cpio archive.
/// Linux's `init/initramfs.c` natively unpacks multiple concatenated compressed/uncompressed
/// `newc` archives, allowing fast in-memory overlays onto `initramfs.cpio.gz`.
pub fn pack_newc_cpio(entries: &[CpioEntry<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ino: u32 = 300_000;

    let push_record = |out: &mut Vec<u8>, ino: u32, mode: u32, nlink: u32, name: &str, data: &[u8]| {
        let namesize = name.len() + 1;
        let hdr = format!(
            "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{filesize:08x}\
             {maj:08x}{min:08x}{rmaj:08x}{rmin:08x}{namesize:08x}{chksum:08x}",
            uid = 0u32,
            gid = 0u32,
            mtime = 0u32,
            filesize = data.len() as u32,
            maj = 0u32,
            min = 0u32,
            rmaj = 0u32,
            rmin = 0u32,
            chksum = 0u32,
        );
        debug_assert_eq!(hdr.len(), 110);
        out.extend_from_slice(hdr.as_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        let pad_hdr = (4 - (out.len() % 4)) % 4;
        out.resize(out.len() + pad_hdr, 0);
        out.extend_from_slice(data);
        let pad_data = (4 - (out.len() % 4)) % 4;
        out.resize(out.len() + pad_data, 0);
    };

    for entry in entries {
        ino += 1;
        match entry {
            CpioEntry::Dir { path, mode } => {
                let clean = path.trim_matches('/');
                push_record(&mut out, ino, 0o040000 | (mode & 0o7777), 2, clean, &[]);
            }
            CpioEntry::File { path, mode, data } => {
                let clean = path.trim_matches('/');
                push_record(&mut out, ino, 0o100000 | (mode & 0o7777), 1, clean, data);
            }
        }
    }

    push_record(&mut out, 0, 0, 1, "TRAILER!!!", &[]);
    out
}

pub fn append_cpio_overlay(base_initramfs: &[u8], entries: &[CpioEntry<'_>]) -> Vec<u8> {
    let overlay = pack_newc_cpio(entries);
    let aligned_base = base_initramfs.len().next_multiple_of(4);
    let mut combined = Vec::with_capacity(aligned_base + overlay.len());
    combined.extend_from_slice(base_initramfs);
    combined.resize(aligned_base, 0);
    combined.extend_from_slice(&overlay);
    combined
}

#[derive(Debug, Clone)]
pub struct NestedMotorOsArtifacts {
    pub l1_kloader: PathBuf,
    pub l1_initrd: PathBuf,
    pub l1_template_raw: PathBuf,
    pub ssh_key: PathBuf,
}

fn run_imager(imager: &Path, args: &[&str]) {
    let status = Command::new(imager)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to execute '{}': {e}", imager.display()));
    assert!(
        status.success(),
        "imager command failed: {} {}",
        imager.display(),
        args.join(" ")
    );
}

pub fn ensure_motor_io_host_artifacts() -> &'static Path {
    static MOTOR_OUT: OnceLock<PathBuf> = OnceLock::new();
    MOTOR_OUT.get_or_init(|| {
        let _ = ensure_vmm_artifacts();
        let root = repo_root();
        let motor_out = root.join("target/motor");
        let mut build_cmd = Command::new(root.join("tests/motor-io-host/build.sh"));
        clear_host_rustup_env(&mut build_cmd);
        let status = build_cmd
            .env("MOTO_VMM_OUT", &motor_out)
            .status()
            .expect("failed to execute tests/motor-io-host/build.sh");
        assert!(status.success(), "tests/motor-io-host/build.sh failed");
        motor_out
    })
}

fn build_nested_motor_os_artifacts() -> NestedMotorOsArtifacts {
    let guest = ensure_test_guest_artifacts();
    let motor_out = ensure_motor_io_host_artifacts();
    let moto_dir = motor_os_release_dir();
    let imager = moto_dir.join("tools/imager");
    let qcow2 = moto_dir.join("motor-os.qcow2");
    let l1_initrd = moto_dir.join("initrd");
    let stock_kloader = moto_dir.join("kloader");
    let ssh_key = moto_dir.join("test.key");

    for required in [&imager, &qcow2, &l1_initrd, &stock_kloader, &ssh_key] {
        assert!(
            required.is_file(),
            "missing required Motor OS release artifact '{}'",
            required.display()
        );
    }

    let stage_dir = motor_out.join("nested-moto-stage");
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir).expect("failed to create target/motor/nested-moto-stage");

    let l2_raw = stage_dir.join("l2-motor-os.raw");
    convert_qcow2_to_raw(&qcow2, &l2_raw);

    let l2_net_toml = stage_dir.join("l2-sys-net.toml");
    fs::write(
        &l2_net_toml,
        "auto_icmp_echo_reply = true\n\
         loopback = true\n\
         max_icmp_error_rate = 200\n\
         max_rst_rate = 200\n\
         max_syn_cookie_rate = 1000\n\n\
         [devices.net0]\n\
         mac = \"a4:a1:c2:00:00:02\"\n\
         cidrs = [\"192.168.5.2/24\"]\n\
         dns_servers = [\"8.8.8.8\"]\n\n\
         [[devices.net0.routes]]\n\
         ip_network = \"0.0.0.0/0\"\n\
         gateway = \"192.168.5.1\"\n",
    )
    .expect("failed to write l2-sys-net.toml");
    run_imager(
        &imager,
        &[
            "put",
            l2_raw.to_str().unwrap(),
            l2_net_toml.to_str().unwrap(),
            "/system/cfg/sys-net.toml",
        ],
    );

    let l1_template_raw = motor_out.join("l1-nested-template.raw");
    let _ = fs::remove_file(&l1_template_raw);
    run_imager(
        &imager,
        &[
            "resize",
            "-i",
            qcow2.to_str().unwrap(),
            "-o",
            l1_template_raw.to_str().unwrap(),
            "--size",
            "768M",
        ],
    );

    let l1_init_cfg = stage_dir.join("l1-sys-init.cfg");
    fs::write(
        &l1_init_cfg,
        "tty:/system/services/sys-tty\n\
         strobe:/system/services/strobe\n\
         svc:328:/system/services/dns-resolver\n\
         svc:17404:/system/services/russhd /system/cfg/sshd.toml\n",
    )
    .expect("failed to write l1-sys-init.cfg");
    run_imager(
        &imager,
        &[
            "put",
            l1_template_raw.to_str().unwrap(),
            l1_init_cfg.to_str().unwrap(),
            "/system/cfg/sys-init.cfg",
        ],
    );
    run_imager(
        &imager,
        &[
            "mkdir",
            "--mode",
            "rwxrwxr-x",
            l1_template_raw.to_str().unwrap(),
            "/user/vm",
        ],
    );

    let vm_l2_toml = stage_dir.join("vm-l2.toml");
    fs::write(
        &vm_l2_toml,
        "log_file = \"/user/tmp/vmm-l2.log\"\n\
         log_level = \"info\"\n\
         pvh = \"/user/vm/kloader\"\n\
         initramfs = \"/user/vm/initrd\"\n\
         cmd_line = \"system-tty\"\n\
         num_cpus = 2\n\
         mem_size = \"256M\"\n\
         blk = [\"/user/vm/l2-motor-os.raw\"]\n\n\
         [net.dev0]\n\
         mac = \"a4:a1:c2:00:00:02\"\n\
         mtu = 1500\n\
         if_name = \"vmm0\"\n",
    )
    .expect("failed to write vm-l2.toml");

    for (src, dst, mode) in [
        (
            motor_out.join("motor-io-host-cwasm"),
            "/user/vm/motor-io-host-cwasm",
            None,
        ),
        (
            motor_out.join("motor-io-host-wasm"),
            "/user/vm/motor-io-host-wasm",
            None,
        ),
        (motor_out.join("vmm-core.cwasm"), "/user/vm/vmm-core.cwasm", None),
        (motor_out.join("vmm-io.cwasm"), "/user/vm/vmm-io.cwasm", None),
        (motor_out.join("vmm-io.wasm"), "/user/vm/vmm-io.wasm", None),
        (stock_kloader, "/user/vm/kloader", None),
        (l1_initrd.clone(), "/user/vm/initrd", None),
        (l2_raw, "/user/vm/l2-motor-os.raw", Some("rw-rw-r--")),
        (vm_l2_toml, "/user/vm/vm-l2.toml", None),
    ] {
        let l1_s = l1_template_raw.to_str().unwrap();
        let src_s = src.to_str().unwrap();
        if let Some(m) = mode {
            run_imager(&imager, &["put", "--mode", m, l1_s, src_s, dst]);
        } else {
            run_imager(&imager, &["put", l1_s, src_s, dst]);
        }
    }

    let _ = fs::remove_dir_all(&stage_dir);

    NestedMotorOsArtifacts {
        l1_kloader: guest.kloader.clone(),
        l1_initrd,
        l1_template_raw,
        ssh_key,
    }
}

pub fn ensure_nested_motor_os_artifacts() -> &'static NestedMotorOsArtifacts {
    static NESTED_MOTO: OnceLock<NestedMotorOsArtifacts> = OnceLock::new();
    NESTED_MOTO.get_or_init(build_nested_motor_os_artifacts)
}

#[derive(Debug, Clone)]
pub struct NestedLinuxInitrdArtifacts {
    pub l1_kloader: PathBuf,
    pub l1_initrd: PathBuf,
    pub l1_template_raw: PathBuf,
}

fn build_nested_linux_initrd_artifacts() -> NestedLinuxInitrdArtifacts {
    let guest = ensure_test_guest_artifacts();
    let motor_out = ensure_motor_io_host_artifacts();
    let moto_dir = motor_os_release_dir();
    let blobs = linux_blobs_dir();
    let imager = moto_dir.join("tools/imager");
    let qcow2 = moto_dir.join("motor-os.qcow2");
    let l1_initrd = moto_dir.join("initrd");
    let bzimage = blobs.join("bzImage");
    let initramfs = blobs.join("initramfs.cpio.gz");

    for required in [&imager, &qcow2, &l1_initrd, &bzimage, &initramfs] {
        assert!(
            required.is_file(),
            "missing required nested Linux initramfs artifact '{}'",
            required.display()
        );
    }

    let stage_dir = motor_out.join("nested-linux-initrd-stage");
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir)
        .expect("failed to create target/motor/nested-linux-initrd-stage");

    let l1_template_raw = motor_out.join("l1-linux-initrd-template.raw");
    let _ = fs::remove_file(&l1_template_raw);
    convert_qcow2_to_raw(&qcow2, &l1_template_raw);

    run_imager(
        &imager,
        &[
            "mkdir",
            "--mode",
            "rwxrwxr-x",
            l1_template_raw.to_str().unwrap(),
            "/user/vm",
        ],
    );

    let vm_l2_toml = stage_dir.join("vm-l2.toml");
    fs::write(
        &vm_l2_toml,
        "log_file = \"/user/tmp/vmm-l2.log\"\n\
         log_level = \"info\"\n\
         kernel = \"/user/vm/bzImage\"\n\
         initramfs = \"/user/vm/initramfs.cpio.gz\"\n\
         cmd_line = \"console=ttyS0 rdinit=/init\"\n\
         num_cpus = 2\n\
         mem_size = \"256M\"\n",
    )
    .expect("failed to write vm-l2.toml for nested Linux initramfs");

    for (src, dst) in [
        (
            motor_out.join("motor-io-host-cwasm"),
            "/user/vm/motor-io-host-cwasm",
        ),
        (
            motor_out.join("motor-io-host-wasm"),
            "/user/vm/motor-io-host-wasm",
        ),
        (motor_out.join("vmm-core.cwasm"), "/user/vm/vmm-core.cwasm"),
        (motor_out.join("vmm-io.cwasm"), "/user/vm/vmm-io.cwasm"),
        (motor_out.join("vmm-io.wasm"), "/user/vm/vmm-io.wasm"),
        (bzimage, "/user/vm/bzImage"),
        (initramfs, "/user/vm/initramfs.cpio.gz"),
        (vm_l2_toml, "/user/vm/vm-l2.toml"),
    ] {
        run_imager(
            &imager,
            &[
                "put",
                l1_template_raw.to_str().unwrap(),
                src.to_str().unwrap(),
                dst,
            ],
        );
    }

    let _ = fs::remove_dir_all(&stage_dir);

    NestedLinuxInitrdArtifacts {
        l1_kloader: guest.kloader.clone(),
        l1_initrd,
        l1_template_raw,
    }
}

pub fn ensure_nested_linux_initrd_artifacts() -> &'static NestedLinuxInitrdArtifacts {
    static NESTED_LINUX_INITRD: OnceLock<NestedLinuxInitrdArtifacts> = OnceLock::new();
    NESTED_LINUX_INITRD.get_or_init(build_nested_linux_initrd_artifacts)
}

#[derive(Debug, Clone)]
pub struct NestedAlpineArtifacts {
    pub l1_kloader: PathBuf,
    pub l1_initrd: PathBuf,
    pub l1_template_raw: PathBuf,
    pub ssh_key: PathBuf,
}

fn copy_file_slice(src: &File, mut src_off: i64, dst: &File, mut dst_off: i64, mut remaining: usize) {
    while remaining > 0 {
        let n = unsafe {
            libc::copy_file_range(
                src.as_raw_fd(),
                &mut src_off,
                dst.as_raw_fd(),
                &mut dst_off,
                remaining,
                0,
            )
        };
        assert!(
            n > 0,
            "copy_file_range failed: {}",
            std::io::Error::last_os_error()
        );
        remaining -= n as usize;
    }
}

fn inject_ssh_pubkey_into_alpine_raw(alpine_raw: &Path, ssh_priv_key: &Path, stage_dir: &Path) {
    let keygen = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(ssh_priv_key)
        .output()
        .expect("failed to invoke ssh-keygen -y");
    assert!(keygen.status.success(), "ssh-keygen -y failed");

    let ak_path = stage_dir.join("authorized_keys");
    fs::write(&ak_path, &keygen.stdout).expect("failed to write staged authorized_keys");

    let raw_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(alpine_raw)
        .expect("failed to open scratch alpine.raw");
    let mut part_entry = [0u8; 8];
    raw_file
        .read_exact_at(&mut part_entry, 0x1be + 2 * 16 + 8)
        .expect("failed to read MBR partition 3 entry");
    let start_sec = u32::from_le_bytes(part_entry[0..4].try_into().unwrap()) as u64;
    let num_sec = u32::from_le_bytes(part_entry[4..8].try_into().unwrap()) as u64;
    let part_off = (start_sec * 512) as i64;
    let part_len = (num_sec * 512) as usize;

    let part3_path = stage_dir.join("part3.ext4");
    {
        let part3_out = File::create(&part3_path).expect("failed to create part3.ext4");
        copy_file_slice(&raw_file, part_off, &part3_out, 0, part_len);
    }

    let _ = Command::new("/usr/sbin/e2fsck")
        .arg("-fy")
        .arg(&part3_path)
        .output()
        .expect("failed to run pre-debugfs e2fsck on part3.ext4");

    let cmds = format!(
        "mkdir /root/.ssh\n\
         set_inode_field /root/.ssh mode 040700\n\
         set_inode_field /root/.ssh uid 0\n\
         set_inode_field /root/.ssh gid 0\n\
         write {} /root/.ssh/authorized_keys\n\
         set_inode_field /root/.ssh/authorized_keys mode 0100600\n\
         set_inode_field /root/.ssh/authorized_keys uid 0\n\
         set_inode_field /root/.ssh/authorized_keys gid 0\n",
        ak_path.display()
    );
    let mut debugfs = Command::new("/usr/sbin/debugfs")
        .arg("-w")
        .arg(&part3_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn /usr/sbin/debugfs");
    debugfs
        .stdin
        .take()
        .unwrap()
        .write_all(cmds.as_bytes())
        .expect("failed to feed commands to debugfs");
    let debugfs_out = debugfs.wait_with_output().expect("debugfs wait failed");
    assert!(
        debugfs_out.status.success(),
        "debugfs failed: {}",
        String::from_utf8_lossy(&debugfs_out.stderr)
    );

    let _ = Command::new("/usr/sbin/e2fsck")
        .arg("-fy")
        .arg(&part3_path)
        .output()
        .expect("failed to run post-debugfs e2fsck on part3.ext4");

    {
        let part3_in = File::open(&part3_path).expect("failed to reopen part3.ext4");
        copy_file_slice(&part3_in, 0, &raw_file, part_off, part_len);
    }
    let _ = fs::remove_file(&part3_path);
}

fn build_nested_alpine_artifacts() -> NestedAlpineArtifacts {
    let guest = ensure_test_guest_artifacts();
    let motor_out = ensure_motor_io_host_artifacts();
    let moto_dir = motor_os_release_dir();
    let blobs = linux_blobs_dir();
    let imager = moto_dir.join("tools/imager");
    let qcow2 = moto_dir.join("motor-os.qcow2");
    let l1_initrd = moto_dir.join("initrd");
    let ssh_key = moto_dir.join("test.key");
    let bzimage = blobs.join("bzImage");
    let src_alpine = blobs.join("alpine.raw");

    for required in [&imager, &qcow2, &l1_initrd, &ssh_key, &bzimage, &src_alpine] {
        assert!(
            required.is_file(),
            "missing required nested Alpine Linux artifact '{}'",
            required.display()
        );
    }

    let stage_dir = motor_out.join("nested-alpine-stage");
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir).expect("failed to create target/motor/nested-alpine-stage");

    let l2_alpine = stage_dir.join("alpine.raw");
    copy_sparse_raw(&src_alpine, &l2_alpine);
    inject_ssh_pubkey_into_alpine_raw(&l2_alpine, &ssh_key, &stage_dir);

    let l1_template_raw = motor_out.join("l1-alpine-template.raw");
    let _ = fs::remove_file(&l1_template_raw);
    run_imager(
        &imager,
        &[
            "resize",
            "-i",
            qcow2.to_str().unwrap(),
            "-o",
            l1_template_raw.to_str().unwrap(),
            "--size",
            "2G",
        ],
    );

    let l1_init_cfg = stage_dir.join("l1-sys-init.cfg");
    fs::write(
        &l1_init_cfg,
        "tty:/system/services/sys-tty\n\
         strobe:/system/services/strobe\n\
         svc:328:/system/services/dns-resolver\n\
         svc:17404:/system/services/russhd /system/cfg/sshd.toml\n",
    )
    .expect("failed to write l1-sys-init.cfg");
    run_imager(
        &imager,
        &[
            "put",
            l1_template_raw.to_str().unwrap(),
            l1_init_cfg.to_str().unwrap(),
            "/system/cfg/sys-init.cfg",
        ],
    );
    run_imager(
        &imager,
        &[
            "mkdir",
            "--mode",
            "rwxrwxr-x",
            l1_template_raw.to_str().unwrap(),
            "/user/vm",
        ],
    );

    let vm_l2_toml = stage_dir.join("vm-l2.toml");
    fs::write(
        &vm_l2_toml,
        "log_file = \"/user/tmp/vmm-l2.log\"\n\
         log_level = \"info\"\n\
         kernel = \"/user/vm/bzImage\"\n\
         cmd_line = \"console=ttyS0 root=/dev/vda3 rw\"\n\
         num_cpus = 2\n\
         mem_size = \"256M\"\n\
         blk = [\"/user/vm/alpine.raw\"]\n\n\
         [net.dev0]\n\
         mac = \"a4:a1:c2:00:00:02\"\n\
         mtu = 1500\n\
         if_name = \"vmm0:192.168.8.1/24\"\n",
    )
    .expect("failed to write vm-l2.toml for nested Alpine");

    for (src, dst, mode) in [
        (
            motor_out.join("motor-io-host-cwasm"),
            "/user/vm/motor-io-host-cwasm",
            None,
        ),
        (
            motor_out.join("motor-io-host-wasm"),
            "/user/vm/motor-io-host-wasm",
            None,
        ),
        (motor_out.join("vmm-core.cwasm"), "/user/vm/vmm-core.cwasm", None),
        (motor_out.join("vmm-io.cwasm"), "/user/vm/vmm-io.cwasm", None),
        (motor_out.join("vmm-io.wasm"), "/user/vm/vmm-io.wasm", None),
        (bzimage, "/user/vm/bzImage", None),
        (l2_alpine, "/user/vm/alpine.raw", Some("rw-rw-r--")),
        (vm_l2_toml, "/user/vm/vm-l2.toml", None),
    ] {
        let l1_s = l1_template_raw.to_str().unwrap();
        let src_s = src.to_str().unwrap();
        if let Some(m) = mode {
            run_imager(&imager, &["put", "--mode", m, l1_s, src_s, dst]);
        } else {
            run_imager(&imager, &["put", l1_s, src_s, dst]);
        }
    }

    let _ = fs::remove_dir_all(&stage_dir);

    NestedAlpineArtifacts {
        l1_kloader: guest.kloader.clone(),
        l1_initrd,
        l1_template_raw,
        ssh_key,
    }
}

pub fn ensure_nested_alpine_artifacts() -> &'static NestedAlpineArtifacts {
    static NESTED_ALPINE: OnceLock<NestedAlpineArtifacts> = OnceLock::new();
    NESTED_ALPINE.get_or_init(build_nested_alpine_artifacts)
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

fn open_raw_pty() -> (File, RawFd) {
    let mut master_fd: RawFd = -1;
    let mut slave_fd: RawFd = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            null_mut(),
            null_mut(),
            null_mut(),
        )
    };
    assert_eq!(
        rc,
        0,
        "openpty failed: {}",
        std::io::Error::last_os_error()
    );
    unsafe {
        let mut tio: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(slave_fd, &mut tio) == 0 {
            libc::cfmakeraw(&mut tio);
            let _ = libc::tcsetattr(slave_fd, libc::TCSANOW, &tio);
        }
    }
    let master = unsafe { File::from_raw_fd(master_fd) };
    (master, slave_fd)
}

pub struct L0LaunchSpec<'a> {
    pub engine: L0Engine,
    pub tmp: &'a TempTestDir,
    pub num_cpus: u32,
    pub mem_size: &'a str,
    pub pvh_kernel: &'a Path,
    pub initramfs: &'a Path,
    pub cmd_line: &'a str,
    pub iommu: bool,
    pub disk_raw: Option<&'a Path>,
    pub tap_if_name: Option<&'a str>,
}

struct L0Session {
    engine: L0Engine,
    desc: String,
    log_path: PathBuf,
    guard: ProcessGroupGuard,
    stdin: Box<dyn Write + Send>,
    state: Arc<(Mutex<SerialCapture>, Condvar)>,
    stdout_handle: thread::JoinHandle<()>,
    stderr_handle: thread::JoinHandle<Vec<u8>>,
}

impl L0Session {
    fn spawn(spec: &L0LaunchSpec<'_>) -> Self {
        let log_path = spec.tmp.path().join("vmm-l0.log");
        let (child, stdin, mut stdout, mut stderr, desc): (
            Child,
            Box<dyn Write + Send>,
            Box<dyn Read + Send>,
            std::process::ChildStderr,
            String,
        ) = match spec.engine {
            L0Engine::Wasm(mode) => {
                let target_dir = ensure_vmm_artifacts();
                let blk_section = match spec.disk_raw {
                    Some(d) => format!("blk = [\"{}\"]\n", d.display()),
                    None => String::from("blk = []\n"),
                };
                let net_section = match spec.tap_if_name {
                    Some(tap) => format!(
                        "\n[net.dev0]\n\
                         mac = \"a4:a1:c2:00:00:01\"\n\
                         mtu = 1500\n\
                         if_name = \"{tap}\"\n"
                    ),
                    None => String::new(),
                };
                let iommu_line = if spec.iommu { "iommu = true\n" } else { "" };
                let config_path = spec.tmp.path().join("vm-l0.toml");
                let full_config = format!(
                    "log_file = \"{}\"\n\
                     log_level = \"info\"\n\
                     pvh = \"{}\"\n\
                     initramfs = \"{}\"\n\
                     cmd_line = \"{}\"\n\
                     num_cpus = {}\n\
                     mem_size = \"{}\"\n\
                     {iommu_line}{blk_section}{net_section}",
                    log_path.display(),
                    spec.pvh_kernel.display(),
                    spec.initramfs.display(),
                    spec.cmd_line,
                    spec.num_cpus,
                    spec.mem_size,
                );
                fs::write(&config_path, &full_config).expect("failed to write L0 vm.toml");

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
                cmd.current_dir(spec.tmp.path())
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
                let cin = child.stdin.take().expect("piped stdin");
                let cout = child.stdout.take().expect("piped stdout");
                let cerr = child.stderr.take().expect("piped stderr");
                (
                    child,
                    Box::new(cin),
                    Box::new(cout),
                    cerr,
                    format!("--- vm-l0.toml ---\n{full_config}"),
                )
            }
            L0Engine::Chv => {
                let chv_bin = find_chv_binary();
                let (pty_master, slave_fd) = open_raw_pty();
                let slave_dup = unsafe { libc::dup(slave_fd) };
                assert!(slave_dup >= 0, "dup(slave_fd) failed");
                let slave_in = unsafe { File::from_raw_fd(slave_fd) };
                let slave_out = unsafe { File::from_raw_fd(slave_dup) };
                let master_reader = pty_master.try_clone().expect("clone pty_master");

                let mut cmd = Command::new(&chv_bin);
                cmd.current_dir(spec.tmp.path())
                    .arg("--cpus")
                    .arg(format!("boot={},nested=on", spec.num_cpus))
                    .arg("--memory")
                    .arg(format!("size={},thp=on", spec.mem_size))
                    .arg("--console")
                    .arg("off")
                    .arg("--serial")
                    .arg("tty")
                    .arg("--log-file")
                    .arg(&log_path)
                    .arg("--kernel")
                    .arg(spec.pvh_kernel)
                    .arg("--initramfs")
                    .arg(spec.initramfs)
                    .arg("--cmdline")
                    .arg(spec.cmd_line);

                let iommu_opt = if spec.iommu { "virtio" } else { "off" };
                cmd.arg("--rng").arg(format!(
                    "src=/dev/urandom,iommu={iommu_opt},pci_device_id=4"
                ));
                if let Some(disk) = spec.disk_raw {
                    cmd.arg("--disk").arg(format!(
                        "path={},image_type=raw,iommu={iommu_opt},pci_device_id=2",
                        disk.display()
                    ));
                }
                if let Some(tap) = spec.tap_if_name {
                    cmd.arg("--net").arg(format!(
                        "tap={tap},mac=a4:a1:c2:00:00:01,iommu={iommu_opt},pci_device_id=3"
                    ));
                }

                let cmd_debug = format!("{cmd:?}");
                cmd.stdin(Stdio::from(slave_in))
                    .stdout(Stdio::from(slave_out))
                    .stderr(Stdio::piped())
                    .process_group(0);

                let mut child = cmd
                    .spawn()
                    .unwrap_or_else(|e| panic!("failed to spawn '{}': {e}", chv_bin.display()));
                let cerr = child.stderr.take().expect("piped stderr");
                (
                    child,
                    Box::new(pty_master),
                    Box::new(master_reader),
                    cerr,
                    format!("--- chv command ---\n{cmd_debug}"),
                )
            }
        };

        let guard = ProcessGroupGuard::new(child);
        let state = Arc::new((
            Mutex::new(SerialCapture {
                buf: Vec::with_capacity(65536),
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

        Self {
            engine: spec.engine,
            desc,
            log_path,
            guard,
            stdin,
            state,
            stdout_handle,
            stderr_handle,
        }
    }

    fn fail(mut self, suite: &str, l1_label: &str, reason: impl AsRef<str>) -> ! {
        self.guard.kill_group();
        self.guard.armed = false;
        drop(self.stdin);
        let _ = self.stdout_handle.join();
        let stderr_bytes = self.stderr_handle.join().unwrap_or_default();
        let serial = self.state.0.lock().unwrap().buf.clone();
        let vmm_log = fs::read_to_string(&self.log_path).unwrap_or_default();
        panic!(
            "[{suite} (l0={}, l1={l1_label})] {}\n{}\n--- serial stdout ---\n{}\n--- stderr ---\n{}\n--- vmm-l0.log ---\n{vmm_log}",
            self.engine.as_str(),
            reason.as_ref(),
            self.desc,
            String::from_utf8_lossy(&serial),
            String::from_utf8_lossy(&stderr_bytes),
        );
    }

    fn finish_from_l1_rush(mut self, suite: &str, l1_label: &str) {
        match self.engine {
            L0Engine::Wasm(_) => {
                let _ = self.stdin.write_all(b"\x01q");
                let _ = self.stdin.flush();
            }
            L0Engine::Chv => {
                let _ = self.stdin.write_all(b"exit\r");
                let _ = self.stdin.flush();
            }
        }
        let shutdown_deadline = Instant::now() + Duration::from_secs(12);
        let exit_status = loop {
            match self.guard.child.try_wait().expect("try_wait failed") {
                Some(status) => {
                    self.guard.armed = false;
                    break Some(status);
                }
                None if Instant::now() >= shutdown_deadline => break None,
                None => thread::sleep(Duration::from_millis(20)),
            }
        };
        drop(self.stdin);
        if exit_status.is_none() {
            self.guard.kill_group();
            self.guard.armed = false;
        }
        let _ = self.stdout_handle.join();
        let stderr_bytes = self.stderr_handle.join().unwrap_or_default();
        let serial = self.state.0.lock().unwrap().buf.clone();
        let vmm_log = fs::read_to_string(&self.log_path).unwrap_or_default();

        let Some(status) = exit_status else {
            panic!(
                "[{suite} (l0={}, l1={l1_label})] L0 VM failed to exit within 12s\n{}\n--- serial stdout ---\n{}\n--- stderr ---\n{}\n--- vmm-l0.log ---\n{vmm_log}",
                self.engine.as_str(),
                self.desc,
                String::from_utf8_lossy(&serial),
                String::from_utf8_lossy(&stderr_bytes),
            );
        };
        assert!(
            status.success(),
            "[{suite} (l0={}, l1={l1_label})] L0 VM exited with non-zero status: {status}\n{}\n--- serial stdout ---\n{}\n--- stderr ---\n{}\n--- vmm-l0.log ---\n{vmm_log}",
            self.engine.as_str(),
            self.desc,
            String::from_utf8_lossy(&serial),
            String::from_utf8_lossy(&stderr_bytes),
        );
    }
}

/// Boots `cloud-hypervisor-static` (with `virtio-iommu` & `nested=on`) and waits for the
/// guest to shut itself down autonomously via ACPI S5, returning the captured serial output.
pub fn boot_chv_until_autonomous_exit(
    test_name: &str,
    tmp: &TempTestDir,
    num_cpus: u32,
    mem_size: &str,
    pvh_kernel: &Path,
    initramfs: &Path,
    cmd_line: &str,
    timeout: Duration,
) -> String {
    let mut sess = L0Session::spawn(&L0LaunchSpec {
        engine: L0Engine::Chv,
        tmp,
        num_cpus,
        mem_size,
        pvh_kernel,
        initramfs,
        cmd_line,
        iommu: true,
        disk_raw: None,
        tap_if_name: None,
    });
    let deadline = Instant::now() + timeout;
    let exit_status = loop {
        match sess.guard.child.try_wait().expect("try_wait failed") {
            Some(status) => {
                sess.guard.armed = false;
                break Some(status);
            }
            None if Instant::now() >= deadline => break None,
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    let Some(status) = exit_status else {
        sess.fail(
            test_name,
            "cwasm",
            format!("CHV VM did not shut down autonomously within {timeout:?}"),
        );
    };
    if !status.success() {
        sess.fail(
            test_name,
            "cwasm",
            format!("CHV VM exited with non-zero status: {status}"),
        );
    }
    drop(sess.stdin);
    let _ = sess.stdout_handle.join();
    let _ = sess.stderr_handle.join();
    let serial = sess.state.0.lock().unwrap().buf.clone();
    String::from_utf8_lossy(&serial).into_owned()
}

fn wait_for_serial_from(
    state: &(Mutex<SerialCapture>, Condvar),
    start_offset: usize,
    needle: &[u8],
    timeout: Duration,
) -> Option<usize> {
    let deadline = Instant::now() + timeout;
    let (lock, cvar) = state;
    let mut cap = lock.lock().unwrap();
    loop {
        if cap.buf.len() > start_offset
            && let Some(rel) = cap.buf[start_offset..]
                .windows(needle.len())
                .position(|w| w == needle)
        {
            return Some(start_offset + rel + needle.len());
        }
        if cap.eof {
            return None;
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let (next_cap, _) = cvar.wait_timeout(cap, deadline - now).unwrap();
        cap = next_cap;
    }
}

fn build_l2_ssh_command(key_path: &Path, remote_cmd: &str) -> Command {
    let proxy = format!(
        "ssh -F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes \
         -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=5 -i {} -W %h:%p -p 2222 motor@192.168.4.2",
        key_path.display()
    );
    let mut cmd = Command::new("ssh");
    cmd.arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg(format!("ProxyCommand={proxy}"))
        .arg("-i")
        .arg(key_path)
        .arg("-p")
        .arg("2222")
        .arg("motor@192.168.5.2")
        .arg(remote_cmd);
    cmd
}

/// Boots L1 full Motor OS (`tests/kloader` + stock `initrd` + staged `l1-motor-os.raw`),
/// launches `motor-io-host-{cwasm,wasm}` inside L1 to boot SMP full Motor OS in L2 with
/// `virtio-blk`, `rush` shell, `virtio-net` (`IpDevice` `192.168.5.1/24`), and `russhd`,
/// verifies ICMP + SSH (when `moto-tap` is active) or console `rush` commands, and verifies
/// clean L2 -> L1 -> L0 teardown.
pub fn boot_nested_full_motor_os(mode: VmmMode, tmp: &TempTestDir, has_host_tap: bool) {
    boot_nested_full_motor_os_with_l0(L0Engine::Wasm(mode), mode, tmp, has_host_tap);
}

pub fn boot_nested_full_motor_os_with_l0(
    l0: L0Engine,
    mode: VmmMode,
    tmp: &TempTestDir,
    has_host_tap: bool,
) {
    let _ = ensure_vmm_artifacts();
    let nested = ensure_nested_motor_os_artifacts();

    let l1_disk = tmp.path().join("l1-motor-os.raw");
    copy_sparse_raw(&nested.l1_template_raw, &l1_disk);

    let key_copy = tmp.path().join("test.key");
    fs::copy(&nested.ssh_key, &key_copy).expect("failed to copy Motor OS SSH test.key");
    fs::set_permissions(&key_copy, fs::Permissions::from_mode(0o600))
        .expect("failed to chmod 0600 test.key");

    let l1_launch = match mode {
        VmmMode::Cwasm => {
            "MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-cwasm -c /user/vm/vm-l2.toml \
             -w /user/vm/vmm-io.cwasm --core-wasm /user/vm/vmm-core.cwasm\r"
        }
        VmmMode::Wasm => {
            "MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-wasm -c /user/vm/vm-l2.toml \
             -w /user/vm/vmm-io.wasm --core-wasm /user/vm/vmm-core.cwasm\r"
        }
    };

    let mut sess = L0Session::spawn(&L0LaunchSpec {
        engine: l0,
        tmp,
        num_cpus: 4,
        mem_size: "1024M",
        pvh_kernel: &nested.l1_kloader,
        initramfs: &nested.l1_initrd,
        cmd_line: "system-tty",
        iommu: true,
        disk_raw: Some(&l1_disk),
        tap_if_name: has_host_tap.then_some("moto-tap"),
    });
    let state = Arc::clone(&sess.state);

    let Some(mut cursor) = wait_for_serial_from(
        &state,
        0,
        b"Starting /system/bin/rush",
        Duration::from_secs(25),
    ) else {
        sess.fail(
            "nested_motor_os",
            mode.as_str(),
            "L1 Motor OS did not boot to /system/bin/rush within 25s",
        );
    };

    {
        let serial_snap = state.0.lock().unwrap().buf.clone();
        let boot_txt = String::from_utf8_lossy(&serial_snap);
        if !boot_txt.contains("vmm::virtio_iommu: active at ") {
            sess.fail(
                "nested_motor_os",
                mode.as_str(),
                "L1 kernel did not activate virtio-iommu during boot",
            );
        }
    }

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(l1_launch.as_bytes())
        .expect("failed to write L2 launch command to L1 stdin");
    sess.stdin.flush().expect("failed to flush L1 stdin");

    let Some(next_pos) = wait_for_serial_from(
        &state,
        cursor,
        b"Starting /system/bin/rush",
        Duration::from_secs(45),
    ) else {
        sess.fail(
            "nested_motor_os",
            mode.as_str(),
            "L2 nested full Motor OS did not boot to /system/bin/rush within 45s",
        );
    };
    cursor = next_pos;

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(b"ping -c 2 192.168.5.1\r")
        .expect("failed to send ping command to L2 console");
    sess.stdin.flush().expect("failed to flush L2 ping command");

    let Some(next_pos) = wait_for_serial_from(
        &state,
        cursor,
        b"bytes from 192.168.5.1",
        Duration::from_secs(15),
    ) else {
        sess.fail(
            "nested_motor_os",
            mode.as_str(),
            "L2 failed to receive ICMP echo reply from L1 IpDevice (192.168.5.1)",
        );
    };
    cursor = next_pos;

    if has_host_tap {
        let ssh_deadline = Instant::now() + Duration::from_secs(20);
        let mut last_err = String::new();
        let mut ssh_stdout = None;
        while Instant::now() < ssh_deadline {
            match build_l2_ssh_command(&key_copy, "echo L2_SSH_OK_$(uname -s)_$(nproc)").output() {
                Ok(out) if out.status.success() => {
                    ssh_stdout = Some(String::from_utf8_lossy(&out.stdout).into_owned());
                    break;
                }
                Ok(out) => {
                    last_err = String::from_utf8_lossy(&out.stderr).into_owned();
                }
                Err(e) => {
                    last_err = e.to_string();
                }
            }
            thread::sleep(Duration::from_millis(400));
        }

        let Some(ssh_out) = ssh_stdout else {
            sess.fail(
                "nested_motor_os",
                mode.as_str(),
                format!("SSH into L2 russhd (192.168.5.2:2222 via L1 192.168.4.2:2222) failed: {last_err}"),
            );
        };
        if !ssh_out.contains("L2_SSH_OK_Motor OS_2") {
            sess.fail(
                "nested_motor_os",
                mode.as_str(),
                format!("unexpected L2 SSH command output: {ssh_out:?}"),
            );
        }

        let _ = build_l2_ssh_command(&key_copy, "shutdown").status();
        let Some(next_pos) =
            wait_for_serial_from(&state, cursor, b"vm_exit: bye.", Duration::from_secs(15))
        else {
            sess.fail(
                "nested_motor_os",
                mode.as_str(),
                "L2 did not emit 'vm_exit: bye.' after SSH shutdown",
            );
        };
        cursor = next_pos;
    } else {
        sess.stdin
            .write_all(b"echo L2_RUSH_OK_$(uname -s)_$(nproc)\r")
            .expect("failed to send echo to L2 rush");
        sess.stdin.flush().expect("failed to flush L2 rush");
        let Some(next_pos) = wait_for_serial_from(
            &state,
            cursor,
            b"L2_RUSH_OK_Motor OS_2",
            Duration::from_secs(15),
        ) else {
            sess.fail(
                "nested_motor_os",
                mode.as_str(),
                "L2 rush echo check failed in no-host-TAP mode",
            );
        };
        cursor = next_pos;

        sess.stdin
            .write_all(b"\x02q")
            .expect("failed to send Ctrl-b q to L2");
        sess.stdin.flush().expect("failed to flush Ctrl-b q");
    }

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(b"echo L1_RESUMED_AFTER_L2_OK\r")
        .expect("failed to send post-L2 check to L1 rush");
    sess.stdin.flush().expect("failed to flush L1 rush");

    if wait_for_serial_from(
        &state,
        cursor,
        b"L1_RESUMED_AFTER_L2_OK",
        Duration::from_secs(10),
    )
    .is_none()
    {
        sess.fail(
            "nested_motor_os",
            mode.as_str(),
            "L1 rush shell did not resume cleanly after L2 teardown",
        );
    }

    sess.finish_from_l1_rush("nested_motor_os", mode.as_str());
}

pub fn boot_nested_linux_initrd(mode: VmmMode, tmp: &TempTestDir) {
    boot_nested_linux_initrd_with_l0(L0Engine::Wasm(mode), mode, tmp);
}

pub fn boot_nested_linux_initrd_with_l0(l0: L0Engine, mode: VmmMode, tmp: &TempTestDir) {
    let _ = ensure_vmm_artifacts();
    let nested = ensure_nested_linux_initrd_artifacts();

    let l1_disk = tmp.path().join("l1-linux-initrd.raw");
    copy_sparse_raw(&nested.l1_template_raw, &l1_disk);

    let l1_launch = match mode {
        VmmMode::Cwasm => {
            "MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-cwasm -c /user/vm/vm-l2.toml \
             -w /user/vm/vmm-io.cwasm --core-wasm /user/vm/vmm-core.cwasm\r"
        }
        VmmMode::Wasm => {
            "MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-wasm -c /user/vm/vm-l2.toml \
             -w /user/vm/vmm-io.wasm --core-wasm /user/vm/vmm-core.cwasm\r"
        }
    };

    let mut sess = L0Session::spawn(&L0LaunchSpec {
        engine: l0,
        tmp,
        num_cpus: 4,
        mem_size: "1024M",
        pvh_kernel: &nested.l1_kloader,
        initramfs: &nested.l1_initrd,
        cmd_line: "system-tty",
        iommu: true,
        disk_raw: Some(&l1_disk),
        tap_if_name: None,
    });
    let state = Arc::clone(&sess.state);

    let Some(mut cursor) = wait_for_serial_from(
        &state,
        0,
        b"Starting /system/bin/rush",
        Duration::from_secs(25),
    ) else {
        sess.fail(
            "nested_linux_initrd",
            mode.as_str(),
            "L1 Motor OS did not boot to /system/bin/rush within 25s",
        );
    };

    {
        let serial_snap = state.0.lock().unwrap().buf.clone();
        let boot_txt = String::from_utf8_lossy(&serial_snap);
        if !boot_txt.contains("vmm::virtio_iommu: active at ") {
            sess.fail(
                "nested_linux_initrd",
                mode.as_str(),
                "L1 kernel did not activate virtio-iommu during boot",
            );
        }
    }

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(l1_launch.as_bytes())
        .expect("failed to write L2 Linux launch command to L1 stdin");
    sess.stdin.flush().expect("failed to flush L1 stdin");

    let Some(next_pos) = wait_for_serial_from(
        &state,
        cursor,
        b"BusyBox initramfs booted successfully in WASM VMM!",
        Duration::from_secs(45),
    ) else {
        sess.fail(
            "nested_linux_initrd",
            mode.as_str(),
            "L2 Linux 6.14 + initramfs did not reach BusyBox banner within 45s",
        );
    };
    cursor = next_pos;

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(b"echo L2_LINUX_OK_$(uname -s)_$(nproc)\n")
        .expect("failed to send command to L2 BusyBox shell");
    sess.stdin.flush().expect("failed to flush L2 BusyBox command");

    let Some(next_pos) = wait_for_serial_from(
        &state,
        cursor,
        b"L2_LINUX_OK_Linux_2",
        Duration::from_secs(15),
    ) else {
        sess.fail(
            "nested_linux_initrd",
            mode.as_str(),
            "L2 BusyBox shell command over ttyS0 (COM1 IRQ 4) failed",
        );
    };
    cursor = next_pos;

    sess.stdin
        .write_all(b"poweroff -f\n")
        .expect("failed to send poweroff -f to L2 BusyBox shell");
    sess.stdin.flush().expect("failed to flush poweroff -f");

    let Some(next_pos) = wait_for_serial_from(
        &state,
        cursor,
        b"reboot: Power down",
        Duration::from_secs(15),
    ) else {
        sess.fail(
            "nested_linux_initrd",
            mode.as_str(),
            "L2 Linux did not emit 'reboot: Power down' on poweroff -f",
        );
    };
    cursor = next_pos;

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(b"echo L1_RESUMED_AFTER_LINUX_OK\r")
        .expect("failed to send post-L2 check to L1 rush");
    sess.stdin.flush().expect("failed to flush L1 rush");

    if wait_for_serial_from(
        &state,
        cursor,
        b"L1_RESUMED_AFTER_LINUX_OK",
        Duration::from_secs(10),
    )
    .is_none()
    {
        sess.fail(
            "nested_linux_initrd",
            mode.as_str(),
            "L1 rush shell did not resume cleanly after L2 Linux ACPI S5 shutdown",
        );
    }

    sess.finish_from_l1_rush("nested_linux_initrd", mode.as_str());
}

fn build_l2_alpine_ssh_command(key_path: &Path, remote_cmd: &str) -> Command {
    let proxy = format!(
        "ssh -F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes \
         -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=5 -i {} -W %h:%p -p 2222 motor@192.168.4.2",
        key_path.display()
    );
    let mut cmd = Command::new("ssh");
    cmd.arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg(format!("ProxyCommand={proxy}"))
        .arg("-i")
        .arg(key_path)
        .arg("-p")
        .arg("22")
        .arg("root@192.168.8.2")
        .arg(remote_cmd);
    cmd
}

/// Boots L1 full Motor OS (`1536M` RAM + `tests/kloader` + resized `2G` `l1-alpine.raw`),
/// launches `motor-io-host-{cwasm,wasm}` inside L1 to boot SMP full Alpine Linux (`bzImage` 6.14
/// + `alpine.raw` over `virtio-blk` + `IpDevice` `vmm0:192.168.8.1/24` over `virtio-net`),
/// verifies `alpine-vm login:` on `ttyS0`, verifies ICMP (`ping -c 2 192.168.8.1`) + OpenSSH
/// (`root@192.168.8.2:22` via L1 `russhd`) + clean `poweroff` (`ACPI S5`), and confirms clean
/// L2 -> L1 `rush` -> L0 teardown.
pub fn boot_nested_full_alpine(mode: VmmMode, tmp: &TempTestDir, has_host_tap: bool) {
    boot_nested_full_alpine_with_l0(L0Engine::Wasm(mode), mode, tmp, has_host_tap);
}

pub fn boot_nested_full_alpine_with_l0(
    l0: L0Engine,
    mode: VmmMode,
    tmp: &TempTestDir,
    has_host_tap: bool,
) {
    let _ = ensure_vmm_artifacts();
    let nested = ensure_nested_alpine_artifacts();

    let l1_disk = tmp.path().join("l1-alpine.raw");
    copy_sparse_raw(&nested.l1_template_raw, &l1_disk);

    let key_copy = tmp.path().join("test.key");
    fs::copy(&nested.ssh_key, &key_copy).expect("failed to copy Motor OS SSH test.key");
    fs::set_permissions(&key_copy, fs::Permissions::from_mode(0o600))
        .expect("failed to chmod 0600 test.key");

    let l1_launch = match mode {
        VmmMode::Cwasm => {
            "MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-cwasm -c /user/vm/vm-l2.toml \
             -w /user/vm/vmm-io.cwasm --core-wasm /user/vm/vmm-core.cwasm\r"
        }
        VmmMode::Wasm => {
            "MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-wasm -c /user/vm/vm-l2.toml \
             -w /user/vm/vmm-io.wasm --core-wasm /user/vm/vmm-core.cwasm\r"
        }
    };

    let mut sess = L0Session::spawn(&L0LaunchSpec {
        engine: l0,
        tmp,
        num_cpus: 4,
        mem_size: "1536M",
        pvh_kernel: &nested.l1_kloader,
        initramfs: &nested.l1_initrd,
        cmd_line: "system-tty",
        iommu: true,
        disk_raw: Some(&l1_disk),
        tap_if_name: has_host_tap.then_some("moto-tap"),
    });
    let state = Arc::clone(&sess.state);

    let Some(mut cursor) = wait_for_serial_from(
        &state,
        0,
        b"Starting /system/bin/rush",
        Duration::from_secs(25),
    ) else {
        sess.fail(
            "nested_alpine",
            mode.as_str(),
            "L1 Motor OS did not boot to /system/bin/rush within 25s",
        );
    };

    {
        let serial_snap = state.0.lock().unwrap().buf.clone();
        let boot_txt = String::from_utf8_lossy(&serial_snap);
        if !boot_txt.contains("vmm::virtio_iommu: active at ") {
            sess.fail(
                "nested_alpine",
                mode.as_str(),
                "L1 kernel did not activate virtio-iommu during boot",
            );
        }
    }

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(l1_launch.as_bytes())
        .expect("failed to write L2 Alpine launch command to L1 stdin");
    sess.stdin.flush().expect("failed to flush L1 stdin");

    let Some(next_pos) = wait_for_serial_from(
        &state,
        cursor,
        b"alpine-vm login:",
        Duration::from_secs(60),
    ) else {
        sess.fail(
            "nested_alpine",
            mode.as_str(),
            "L2 nested full Alpine Linux did not reach 'alpine-vm login:' within 60s",
        );
    };
    cursor = next_pos;

    if has_host_tap {
        let ssh_deadline = Instant::now() + Duration::from_secs(25);
        let mut last_err = String::new();
        let mut ssh_stdout = None;
        let verify_cmd = "ping -c 2 192.168.8.1 && echo L2_ALPINE_SSH_OK_$(uname -s)_$(nproc)";
        while Instant::now() < ssh_deadline {
            match build_l2_alpine_ssh_command(&key_copy, verify_cmd).output() {
                Ok(out) if out.status.success() => {
                    ssh_stdout = Some(String::from_utf8_lossy(&out.stdout).into_owned());
                    break;
                }
                Ok(out) => {
                    last_err = String::from_utf8_lossy(&out.stderr).into_owned();
                }
                Err(e) => {
                    last_err = e.to_string();
                }
            }
            thread::sleep(Duration::from_millis(400));
        }

        let Some(ssh_out) = ssh_stdout else {
            sess.fail(
                "nested_alpine",
                mode.as_str(),
                format!("SSH into L2 Alpine sshd (root@192.168.8.2:22 via L1 192.168.4.2:2222) failed: {last_err}"),
            );
        };
        if !ssh_out.contains("bytes from 192.168.8.1")
            || !ssh_out.contains("L2_ALPINE_SSH_OK_Linux_2")
        {
            sess.fail(
                "nested_alpine",
                mode.as_str(),
                format!("unexpected L2 Alpine SSH/ping output: {ssh_out:?}"),
            );
        };

        let _ = build_l2_alpine_ssh_command(&key_copy, "poweroff").status();
        let Some(next_pos) = wait_for_serial_from(
            &state,
            cursor,
            b"reboot: Power down",
            Duration::from_secs(20),
        ) else {
            sess.fail(
                "nested_alpine",
                mode.as_str(),
                "L2 Alpine did not emit 'reboot: Power down' after SSH poweroff",
            );
        };
        cursor = next_pos;
    } else {
        sess.stdin
            .write_all(b"\x02q")
            .expect("failed to send Ctrl-b q to L2 Alpine");
        sess.stdin.flush().expect("failed to flush Ctrl-b q");
    }

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(b"echo L1_RESUMED_AFTER_ALPINE_OK\r")
        .expect("failed to send post-L2 check to L1 rush");
    sess.stdin.flush().expect("failed to flush L1 rush");

    if wait_for_serial_from(
        &state,
        cursor,
        b"L1_RESUMED_AFTER_ALPINE_OK",
        Duration::from_secs(10),
    )
    .is_none()
    {
        sess.fail(
            "nested_alpine",
            mode.as_str(),
            "L1 rush shell did not resume cleanly after L2 Alpine teardown",
        );
    }

    sess.finish_from_l1_rush("nested_alpine", mode.as_str());
}

#[derive(Debug, Clone)]
pub struct PassthroughNetAlpineArtifacts {
    pub l1_kloader: PathBuf,
    pub l1_initrd: PathBuf,
    pub l1_template_raw: PathBuf,
    pub ssh_key: PathBuf,
}

fn build_passthrough_net_alpine_artifacts() -> PassthroughNetAlpineArtifacts {
    let guest = ensure_test_guest_artifacts();
    let motor_out = ensure_motor_io_host_artifacts();
    let moto_dir = motor_os_release_dir();
    let blobs = linux_blobs_dir();
    let imager = moto_dir.join("tools/imager");
    let qcow2 = moto_dir.join("motor-os.qcow2");
    let l1_initrd = moto_dir.join("initrd");
    let ssh_key = moto_dir.join("test.key");
    let bzimage = blobs.join("bzImage");
    let src_alpine = blobs.join("alpine.raw");

    for required in [&imager, &qcow2, &l1_initrd, &ssh_key, &bzimage, &src_alpine] {
        assert!(
            required.is_file(),
            "missing required passthrough-net Alpine artifact '{}'",
            required.display()
        );
    }

    let stage_dir = motor_out.join("passthrough-net-alpine-stage");
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir)
        .expect("failed to create target/motor/passthrough-net-alpine-stage");

    let l2_alpine = stage_dir.join("alpine.raw");
    copy_sparse_raw(&src_alpine, &l2_alpine);
    inject_ssh_pubkey_into_alpine_raw(&l2_alpine, &ssh_key, &stage_dir);

    let l1_template_raw = motor_out.join("l1-passthrough-net-alpine-template.raw");
    let _ = fs::remove_file(&l1_template_raw);
    run_imager(
        &imager,
        &[
            "resize",
            "-i",
            qcow2.to_str().unwrap(),
            "-o",
            l1_template_raw.to_str().unwrap(),
            "--size",
            "2G",
        ],
    );

    // L1 has zero network devices in Topology A (00:03.0 is passed through to L2),
    // so start only `sys-tty` and `strobe` in L1.
    let l1_init_cfg = stage_dir.join("l1-sys-init.cfg");
    fs::write(
        &l1_init_cfg,
        "tty:/system/services/sys-tty\n\
         strobe:/system/services/strobe\n",
    )
    .expect("failed to write l1-sys-init.cfg");
    run_imager(
        &imager,
        &[
            "put",
            l1_template_raw.to_str().unwrap(),
            l1_init_cfg.to_str().unwrap(),
            "/system/cfg/sys-init.cfg",
        ],
    );
    run_imager(
        &imager,
        &[
            "mkdir",
            "--mode",
            "rwxrwxr-x",
            l1_template_raw.to_str().unwrap(),
            "/user/vm",
        ],
    );

    let vm_l2_toml = stage_dir.join("vm-l2.toml");
    fs::write(
        &vm_l2_toml,
        "log_file = \"/user/tmp/vmm-l2.log\"\n\
         log_level = \"info\"\n\
         kernel = \"/user/vm/bzImage\"\n\
         cmd_line = \"console=ttyS0 root=/dev/vda3 rw\"\n\
         num_cpus = 2\n\
         mem_size = \"256M\"\n\
         pci = [\"00:03.0\"]\n\
         blk = [\"/user/vm/alpine.raw\"]\n",
    )
    .expect("failed to write vm-l2.toml for passthrough-net Alpine");

    for (src, dst, mode) in [
        (
            motor_out.join("motor-io-host-cwasm"),
            "/user/vm/motor-io-host-cwasm",
            None,
        ),
        (
            motor_out.join("motor-io-host-wasm"),
            "/user/vm/motor-io-host-wasm",
            None,
        ),
        (motor_out.join("vmm-core.cwasm"), "/user/vm/vmm-core.cwasm", None),
        (motor_out.join("vmm-io.cwasm"), "/user/vm/vmm-io.cwasm", None),
        (motor_out.join("vmm-io.wasm"), "/user/vm/vmm-io.wasm", None),
        (bzimage, "/user/vm/bzImage", None),
        (l2_alpine, "/user/vm/alpine.raw", Some("rw-rw-r--")),
        (vm_l2_toml, "/user/vm/vm-l2.toml", None),
    ] {
        let l1_s = l1_template_raw.to_str().unwrap();
        let src_s = src.to_str().unwrap();
        if let Some(m) = mode {
            run_imager(&imager, &["put", "--mode", m, l1_s, src_s, dst]);
        } else {
            run_imager(&imager, &["put", l1_s, src_s, dst]);
        }
    }

    let _ = fs::remove_dir_all(&stage_dir);

    PassthroughNetAlpineArtifacts {
        l1_kloader: guest.kloader.clone(),
        l1_initrd,
        l1_template_raw,
        ssh_key,
    }
}

pub fn ensure_passthrough_net_alpine_artifacts() -> &'static PassthroughNetAlpineArtifacts {
    static PT_NET_ALPINE: OnceLock<PassthroughNetAlpineArtifacts> = OnceLock::new();
    PT_NET_ALPINE.get_or_init(build_passthrough_net_alpine_artifacts)
}

pub fn build_direct_alpine_ssh_command(key_path: &Path, remote_cmd: &str) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("ProxyCommand=none")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-i")
        .arg(key_path)
        .arg("-p")
        .arg("22")
        .arg("root@192.168.8.2")
        .arg(remote_cmd);
    cmd
}

/// Topology A: Boots L1 full Motor OS with `pci_passthrough=00:03.0` while L0 attaches
/// `puff-tap` (`192.168.8.1/24`) at `00:03.0` behind `virtio-iommu`.
/// Verifies that L1 `sys-io` sees **zero** network devices, launches L2 Alpine Linux with
/// `pci = ["00:03.0"]`, connects **directly** from L0 to L2 (`root@192.168.8.2:22`,
/// `ProxyCommand=none`) over the passed-through `virtio-net` device, verifies ICMP + SSH +
/// `poweroff`, and verifies clean L2 -> L1 `rush` -> L0 teardown.
pub fn boot_passthrough_net_alpine(mode: VmmMode, tmp: &TempTestDir) {
    boot_passthrough_net_alpine_with_l0(L0Engine::Wasm(mode), mode, tmp);
}

pub fn boot_passthrough_net_alpine_with_l0(l0: L0Engine, mode: VmmMode, tmp: &TempTestDir) {
    let _ = ensure_vmm_artifacts();
    let pt = ensure_passthrough_net_alpine_artifacts();

    let l1_disk = tmp.path().join("l1-pt-net-alpine.raw");
    copy_sparse_raw(&pt.l1_template_raw, &l1_disk);

    let key_copy = tmp.path().join("test.key");
    fs::copy(&pt.ssh_key, &key_copy).expect("failed to copy Motor OS SSH test.key");
    fs::set_permissions(&key_copy, fs::Permissions::from_mode(0o600))
        .expect("failed to chmod 0600 test.key");

    let l1_launch = match mode {
        VmmMode::Cwasm => {
            "MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-cwasm -c /user/vm/vm-l2.toml \
             -w /user/vm/vmm-io.cwasm --core-wasm /user/vm/vmm-core.cwasm\r"
        }
        VmmMode::Wasm => {
            "MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-wasm -c /user/vm/vm-l2.toml \
             -w /user/vm/vmm-io.wasm --core-wasm /user/vm/vmm-core.cwasm\r"
        }
    };

    let mut sess = L0Session::spawn(&L0LaunchSpec {
        engine: l0,
        tmp,
        num_cpus: 4,
        mem_size: "1536M",
        pvh_kernel: &pt.l1_kloader,
        initramfs: &pt.l1_initrd,
        cmd_line: "system-tty pci_passthrough=00:03.0",
        iommu: true,
        disk_raw: Some(&l1_disk),
        tap_if_name: Some("puff-tap"),
    });
    let state = Arc::clone(&sess.state);

    let Some(mut cursor) = wait_for_serial_from(
        &state,
        0,
        b"Starting /system/bin/rush",
        Duration::from_secs(25),
    ) else {
        sess.fail(
            "passthrough_net_alpine",
            mode.as_str(),
            "L1 Motor OS did not boot to /system/bin/rush within 25s",
        );
    };

    {
        let serial_snap = state.0.lock().unwrap().buf.clone();
        let boot_txt = String::from_utf8_lossy(&serial_snap);
        if !boot_txt.contains("vmm::pci_cfg: reserved passthrough PCI BDF 00:03.0") {
            sess.fail(
                "passthrough_net_alpine",
                mode.as_str(),
                "L1 kernel did not reserve passthrough PCI BDF 00:03.0",
            );
        }
        if !boot_txt.contains("vmm::virtio_iommu: active at ") {
            sess.fail(
                "passthrough_net_alpine",
                mode.as_str(),
                "L1 kernel did not activate virtio-iommu during boot",
            );
        }
        if !boot_txt.contains("Cannot find NET device") {
            sess.fail(
                "passthrough_net_alpine",
                mode.as_str(),
                "expected L1 sys-io to see zero NET devices when 00:03.0 is hidden for passthrough",
            );
        }
    }

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(l1_launch.as_bytes())
        .expect("failed to write L2 passthrough-net launch command to L1 stdin");
    sess.stdin.flush().expect("failed to flush L1 stdin");

    let Some(next_pos) = wait_for_serial_from(
        &state,
        cursor,
        b"alpine-vm login:",
        Duration::from_secs(60),
    ) else {
        sess.fail(
            "passthrough_net_alpine",
            mode.as_str(),
            "L2 Alpine Linux with passed-through 00:03.0 did not reach 'alpine-vm login:' within 60s",
        );
    };
    cursor = next_pos;

    let ssh_deadline = Instant::now() + Duration::from_secs(25);
    let mut last_err = String::new();
    let mut ssh_stdout = None;
    let verify_cmd = "ping -c 2 192.168.8.1 && echo L2_PASSTHROUGH_NET_OK_$(uname -s)_$(nproc)";
    while Instant::now() < ssh_deadline {
        match build_direct_alpine_ssh_command(&key_copy, verify_cmd).output() {
            Ok(out) if out.status.success() => {
                ssh_stdout = Some(String::from_utf8_lossy(&out.stdout).into_owned());
                break;
            }
            Ok(out) => {
                last_err = String::from_utf8_lossy(&out.stderr).into_owned();
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
        thread::sleep(Duration::from_millis(400));
    }

    let Some(ssh_out) = ssh_stdout else {
        sess.fail(
            "passthrough_net_alpine",
            mode.as_str(),
            format!("direct L0 -> L2 SSH (root@192.168.8.2:22 over puff-tap, ProxyCommand=none) failed: {last_err}"),
        );
    };
    if !ssh_out.contains("bytes from 192.168.8.1")
        || !ssh_out.contains("L2_PASSTHROUGH_NET_OK_Linux_2")
    {
        sess.fail(
            "passthrough_net_alpine",
            mode.as_str(),
            format!("unexpected L2 direct SSH/ping output: {ssh_out:?}"),
        );
    }

    let _ = build_direct_alpine_ssh_command(&key_copy, "poweroff").status();
    let Some(next_pos) = wait_for_serial_from(
        &state,
        cursor,
        b"reboot: Power down",
        Duration::from_secs(20),
    ) else {
        sess.fail(
            "passthrough_net_alpine",
            mode.as_str(),
            "L2 Alpine did not emit 'reboot: Power down' after direct SSH poweroff",
        );
    };
    cursor = next_pos;

    thread::sleep(Duration::from_millis(300));
    sess.stdin
        .write_all(b"echo L1_RESUMED_AFTER_PT_NET_OK\r")
        .expect("failed to send post-L2 check to L1 rush");
    sess.stdin.flush().expect("failed to flush L1 rush");

    if wait_for_serial_from(
        &state,
        cursor,
        b"L1_RESUMED_AFTER_PT_NET_OK",
        Duration::from_secs(10),
    )
    .is_none()
    {
        sess.fail(
            "passthrough_net_alpine",
            mode.as_str(),
            "L1 rush shell did not resume cleanly after L2 passthrough-net teardown",
        );
    }

    sess.finish_from_l1_rush("passthrough_net_alpine", mode.as_str());
}

#[derive(Debug, Clone)]
pub struct PassthroughBlkAlpineArtifacts {
    pub l1_kloader: PathBuf,
    pub l1_passthrough_initrd: PathBuf,
    pub alpine_template_raw: PathBuf,
    pub ssh_key: PathBuf,
}

fn build_passthrough_blk_alpine_artifacts() -> PassthroughBlkAlpineArtifacts {
    let guest = ensure_test_guest_artifacts();
    let moto_dir = motor_os_release_dir();
    let blobs = linux_blobs_dir();
    let ssh_key = moto_dir.join("test.key");
    let bzimage = blobs.join("bzImage");
    let src_alpine = blobs.join("alpine.raw");

    for required in [&ssh_key, &bzimage, &src_alpine] {
        assert!(
            required.is_file(),
            "missing required passthrough-blk Alpine artifact '{}'",
            required.display()
        );
    }

    let out_dir = guest.dir.join("passthrough-blk-alpine");
    let stage_dir = out_dir.join("stage");
    let _ = fs::remove_dir_all(&out_dir);
    fs::create_dir_all(&stage_dir)
        .expect("failed to create target/test-guest/passthrough-blk-alpine/stage");

    let alpine_template_raw = out_dir.join("alpine-template.raw");
    copy_sparse_raw(&src_alpine, &alpine_template_raw);
    inject_ssh_pubkey_into_alpine_raw(&alpine_template_raw, &ssh_key, &stage_dir);
    let _ = fs::remove_dir_all(&stage_dir);

    let vm_l2_toml = "\
kernel = \"bzImage\"\n\
cmd_line = \"console=ttyS0 root=/dev/vda3 rw\"\n\
num_cpus = 2\n\
mem_size = \"256M\"\n\
pci = [\"00:02.0\", \"00:03.0\"]\n";

    let test_init_bytes =
        fs::read(&guest.test_init).expect("failed to read stripped test-init ELF");
    let cwasm_bytes = fs::read(&guest.vmm_core_motor_cwasm)
        .expect("failed to read vmm-core-motor.cwasm");
    let bzimage_bytes = fs::read(&bzimage).expect("failed to read Linux bzImage");

    let packed = pack_passthrough_initrd(
        &test_init_bytes,
        vm_l2_toml.as_bytes(),
        &cwasm_bytes,
        &bzimage_bytes,
        &[],
    );
    let l1_passthrough_initrd = out_dir.join("initrd-passthrough-blk-alpine");
    fs::write(&l1_passthrough_initrd, &packed)
        .expect("failed to write initrd-passthrough-blk-alpine");

    PassthroughBlkAlpineArtifacts {
        l1_kloader: guest.kloader.clone(),
        l1_passthrough_initrd,
        alpine_template_raw,
        ssh_key,
    }
}

pub fn ensure_passthrough_blk_alpine_artifacts() -> &'static PassthroughBlkAlpineArtifacts {
    static PT_BLK_ALPINE: OnceLock<PassthroughBlkAlpineArtifacts> = OnceLock::new();
    PT_BLK_ALPINE.get_or_init(build_passthrough_blk_alpine_artifacts)
}

/// Topology B: Boots diskless (`initrd-only`) L1 Motor OS with
/// `pci_passthrough=00:02.0,00:03.0` while L0 attaches `alpine.raw` (`virtio-blk` `00:02.0`)
/// and `puff-tap` (`virtio-net` `00:03.0`) behind `virtio-iommu`.
/// L1's lean PID 2 (`test-init` + `InitrdBundle`) drives Ring-0 `vmm-core-motor.cwasm`
/// directly with zero Ring-3 Wasmtime or `vmm-io`, passing both PCI endpoints straight
/// through to L2 Alpine Linux. Verifies bidirectional serial console, direct L0 -> L2 SSH,
/// rootfs `/dev/vda3`, ICMP ping, and autonomous L2 -> L1 -> L0 ACPI S5 shutdown!
pub fn boot_passthrough_blk_alpine(mode: VmmMode, tmp: &TempTestDir) {
    boot_passthrough_blk_alpine_with_l0(L0Engine::Wasm(mode), "cwasm", tmp);
}

pub fn boot_passthrough_blk_alpine_with_l0(l0: L0Engine, l1_label: &str, tmp: &TempTestDir) {
    if matches!(l0, L0Engine::Wasm(_)) {
        let _ = ensure_vmm_artifacts();
    }
    let pt = ensure_passthrough_blk_alpine_artifacts();

    let scratch_alpine = tmp.path().join("alpine.raw");
    copy_sparse_raw(&pt.alpine_template_raw, &scratch_alpine);

    let key_copy = tmp.path().join("test.key");
    fs::copy(&pt.ssh_key, &key_copy).expect("failed to copy Motor OS SSH test.key");
    fs::set_permissions(&key_copy, fs::Permissions::from_mode(0o600))
        .expect("failed to chmod 0600 test.key");

    let mut sess = L0Session::spawn(&L0LaunchSpec {
        engine: l0,
        tmp,
        num_cpus: 4,
        mem_size: "768M",
        pvh_kernel: &pt.l1_kloader,
        initramfs: &pt.l1_passthrough_initrd,
        cmd_line: "vmm-passthrough pci_passthrough=00:02.0,00:03.0",
        iommu: true,
        disk_raw: Some(&scratch_alpine),
        tap_if_name: Some("puff-tap"),
    });
    let state = Arc::clone(&sess.state);

    let Some(mut cursor) = wait_for_serial_from(
        &state,
        0,
        b"alpine-vm login:",
        Duration::from_secs(60),
    ) else {
        sess.fail(
            "passthrough_blk_alpine",
            l1_label,
            "L2 Alpine Linux booting from passed-through 00:02.0 + 00:03.0 did not reach 'alpine-vm login:' within 60s",
        );
    };

    {
        let serial_snap = state.0.lock().unwrap().buf.clone();
        let boot_txt = String::from_utf8_lossy(&serial_snap);
        for expected in [
            "vmm::pci_cfg: reserved passthrough PCI BDF 00:02.0",
            "vmm::pci_cfg: reserved passthrough PCI BDF 00:03.0",
            "vmm::virtio_iommu: active at ",
            "vmm-passthrough: starting L2 VM (cpus=2, mem_mib=256, pci_devs=2)",
            "vmm::pci_host: attached 00:02.0",
            "vmm::pci_host: attached 00:03.0",
        ] {
            if !boot_txt.contains(expected) {
                sess.fail(
                    "passthrough_blk_alpine",
                    l1_label,
                    format!("missing expected L1 Topology B boot marker {expected:?}"),
                );
            }
        }
    }

    let ssh_deadline = Instant::now() + Duration::from_secs(25);
    let mut last_err = String::new();
    let mut ssh_stdout = None;
    let verify_cmd = "ping -c 2 192.168.8.1 && test -b /dev/vda3 && df -T / && echo L2_PASSTHROUGH_BLK_OK_$(uname -s)_$(nproc)";
    while Instant::now() < ssh_deadline {
        match build_direct_alpine_ssh_command(&key_copy, verify_cmd).output() {
            Ok(out) if out.status.success() => {
                ssh_stdout = Some(String::from_utf8_lossy(&out.stdout).into_owned());
                break;
            }
            Ok(out) => {
                last_err = String::from_utf8_lossy(&out.stderr).into_owned();
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
        thread::sleep(Duration::from_millis(400));
    }

    let Some(ssh_out) = ssh_stdout else {
        sess.fail(
            "passthrough_blk_alpine",
            l1_label,
            format!("direct L0 -> L2 SSH (root@192.168.8.2:22 over passed-through 00:03.0) failed: {last_err}"),
        );
    };
    if !ssh_out.contains("bytes from 192.168.8.1")
        || !ssh_out.contains("ext4")
        || !ssh_out.contains("L2_PASSTHROUGH_BLK_OK_Linux_2")
    {
        sess.fail(
            "passthrough_blk_alpine",
            l1_label,
            format!("unexpected L2 direct SSH/df/ping output: {ssh_out:?}"),
        );
    }

    // Also verify interactive COM1 RX forwarding (`L0 -> L1 PID 2 -> L2 ttyS0`) before poweroff!
    sess.stdin
        .write_all(b"\r")
        .expect("failed to send CR over COM1 to L2 ttyS0");
    sess.stdin.flush().expect("failed to flush CR over COM1");
    let Some(next_pos) = wait_for_serial_from(
        &state,
        cursor,
        b"alpine-vm login:",
        Duration::from_secs(10),
    ) else {
        sess.fail(
            "passthrough_blk_alpine",
            l1_label,
            "interactive COM1 RX forwarding (L0 -> L1 PID 2 -> L2 ttyS0) did not echo login prompt",
        );
    };
    cursor = next_pos;

    // Power off L2 over direct SSH; verify autonomous L2 -> L1 -> L0 ACPI S5 shutdown!
    let _ = build_direct_alpine_ssh_command(&key_copy, "poweroff").status();
    if wait_for_serial_from(&state, cursor, b"reboot: Power down", Duration::from_secs(20))
        .is_none()
    {
        sess.fail(
            "passthrough_blk_alpine",
            l1_label,
            "L2 Alpine did not emit 'reboot: Power down' after direct SSH poweroff",
        );
    }

    let shutdown_deadline = Instant::now() + Duration::from_secs(15);
    let exit_status = loop {
        match sess.guard.child.try_wait().expect("try_wait failed") {
            Some(status) => {
                sess.guard.armed = false;
                break Some(status);
            }
            None if Instant::now() >= shutdown_deadline => break None,
            None => thread::sleep(Duration::from_millis(20)),
        }
    };
    let Some(status) = exit_status else {
        sess.fail(
            "passthrough_blk_alpine",
            l1_label,
            "L1/L0 did not shut down autonomously within 15s after L2 poweroff",
        );
    };
    if !status.success() {
        sess.fail(
            "passthrough_blk_alpine",
            l1_label,
            format!("L0 exited with non-zero status: {status}"),
        );
    }

    drop(sess.stdin);
    let _ = sess.stdout_handle.join();
    let _ = sess.stderr_handle.join();
    let serial_bytes = sess.state.0.lock().unwrap().buf.clone();
    let full_serial = String::from_utf8_lossy(&serial_bytes);
    assert!(
        full_serial.contains("vmm-passthrough: l2_shutdown=clean"),
        "missing L1 PID-2 clean teardown marker in serial output:\n{full_serial}"
    );
    assert!(
        full_serial.contains("vm_exit: bye."),
        "missing L1 kernel ACPI S5 exit marker in serial output:\n{full_serial}"
    );
}

/// Boots L1 Linux (`bzImage` from `../linux-stable`) with L0 `virtio-iommu` active (either
/// `wasm-vmm` or `cloud-hypervisor-static`), loads and unloads out-of-tree `airlock.ko`, and
/// verifies `/dev/airlock` both with `kvm` unloaded AND concurrently with `kvm.ko + kvm-amd.ko`.
pub fn boot_airlock_linux_test_guest_with_l0(
    l0_engine: L0Engine,
    l1_io_mode: VmmMode,
    tmp: &TempTestDir,
) {
    let airlock = ensure_linux_airlock_artifacts();
    let vmm_dir = ensure_vmm_artifacts();
    let guest = ensure_test_guest_artifacts();
    let blobs = linux_blobs_dir();
    let base_initramfs = fs::read(blobs.join("initramfs.cpio.gz"))
        .expect("failed to read ../linux-blobs/initramfs.cpio.gz");
    let airlock_ko = fs::read(&airlock.airlock_ko).expect("failed to read airlock.ko");
    let irqbypass_ko = fs::read(&airlock.irqbypass_ko).expect("failed to read irqbypass.ko");
    let kvm_ko = fs::read(&airlock.kvm_ko).expect("failed to read kvm.ko");
    let kvm_amd_ko = fs::read(&airlock.kvm_amd_ko).expect("failed to read kvm-amd.ko");
    let ioctl_check = fs::read(&airlock.ioctl_check).expect("failed to read airlock-ioctl-check");

    let (io_host_bin_name, io_mod_name) = match l1_io_mode {
        VmmMode::Cwasm => ("vmm-io-host-cwasm", "vmm-io.cwasm"),
        VmmMode::Wasm => ("vmm-io-host-wasm", "vmm-io.wasm"),
    };
    let io_host_bin = fs::read(vmm_dir.join(io_host_bin_name))
        .unwrap_or_else(|e| panic!("failed to read {io_host_bin_name}: {e}"));
    let io_mod_bytes =
        fs::read(vmm_dir.join(io_mod_name)).unwrap_or_else(|e| panic!("failed to read {io_mod_name}: {e}"));
    let core_motor_cwasm = fs::read(vmm_dir.join("vmm-core-motor.cwasm"))
        .expect("failed to read vmm-core-motor.cwasm");
    let kloader_bytes = fs::read(&guest.kloader).expect("failed to read test-guest kloader");
    let l2_initrd_bytes =
        fs::read(&guest.initrd).expect("failed to read initrd-test-guest");

    let vm_solo_toml = b"log_file = \"/tmp/vmm-l2-solo.log\"\n\
log_level = \"info\"\n\
pvh = \"/opt/airlock/kloader\"\n\
initramfs = \"/opt/airlock/initrd-test-guest\"\n\
cmd_line = \"test-guest-airlock-solo\"\n\
num_cpus = 2\n\
mem_size = \"128M\"\n\
blk = []\n";

    let vm_coexist_toml = b"log_file = \"/tmp/vmm-l2-coexist.log\"\n\
log_level = \"info\"\n\
pvh = \"/opt/airlock/kloader\"\n\
initramfs = \"/opt/airlock/initrd-test-guest\"\n\
cmd_line = \"test-guest-airlock-coexist\"\n\
num_cpus = 2\n\
mem_size = \"128M\"\n\
blk = []\n";

    let init_script = format!(
        "#!/bin/sh\n\
set -e\n\
mount -t proc proc /proc\n\
mount -t sysfs sysfs /sys\n\
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true\n\
mkdir -p /tmp\n\
mount -t tmpfs tmpfs /tmp\n\
echo \"L1_KERNEL_RELEASE=$(uname -r)\"\n\
dmesg | grep -E 'virtio_iommu|Adding to iommu group' | head -n 6 || true\n\
dmesg -n 4 2>/dev/null || true\n\
# 1. Boot SMP L2 test-guest on airlock.ko with ZERO KVM modules loaded (!kvm)\n\
insmod /lib/modules/airlock.ko\n\
/bin/airlock-ioctl-check\n\
/opt/airlock/{io_host_bin_name} --airlock -c /opt/airlock/vm-solo.toml < /dev/null\n\
echo \"AIRLOCK_SOLO_L2_OK\"\n\
rmmod airlock\n\
echo \"AIRLOCK_SOLO_UNLOAD_OK\"\n\
# 2. Load airlock.ko FIRST, then load kvm + kvm-amd and verify KVM_CREATE_VM succeeds\n\
insmod /lib/modules/airlock.ko\n\
insmod /lib/modules/irqbypass.ko\n\
insmod /lib/modules/kvm.ko\n\
insmod /lib/modules/kvm-amd.ko\n\
/bin/airlock-ioctl-check --kvm-coexist\n\
rmmod airlock\n\
# 3. With kvm + kvm-amd ALREADY loaded, load airlock.ko and boot SMP L2 test-guest concurrently\n\
insmod /lib/modules/airlock.ko\n\
/bin/airlock-ioctl-check --kvm-coexist\n\
/opt/airlock/{io_host_bin_name} --airlock -c /opt/airlock/vm-coexist.toml < /dev/null\n\
echo \"AIRLOCK_COEXIST_L2_OK\"\n\
rmmod airlock\n\
rmmod kvm_amd\n\
rmmod kvm\n\
rmmod irqbypass\n\
dmesg | grep 'airlock:'\n\
dmesg -n 1 2>/dev/null || true\n\
echo \"AIRLOCK_L1_TEST_GUEST_ALL_OK\"\n\
poweroff -f\n"
    );

    let io_host_cpio_path = format!("opt/airlock/{io_host_bin_name}");
    let io_mod_cpio_path = format!("opt/airlock/{io_mod_name}");

    let overlay_initramfs = append_cpio_overlay(
        &base_initramfs,
        &[
            CpioEntry::Dir {
                path: "lib",
                mode: 0o755,
            },
            CpioEntry::Dir {
                path: "lib/modules",
                mode: 0o755,
            },
            CpioEntry::Dir {
                path: "opt",
                mode: 0o755,
            },
            CpioEntry::Dir {
                path: "opt/airlock",
                mode: 0o755,
            },
            CpioEntry::File {
                path: "lib/modules/airlock.ko",
                mode: 0o644,
                data: &airlock_ko,
            },
            CpioEntry::File {
                path: "lib/modules/irqbypass.ko",
                mode: 0o644,
                data: &irqbypass_ko,
            },
            CpioEntry::File {
                path: "lib/modules/kvm.ko",
                mode: 0o644,
                data: &kvm_ko,
            },
            CpioEntry::File {
                path: "lib/modules/kvm-amd.ko",
                mode: 0o644,
                data: &kvm_amd_ko,
            },
            CpioEntry::File {
                path: "bin/airlock-ioctl-check",
                mode: 0o755,
                data: &ioctl_check,
            },
            CpioEntry::File {
                path: &io_host_cpio_path,
                mode: 0o755,
                data: &io_host_bin,
            },
            CpioEntry::File {
                path: &io_mod_cpio_path,
                mode: 0o644,
                data: &io_mod_bytes,
            },
            CpioEntry::File {
                path: "opt/airlock/vmm-core-motor.cwasm",
                mode: 0o644,
                data: &core_motor_cwasm,
            },
            CpioEntry::File {
                path: "opt/airlock/kloader",
                mode: 0o644,
                data: &kloader_bytes,
            },
            CpioEntry::File {
                path: "opt/airlock/initrd-test-guest",
                mode: 0o644,
                data: &l2_initrd_bytes,
            },
            CpioEntry::File {
                path: "opt/airlock/vm-solo.toml",
                mode: 0o644,
                data: vm_solo_toml,
            },
            CpioEntry::File {
                path: "opt/airlock/vm-coexist.toml",
                mode: 0o644,
                data: vm_coexist_toml,
            },
            CpioEntry::File {
                path: "init",
                mode: 0o755,
                data: init_script.as_bytes(),
            },
        ],
    );

    let initrd_path = tmp.path().join("initramfs-airlock-test-guest.cpio");
    fs::write(&initrd_path, &overlay_initramfs).expect("failed to write overlay initramfs");

    let cmdline = "console=ttyS0 rdinit=/init";
    let serial = match l0_engine {
        L0Engine::Wasm(mode) => {
            let cfg = format!(
                "kernel = \"{}\"\n\
                 initramfs = \"{}\"\n\
                 cmd_line = \"{cmdline}\"\n\
                 num_cpus = 2\n\
                 mem_size = \"768M\"\n\
                 iommu = true\n\
                 blk = []\n",
                airlock.bzimage.display(),
                initrd_path.display(),
            );
            boot_until_autonomous_exit(
                "airlock_linux_test_guest",
                mode,
                tmp,
                &cfg,
                Duration::from_secs(60),
            )
        }
        L0Engine::Chv => boot_chv_until_autonomous_exit(
            "airlock_linux_test_guest_chv",
            tmp,
            2,
            "768M",
            &airlock.bzimage,
            &initrd_path,
            cmdline,
            Duration::from_secs(60),
        ),
    };

    for expected in [
        "Adding to iommu group",
        "airlock: Rust Ring-0 core + #![no_std] Wasmtime ready (svm=1, npt=1,",
        "airlock: loaded (/dev/airlock ready,",
        "AIRLOCK_IOCTL_OK ver=1 caps=0x",
        "test-guest: ok | cpus=2",
        "cmd=\"test-guest-airlock-solo\"",
        "AIRLOCK_SOLO_L2_OK",
        "AIRLOCK_SOLO_UNLOAD_OK",
        "AIRLOCK_KVM_COEXIST_OK ver=1 caps=0x",
        "cmd=\"test-guest-airlock-coexist\"",
        "AIRLOCK_COEXIST_L2_OK",
        "AIRLOCK_L1_TEST_GUEST_ALL_OK",
    ] {
        assert!(
            serial.contains(expected),
            "[airlock_linux_test_guest (l0={}, l1_io={})] missing expected marker {expected:?} in serial output:\n{serial}",
            l0_engine.as_str(),
            l1_io_mode.as_str(),
        );
    }
    let bye_count = serial.matches("vm_exit: bye.").count();
    assert!(
        bye_count >= 2,
        "[airlock_linux_test_guest (l0={}, l1_io={})] expected >= 2 L2 'vm_exit: bye.' markers, found {bye_count} in:\n{serial}",
        l0_engine.as_str(),
        l1_io_mode.as_str(),
    );
}

pub fn boot_airlock_linux_test_guest(mode: VmmMode, tmp: &TempTestDir) {
    boot_airlock_linux_test_guest_with_l0(L0Engine::Wasm(mode), mode, tmp);
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

    #[test]
    fn test_pack_passthrough_initrd_bundle_layout() {
        let fake_elf = b"\x7fELFtest-init-elf";
        let fake_toml = b"kernel = \"bzImage\"\nnum_cpus = 2\nmem_size = \"256M\"\npci = [\"00:02.0\"]\n";
        let fake_cwasm = b"CWASM_PAYLOAD";
        let fake_kernel = b"BZIMAGE_PAYLOAD_1234";
        let image = pack_passthrough_initrd(fake_elf, fake_toml, fake_cwasm, fake_kernel, &[]);

        assert_eq!(image.len() % 4096, 0);
        let sys_io_start = u32::from_le_bytes(image[20..24].try_into().unwrap()) as usize;
        let sys_io_end = u32::from_le_bytes(image[24..28].try_into().unwrap()) as usize;
        assert_eq!(sys_io_start, 4096);
        assert_eq!(sys_io_end, 4096 + fake_elf.len());

        let bundle_off = sys_io_end.next_multiple_of(4096);
        assert_eq!(bundle_off, 8192);
        assert_eq!(&image[bundle_off..bundle_off + 8], b"MVMMBNDL");
        let ver = u32::from_le_bytes(image[bundle_off + 8..bundle_off + 12].try_into().unwrap());
        assert_eq!(ver, INITRD_BUNDLE_VERSION);
        let toml_len =
            u64::from_le_bytes(image[bundle_off + 16..bundle_off + 24].try_into().unwrap())
                as usize;
        let cwasm_len =
            u64::from_le_bytes(image[bundle_off + 24..bundle_off + 32].try_into().unwrap())
                as usize;
        let kernel_len =
            u64::from_le_bytes(image[bundle_off + 32..bundle_off + 40].try_into().unwrap())
                as usize;
        let initramfs_len =
            u64::from_le_bytes(image[bundle_off + 40..bundle_off + 48].try_into().unwrap())
                as usize;

        assert_eq!(toml_len, fake_toml.len());
        assert_eq!(cwasm_len, fake_cwasm.len());
        assert_eq!(kernel_len, fake_kernel.len());
        assert_eq!(initramfs_len, 0);

        let p0 = bundle_off + INITRD_BUNDLE_HEADER_SIZE;
        assert_eq!(&image[p0..p0 + toml_len], fake_toml);
        let p1 = p0 + toml_len;
        assert_eq!(&image[p1..p1 + cwasm_len], fake_cwasm);
        let p2 = p1 + cwasm_len;
        assert_eq!(&image[p2..p2 + kernel_len], fake_kernel);
    }

    #[test]
    fn test_pack_newc_cpio_alignment_and_headers() {
        let archive = pack_newc_cpio(&[
            CpioEntry::Dir {
                path: "/lib/modules",
                mode: 0o755,
            },
            CpioEntry::File {
                path: "/init",
                mode: 0o755,
                data: b"#!/bin/sh\necho hi\n",
            },
        ]);
        assert_eq!(archive.len() % 4, 0);
        assert_eq!(&archive[0..6], b"070701");
        assert!(
            archive
                .windows(b"TRAILER!!!\0".len())
                .any(|w| w == b"TRAILER!!!\0")
        );
    }
}
