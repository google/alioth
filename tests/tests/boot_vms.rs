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

use std::time::Duration;

use vmm_tests::{
    L0Engine, TempTestDir, VmmMode, acquire_linux_lock, acquire_motor_os_lock,
    boot_airlock_linux_motor_os, boot_airlock_linux_motor_os_with_l0,
    boot_airlock_linux_test_guest, boot_airlock_linux_test_guest_with_l0, boot_and_shutdown,
    boot_chv_until_autonomous_exit, boot_nested_full_alpine, boot_nested_full_alpine_with_l0,
    boot_nested_full_motor_os, boot_nested_full_motor_os_with_l0, boot_nested_linux_initrd,
    boot_nested_linux_initrd_with_l0, boot_passthrough_blk_alpine,
    boot_passthrough_blk_alpine_with_l0, boot_passthrough_net_alpine,
    boot_passthrough_net_alpine_with_l0, boot_until_autonomous_exit, convert_qcow2_to_raw,
    copy_sparse_raw, ensure_test_guest_artifacts, linux_blobs_dir, motor_os_release_dir,
    use_network_tap,
};

fn run_linux_initrd(mode: VmmMode) {
    let blobs = linux_blobs_dir();
    let kernel = blobs.join("bzImage");
    let initramfs = blobs.join("initramfs.cpio.gz");
    assert!(kernel.is_file(), "missing kernel '{}'", kernel.display());
    assert!(
        initramfs.is_file(),
        "missing initramfs '{}'",
        initramfs.display()
    );

    let tmp = TempTestDir::new(&format!("linux-initrd-{}", mode.as_str()));
    let cfg = format!(
        "kernel = \"{}\"\n\
         initramfs = \"{}\"\n\
         cmd_line = \"console=ttyS0 rdinit=/init\"\n\
         num_cpus = 2\n\
         mem_size = \"256M\"\n",
        kernel.display(),
        initramfs.display(),
    );

    boot_and_shutdown(
        "linux_initrd",
        mode,
        &tmp,
        &cfg,
        "BusyBox initramfs booted successfully in WASM VMM!",
        Duration::from_secs(20),
    );
}

fn run_full_linux(mode: VmmMode) {
    let _lock = acquire_linux_lock();
    let blobs = linux_blobs_dir();
    let kernel = blobs.join("bzImage");
    let src_disk = blobs.join("alpine.raw");
    assert!(kernel.is_file(), "missing kernel '{}'", kernel.display());
    assert!(
        src_disk.is_file(),
        "missing Alpine disk '{}'",
        src_disk.display()
    );

    let tmp = TempTestDir::new(&format!("full-linux-{}", mode.as_str()));
    let scratch_disk = tmp.path().join("alpine.raw");
    copy_sparse_raw(&src_disk, &scratch_disk);

    let net_section = if use_network_tap("puff-tap", "run ./vm_scripts/create-tap.sh") {
        "\n[net.dev0]\n\
         mac = \"a4:a1:c2:00:00:01\"\n\
         mtu = 1500\n\
         if_name = \"puff-tap\"\n"
    } else {
        ""
    };

    let cfg = format!(
        "kernel = \"{}\"\n\
         cmd_line = \"console=ttyS0 root=/dev/vda3 rw\"\n\
         num_cpus = 4\n\
         mem_size = \"256M\"\n\
         blk = [\"{}\"]\n\
         {net_section}",
        kernel.display(),
        scratch_disk.display(),
    );

    boot_and_shutdown(
        "full_linux",
        mode,
        &tmp,
        &cfg,
        "alpine-vm login:",
        Duration::from_secs(30),
    );
}

/// Boots full Motor OS from `../motor-dev/motor-os/vm_images/release` (see
/// <https://github.com/moturus/motor-os/blob/main/docs/build.md>) and immediately shuts down.
fn run_full_motor_os(mode: VmmMode) {
    let _lock = acquire_motor_os_lock();
    let moto_dir = motor_os_release_dir();
    let kloader = moto_dir.join("kloader");
    let initrd = moto_dir.join("initrd");
    let qcow2 = moto_dir.join("motor-os.qcow2");
    assert!(
        kloader.is_file(),
        "missing Motor OS kloader '{}'",
        kloader.display()
    );
    assert!(
        initrd.is_file(),
        "missing Motor OS initrd '{}'",
        initrd.display()
    );
    assert!(
        qcow2.is_file(),
        "missing Motor OS image '{}'",
        qcow2.display()
    );

    let tmp = TempTestDir::new(&format!("motor-os-{}", mode.as_str()));
    let scratch_raw = tmp.path().join("motor-os.raw");
    convert_qcow2_to_raw(&qcow2, &scratch_raw);

    let net_section = if use_network_tap(
        "moto-tap",
        "run ../motor-dev/motor-os/vm_images/release/create-tap.sh",
    ) {
        "\n[net.dev0]\n\
         mac = \"a4:a1:c2:00:00:01\"\n\
         mtu = 1500\n\
         if_name = \"moto-tap\"\n"
    } else {
        ""
    };

    let cfg = format!(
        "pvh = \"{}\"\n\
         initramfs = \"{}\"\n\
         num_cpus = 4\n\
         mem_size = \"1024M\"\n\
         blk = [\"{}\"]\n\
         {net_section}",
        kloader.display(),
        initrd.display(),
        scratch_raw.display(),
    );

    boot_and_shutdown(
        "full_motor_os",
        mode,
        &tmp,
        &cfg,
        "Starting /system/bin/rush",
        Duration::from_secs(20),
    );
}

#[test]
fn boot_linux_initrd_cwasm() {
    run_linux_initrd(VmmMode::Cwasm);
}

#[test]
fn boot_linux_initrd_wasm() {
    run_linux_initrd(VmmMode::Wasm);
}

#[test]
fn boot_full_linux_cwasm() {
    run_full_linux(VmmMode::Cwasm);
}

#[test]
fn boot_full_linux_wasm() {
    run_full_linux(VmmMode::Wasm);
}

#[test]
fn boot_full_motor_os_cwasm() {
    run_full_motor_os(VmmMode::Cwasm);
}

#[test]
fn boot_full_motor_os_wasm() {
    run_full_motor_os(VmmMode::Wasm);
}

fn run_test_guest(mode: VmmMode) {
    let guest = ensure_test_guest_artifacts();
    let tmp = TempTestDir::new(&format!("test-guest-{}", mode.as_str()));
    let cfg = format!(
        "pvh = \"{}\"\n\
         initramfs = \"{}\"\n\
         cmd_line = \"test-guest\"\n\
         num_cpus = 2\n\
         mem_size = \"64M\"\n\
         blk = []\n",
        guest.kloader.display(),
        guest.initrd.display(),
    );

    let serial =
        boot_until_autonomous_exit("test_guest", mode, &tmp, &cfg, Duration::from_secs(10));

    assert!(
        serial.contains("test-guest: ok | cpus=2"),
        "missing test-guest summary line in serial output:\n{serial}"
    );
    assert!(
        serial.contains("cmd=\"test-guest\""),
        "missing kernel cmdline in test-guest serial output:\n{serial}"
    );
    assert!(
        serial.contains("hv=svm(npt=1,") || serial.contains("hv=vmx"),
        "expected nested hardware virtualization (SVM+NPT or VMX) in L1 test-guest, got:\n{serial}"
    );
    assert!(
        serial.contains("vm_exit: bye."),
        "missing clean Motor OS ACPI S5 exit marker in serial output:\n{serial}"
    );
}

#[test]
fn boot_test_guest_cwasm() {
    run_test_guest(VmmMode::Cwasm);
}

#[test]
fn boot_test_guest_wasm() {
    run_test_guest(VmmMode::Wasm);
}

fn assert_nested_test_guest_serial(serial: &str) {
    assert!(
        serial.contains("vmm::virtio_iommu: active at "),
        "missing L1 virtio-iommu activation banner in serial output:\n{serial}"
    );
    // Verify L1 booted with 2 vCPUs and hardware nested virtualization enabled.
    assert!(
        serial.contains("test-guest: ok | cpus=2")
            && serial.contains("cmd=\"test-guest-nested\"")
            && (serial.contains("hv=svm(npt=1,") || serial.contains("hv=vmx")),
        "missing expected L1 test-guest banner in serial output:\n{serial}"
    );

    // Verify L2 booted SMP (2 vCPUs) inside L1's Ring-0 Airlock Wasm VMM and exited cleanly!
    assert!(
        serial.contains("test-guest: ok | cpus=2") && serial.contains("cmd=\"test-guest-l2\""),
        "missing expected L2 SMP test-guest banner in serial output:\n{serial}"
    );
    assert!(
        serial.contains("[L2] vm_exit: bye."),
        "missing L2 clean ACPI S5 exit marker in serial output:\n{serial}"
    );
    assert!(
        serial.contains("test-guest: nested-ok | l2_shutdown=clean"),
        "missing L1 nested-ok teardown confirmation in serial output:\n{serial}"
    );
    assert!(
        serial.contains("vm_exit: bye."),
        "missing L1 clean Motor OS ACPI S5 exit marker in serial output:\n{serial}"
    );
}

fn run_nested_test_guest(mode: VmmMode) {
    let guest = ensure_test_guest_artifacts();
    let tmp = TempTestDir::new(&format!("nested-test-guest-{}", mode.as_str()));
    let cfg = format!(
        "pvh = \"{}\"\n\
         initramfs = \"{}\"\n\
         cmd_line = \"test-guest-nested\"\n\
         num_cpus = 2\n\
         mem_size = \"256M\"\n\
         iommu = true\n\
         blk = []\n",
        guest.kloader.display(),
        guest.nested_initrd.display(),
    );

    let serial = boot_until_autonomous_exit(
        "nested_test_guest",
        mode,
        &tmp,
        &cfg,
        Duration::from_secs(30),
    );
    assert_nested_test_guest_serial(&serial);
}

#[test]
fn boot_nested_test_guest_cwasm() {
    run_nested_test_guest(VmmMode::Cwasm);
}

#[test]
fn boot_nested_test_guest_wasm() {
    run_nested_test_guest(VmmMode::Wasm);
}

#[test]
fn boot_nested_test_guest_chv() {
    let guest = ensure_test_guest_artifacts();
    let tmp = TempTestDir::new("nested-test-guest-chv");
    let serial = boot_chv_until_autonomous_exit(
        "nested_test_guest_chv",
        &tmp,
        2,
        "256M",
        &guest.kloader,
        &guest.nested_initrd,
        "test-guest-nested",
        Duration::from_secs(30),
    );
    assert_nested_test_guest_serial(&serial);
}

fn run_nested_motor_os(mode: VmmMode) {
    let _lock = acquire_motor_os_lock();
    let has_tap = use_network_tap(
        "moto-tap",
        "run ../motor-dev/motor-os/vm_images/release/create-tap.sh",
    );
    let tmp = TempTestDir::new(&format!("nested-motor-os-{}", mode.as_str()));
    boot_nested_full_motor_os(mode, &tmp, has_tap);
}

fn run_nested_motor_os_chv(mode: VmmMode) {
    let _lock = acquire_motor_os_lock();
    let has_tap = use_network_tap(
        "moto-tap",
        "run ../motor-dev/motor-os/vm_images/release/create-tap.sh",
    );
    let tmp = TempTestDir::new(&format!("nested-motor-os-chv-{}", mode.as_str()));
    boot_nested_full_motor_os_with_l0(L0Engine::Chv, mode, &tmp, has_tap);
}

#[test]
fn boot_nested_motor_os_cwasm() {
    run_nested_motor_os(VmmMode::Cwasm);
}

#[test]
fn boot_nested_motor_os_wasm() {
    run_nested_motor_os(VmmMode::Wasm);
}

#[test]
fn boot_nested_motor_os_chv_cwasm() {
    run_nested_motor_os_chv(VmmMode::Cwasm);
}

#[test]
fn boot_nested_motor_os_chv_wasm() {
    run_nested_motor_os_chv(VmmMode::Wasm);
}

fn run_nested_linux_initrd(mode: VmmMode) {
    let tmp = TempTestDir::new(&format!("nested-linux-initrd-{}", mode.as_str()));
    boot_nested_linux_initrd(mode, &tmp);
}

fn run_nested_linux_initrd_chv(mode: VmmMode) {
    let tmp = TempTestDir::new(&format!("nested-linux-initrd-chv-{}", mode.as_str()));
    boot_nested_linux_initrd_with_l0(L0Engine::Chv, mode, &tmp);
}

#[test]
fn boot_nested_linux_initrd_cwasm() {
    run_nested_linux_initrd(VmmMode::Cwasm);
}

#[test]
fn boot_nested_linux_initrd_wasm() {
    run_nested_linux_initrd(VmmMode::Wasm);
}

#[test]
fn boot_nested_linux_initrd_chv_cwasm() {
    run_nested_linux_initrd_chv(VmmMode::Cwasm);
}

#[test]
fn boot_nested_linux_initrd_chv_wasm() {
    run_nested_linux_initrd_chv(VmmMode::Wasm);
}

fn run_nested_alpine(mode: VmmMode) {
    let _lock = acquire_motor_os_lock();
    let has_tap = use_network_tap(
        "moto-tap",
        "run ../motor-dev/motor-os/vm_images/release/create-tap.sh",
    );
    let tmp = TempTestDir::new(&format!("nested-alpine-{}", mode.as_str()));
    boot_nested_full_alpine(mode, &tmp, has_tap);
}

fn run_nested_alpine_chv(mode: VmmMode) {
    let _lock = acquire_motor_os_lock();
    let has_tap = use_network_tap(
        "moto-tap",
        "run ../motor-dev/motor-os/vm_images/release/create-tap.sh",
    );
    let tmp = TempTestDir::new(&format!("nested-alpine-chv-{}", mode.as_str()));
    boot_nested_full_alpine_with_l0(L0Engine::Chv, mode, &tmp, has_tap);
}

#[test]
fn boot_nested_alpine_cwasm() {
    run_nested_alpine(VmmMode::Cwasm);
}

#[test]
fn boot_nested_alpine_wasm() {
    run_nested_alpine(VmmMode::Wasm);
}

#[test]
fn boot_nested_alpine_chv_cwasm() {
    run_nested_alpine_chv(VmmMode::Cwasm);
}

#[test]
fn boot_nested_alpine_chv_wasm() {
    run_nested_alpine_chv(VmmMode::Wasm);
}

fn run_passthrough_net_alpine(mode: VmmMode) {
    let _lock = acquire_linux_lock();
    if !use_network_tap("puff-tap", "run ./vm_scripts/create-tap.sh") {
        eprintln!("skipping boot_passthrough_net_alpine because VMM_TEST_NO_NET is set");
        return;
    }
    let tmp = TempTestDir::new(&format!("pt-net-alpine-{}", mode.as_str()));
    boot_passthrough_net_alpine(mode, &tmp);
}

fn run_passthrough_net_alpine_chv(mode: VmmMode) {
    let _lock = acquire_linux_lock();
    if !use_network_tap("puff-tap", "run ./vm_scripts/create-tap.sh") {
        eprintln!("skipping boot_passthrough_net_alpine_chv because VMM_TEST_NO_NET is set");
        return;
    }
    let tmp = TempTestDir::new(&format!("pt-net-alpine-chv-{}", mode.as_str()));
    boot_passthrough_net_alpine_with_l0(L0Engine::Chv, mode, &tmp);
}

#[test]
fn boot_passthrough_net_alpine_cwasm() {
    run_passthrough_net_alpine(VmmMode::Cwasm);
}

#[test]
fn boot_passthrough_net_alpine_wasm() {
    run_passthrough_net_alpine(VmmMode::Wasm);
}

#[test]
fn boot_passthrough_net_alpine_chv_cwasm() {
    run_passthrough_net_alpine_chv(VmmMode::Cwasm);
}

#[test]
fn boot_passthrough_net_alpine_chv_wasm() {
    run_passthrough_net_alpine_chv(VmmMode::Wasm);
}

fn run_passthrough_blk_alpine(mode: VmmMode) {
    let _lock = acquire_linux_lock();
    if !use_network_tap("puff-tap", "run ./vm_scripts/create-tap.sh") {
        eprintln!("skipping boot_passthrough_blk_alpine because VMM_TEST_NO_NET is set");
        return;
    }
    let tmp = TempTestDir::new(&format!("pt-blk-alpine-{}", mode.as_str()));
    boot_passthrough_blk_alpine(mode, &tmp);
}

fn run_passthrough_blk_alpine_chv(mode: VmmMode) {
    let _lock = acquire_linux_lock();
    if !use_network_tap("puff-tap", "run ./vm_scripts/create-tap.sh") {
        eprintln!("skipping boot_passthrough_blk_alpine_chv because VMM_TEST_NO_NET is set");
        return;
    }
    let tmp = TempTestDir::new(&format!("pt-blk-alpine-chv-{}", mode.as_str()));
    boot_passthrough_blk_alpine_with_l0(L0Engine::Chv, mode.as_str(), &tmp);
}

#[test]
fn boot_passthrough_blk_alpine_cwasm() {
    run_passthrough_blk_alpine(VmmMode::Cwasm);
}

#[test]
fn boot_passthrough_blk_alpine_wasm() {
    run_passthrough_blk_alpine(VmmMode::Wasm);
}

#[test]
fn boot_passthrough_blk_alpine_chv_cwasm() {
    run_passthrough_blk_alpine_chv(VmmMode::Cwasm);
}

#[test]
fn boot_passthrough_blk_alpine_chv_wasm() {
    run_passthrough_blk_alpine_chv(VmmMode::Wasm);
}

#[test]
fn boot_airlock_linux_test_guest_cwasm() {
    let tmp = TempTestDir::new("airlock-linux-test-guest-cwasm");
    boot_airlock_linux_test_guest(VmmMode::Cwasm, &tmp);
}

#[test]
fn boot_airlock_linux_test_guest_wasm() {
    let tmp = TempTestDir::new("airlock-linux-test-guest-wasm");
    boot_airlock_linux_test_guest(VmmMode::Wasm, &tmp);
}

#[test]
fn boot_airlock_linux_test_guest_chv() {
    let tmp = TempTestDir::new("airlock-linux-test-guest-chv");
    boot_airlock_linux_test_guest_with_l0(L0Engine::Chv, VmmMode::Cwasm, &tmp);
}

fn run_airlock_linux_motor_os(mode: VmmMode) {
    let _lock = acquire_linux_lock();
    let has_tap = use_network_tap("puff-tap", "run ./vm_scripts/create-tap.sh");
    let tmp = TempTestDir::new(&format!("airlock-linux-motor-os-{}", mode.as_str()));
    boot_airlock_linux_motor_os(mode, &tmp, has_tap);
}

fn run_airlock_linux_motor_os_chv(mode: VmmMode) {
    let _lock = acquire_linux_lock();
    let has_tap = use_network_tap("puff-tap", "run ./vm_scripts/create-tap.sh");
    let tmp = TempTestDir::new(&format!("airlock-linux-motor-os-chv-{}", mode.as_str()));
    boot_airlock_linux_motor_os_with_l0(L0Engine::Chv, mode, &tmp, has_tap);
}

#[test]
fn boot_airlock_linux_motor_os_cwasm() {
    run_airlock_linux_motor_os(VmmMode::Cwasm);
}

#[test]
fn boot_airlock_linux_motor_os_wasm() {
    run_airlock_linux_motor_os(VmmMode::Wasm);
}

#[test]
fn boot_airlock_linux_motor_os_chv_cwasm() {
    run_airlock_linux_motor_os_chv(VmmMode::Cwasm);
}

#[test]
fn boot_airlock_linux_motor_os_chv_wasm() {
    run_airlock_linux_motor_os_chv(VmmMode::Wasm);
}
