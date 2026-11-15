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

use std::fs;
use std::path::PathBuf;

use vmm_tests::{AlpineStageFile, AlpineStageSpec, CpioEntry, append_cpio_overlay, stage_alpine_raw};

fn parse_put_spec(spec: &str) -> (PathBuf, String, u32) {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    assert_eq!(
        parts.len(),
        3,
        "invalid --put '{spec}' (expected <host_src>:<guest_dst>:<octal_mode>)"
    );
    let mode = u32::from_str_radix(parts[2], 8)
        .unwrap_or_else(|e| panic!("invalid octal mode '{}' in '{spec}': {e}", parts[2]));
    (PathBuf::from(parts[0]), parts[1].to_string(), mode)
}

fn run_stage_alpine(args: &[String]) {
    let mut src: Option<PathBuf> = None;
    let mut dst: Option<PathBuf> = None;
    let mut stage_dir: Option<PathBuf> = None;
    let mut resize_bytes: Option<u64> = None;
    let mut ssh_key: Option<PathBuf> = None;
    let mut allow_tcp_forwarding = false;
    let mut autologin: Option<String> = None;
    let mut interfaces_body: Option<String> = None;
    let mut dirs: Vec<String> = Vec::new();
    let mut puts: Vec<(PathBuf, String, u32)> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--src" => {
                i += 1;
                src = Some(PathBuf::from(&args[i]));
            }
            "--dst" => {
                i += 1;
                dst = Some(PathBuf::from(&args[i]));
            }
            "--stage-dir" => {
                i += 1;
                stage_dir = Some(PathBuf::from(&args[i]));
            }
            "--resize-mib" => {
                i += 1;
                let mib: u64 = args[i].parse().expect("invalid --resize-mib");
                resize_bytes = Some(mib * 1024 * 1024);
            }
            "--ssh-key" => {
                i += 1;
                ssh_key = Some(PathBuf::from(&args[i]));
            }
            "--allow-tcp-forwarding" => {
                allow_tcp_forwarding = true;
            }
            "--autologin" => {
                i += 1;
                autologin = Some(args[i].clone());
            }
            "--interfaces-file" => {
                i += 1;
                interfaces_body = Some(
                    fs::read_to_string(&args[i]).expect("failed to read --interfaces-file"),
                );
            }
            "--mkdir" => {
                i += 1;
                dirs.push(args[i].clone());
            }
            "--put" => {
                i += 1;
                puts.push(parse_put_spec(&args[i]));
            }
            other => panic!("stage-alpine: unknown argument '{other}'"),
        }
        i += 1;
    }

    let src = src.expect("missing --src");
    let dst = dst.expect("missing --dst");
    let stage_dir = stage_dir.expect("missing --stage-dir");
    let dir_refs: Vec<&str> = dirs.iter().map(|s| s.as_str()).collect();
    let file_refs: Vec<AlpineStageFile<'_>> = puts
        .iter()
        .map(|(s, d, m)| AlpineStageFile {
            src: s.as_path(),
            dst_in_guest: d.as_str(),
            mode_octal: *m,
        })
        .collect();

    stage_alpine_raw(
        &AlpineStageSpec {
            src_alpine_raw: &src,
            dst_alpine_raw: &dst,
            resize_bytes,
            ssh_priv_key: ssh_key.as_deref(),
            allow_tcp_forwarding,
            autologin_shell_script: autologin.as_deref(),
            custom_interfaces: interfaces_body.as_deref(),
            extra_dirs: &dir_refs,
            extra_files: &file_refs,
        },
        &stage_dir,
    );
}

fn run_pack_cpio_overlay(args: &[String]) {
    let mut base: Option<PathBuf> = None;
    let mut dst: Option<PathBuf> = None;
    let mut dirs: Vec<String> = Vec::new();
    let mut puts: Vec<(Vec<u8>, String, u32)> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = Some(PathBuf::from(&args[i]));
            }
            "--dst" => {
                i += 1;
                dst = Some(PathBuf::from(&args[i]));
            }
            "--mkdir" => {
                i += 1;
                dirs.push(args[i].clone());
            }
            "--put" => {
                i += 1;
                let (src_path, guest_dst, mode) = parse_put_spec(&args[i]);
                let bytes = fs::read(&src_path).unwrap_or_else(|e| {
                    panic!("pack-cpio-overlay: failed to read '{}': {e}", src_path.display())
                });
                puts.push((bytes, guest_dst, mode));
            }
            other => panic!("pack-cpio-overlay: unknown argument '{other}'"),
        }
        i += 1;
    }

    let base = base.expect("missing --base");
    let dst = dst.expect("missing --dst");
    let base_bytes = fs::read(&base).expect("failed to read --base initramfs");

    let mut entries: Vec<CpioEntry<'_>> = Vec::with_capacity(dirs.len() + puts.len());
    for d in &dirs {
        entries.push(CpioEntry::Dir {
            path: d.as_str(),
            mode: 0o755,
        });
    }
    for (data, guest_dst, mode) in &puts {
        entries.push(CpioEntry::File {
            path: guest_dst.as_str(),
            mode: *mode,
            data: data.as_slice(),
        });
    }
    let combined = append_cpio_overlay(&base_bytes, &entries);
    fs::write(&dst, &combined).expect("failed to write --dst cpio overlay");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() >= 2,
        "Usage: stage_airlock_guest <stage-alpine | pack-cpio-overlay> [options]"
    );
    match args[1].as_str() {
        "stage-alpine" => run_stage_alpine(&args[2..]),
        "pack-cpio-overlay" => run_pack_cpio_overlay(&args[2..]),
        other => panic!("unknown subcommand '{other}'"),
    }
}
