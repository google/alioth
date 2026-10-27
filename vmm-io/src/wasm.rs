// Copyright 2024 Google LLC
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

use std::collections::VecDeque;
use std::io::{self, IoSlice, IoSliceMut};
use std::path::Path;

use crate::host::abi::{
    ERR_EOF, ERR_INTERRUPTED, ERR_WOULD_BLOCK, EXEC_TYPE_LINUX, EXEC_TYPE_NONE, EXEC_TYPE_PVH,
    IO_BRIDGE_EVENT_POLL, IO_BRIDGE_EVENT_SERIAL_INPUT, IO_BRIDGE_EVENT_SERIAL_TX,
    IO_BRIDGE_EVENT_SHUTDOWN, IO_BRIDGE_EVENT_VIRTIO_NOTIFY, IO_BRIDGE_EVENT_VIRTIO_RESET,
    IO_BRIDGE_EVENT_VIRTIO_START, IRQ_KIND_CONFIG, IRQ_KIND_QUEUE, RawIoBootConfig,
    RawIoBridgeEvent, ShmVirtioDeviceSpec,
};
use crate::host::{
    BlockBackend, ExecKind, GuestMemAccess, Handle, Interest, IoBootConfig, IoBridgeEvent, IoHost,
    PollEvent, SerialConsole, Tap, Token, VirtioDeviceSpec, VirtioIrqKind, VirtioQueueConfig,
};
use crate::virtio::dev::net::NetFeature;

#[link(wasm_import_module = "vmm")]
unsafe extern "C" {
    fn vmm_last_error_len() -> u32;
    fn vmm_last_error_read(dst_ptr: u32, dst_len: u32) -> i32;

    fn tap_open(has_name: u32, name_ptr: u32, name_len: u32) -> i64;
    fn tap_detected_offload(tap: u64) -> u64;
    fn tap_enable_offload(tap: u64, feature: u64) -> i32;
    fn tap_register(tap: u64, token: u64, interests: u32) -> i32;
    fn tap_deregister(tap: u64);
    fn tap_read(tap: u64, dst_ptr: u32, max_len: u32) -> i32;
    fn tap_write(tap: u64, src_ptr: u32, len: u32) -> i32;
    fn tap_close(tap: u64);

    fn blk_open(path_ptr: u32, path_len: u32, read_only: u32, size_out_ptr: u32) -> i64;
    fn blk_read_at(blk: u64, offset: u64, dst_ptr: u32, len: u32) -> i32;
    fn blk_write_at(blk: u64, offset: u64, src_ptr: u32, len: u32) -> i32;
    fn blk_flush(blk: u64) -> i32;
    fn blk_close(blk: u64);

    fn serial_open() -> i64;
    fn serial_write_byte(serial: u64, byte: u32) -> i32;
    fn serial_read_input(serial: u64, dst_ptr: u32, max_len: u32) -> i32;
    fn serial_shutdown(serial: u64) -> i32;
    fn serial_close(serial: u64);

    fn io_register_vm_config(boot_cfg_ptr: u32, devs_ptr: u32, num_devs: u32) -> i32;
    fn io_next_event(event_out_ptr: u32) -> i32;
    fn io_request_shutdown() -> i32;
    fn io_guest_mem_read(gpa: u64, dst_ptr: u32, len: u32) -> i32;
    fn io_guest_mem_write(gpa: u64, src_ptr: u32, len: u32) -> i32;
    fn io_virtio_irq(dev: u64, irq_kind: u32, queue_index: u32) -> i32;
    fn io_serial_push_rx(src_ptr: u32, len: u32) -> i32;
}

fn fetch_last_error() -> String {
    let len = unsafe { vmm_last_error_len() } as usize;
    if len == 0 {
        return "unknown host error".to_string();
    }
    let mut buf = vec![0u8; len];
    unsafe { vmm_last_error_read(buf.as_mut_ptr() as u32, len as u32) };
    String::from_utf8_lossy(&buf).into_owned()
}

fn check_io(rc: i32) -> io::Result<u32> {
    if rc >= 0 {
        Ok(rc as u32)
    } else if rc == ERR_WOULD_BLOCK {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    } else if rc == ERR_INTERRUPTED {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
        Err(io::Error::other(fetch_last_error()))
    }
}

fn check_io_handle(rc: i64) -> io::Result<Handle> {
    if rc >= 0 {
        Ok(rc as Handle)
    } else if rc as i32 == ERR_WOULD_BLOCK {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    } else if rc as i32 == ERR_INTERRUPTED {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    } else {
        Err(io::Error::other(fetch_last_error()))
    }
}

fn check_io_unit(rc: i32) -> io::Result<()> {
    check_io(rc).map(|_| ())
}

#[derive(Debug)]
pub struct WasmTap {
    handle: Handle,
}

impl Drop for WasmTap {
    fn drop(&mut self) {
        unsafe { tap_close(self.handle) };
    }
}

impl Tap for WasmTap {
    fn detected_offload(&self) -> NetFeature {
        NetFeature::from_bits_retain(unsafe { tap_detected_offload(self.handle) })
    }

    fn enable_offload(&mut self, feature: NetFeature) -> io::Result<()> {
        check_io_unit(unsafe { tap_enable_offload(self.handle, feature.bits()) })
    }

    fn register(&self, token: Token, interests: Interest) -> io::Result<()> {
        check_io_unit(unsafe { tap_register(self.handle, token.0, interests.bits() as u32) })
    }

    fn deregister(&self) {
        unsafe { tap_deregister(self.handle) };
    }

    fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let total_len: usize = bufs.iter().map(|b| b.len()).sum();
        let mut data = vec![0u8; total_len];
        let n = check_io(unsafe {
            tap_read(self.handle, data.as_mut_ptr() as u32, total_len as u32)
        })? as usize;
        let mut offset = 0;
        for buf in bufs.iter_mut() {
            let rest = n.saturating_sub(offset);
            if rest == 0 {
                break;
            }
            let copy_len = buf.len().min(rest);
            buf[..copy_len].copy_from_slice(&data[offset..offset + copy_len]);
            offset += copy_len;
        }
        Ok(offset)
    }

    fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let total_len: usize = bufs.iter().map(|b| b.len()).sum();
        let mut data = Vec::with_capacity(total_len);
        for buf in bufs {
            data.extend_from_slice(buf);
        }
        let n = check_io(unsafe {
            tap_write(self.handle, data.as_ptr() as u32, data.len() as u32)
        })? as usize;
        Ok(n)
    }
}

#[derive(Debug)]
pub struct WasmBlock {
    handle: Handle,
    size: u64,
}

impl Drop for WasmBlock {
    fn drop(&mut self) {
        unsafe { blk_close(self.handle) };
    }
}

impl BlockBackend for WasmBlock {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        check_io_unit(unsafe {
            blk_read_at(
                self.handle,
                offset,
                dst.as_mut_ptr() as u32,
                dst.len() as u32,
            )
        })
    }

    fn write_at(&self, offset: u64, src: &[u8]) -> io::Result<()> {
        check_io_unit(unsafe {
            blk_write_at(self.handle, offset, src.as_ptr() as u32, src.len() as u32)
        })
    }

    fn flush(&self) -> io::Result<()> {
        check_io_unit(unsafe { blk_flush(self.handle) })
    }
}

#[derive(Debug)]
pub struct WasmSerialConsole {
    handle: Handle,
}

impl Drop for WasmSerialConsole {
    fn drop(&mut self) {
        unsafe { serial_close(self.handle) };
    }
}

impl SerialConsole for WasmSerialConsole {
    fn write_byte(&self, byte: u8) -> io::Result<()> {
        check_io_unit(unsafe { serial_write_byte(self.handle, byte as u32) })
    }

    fn read_input(&self, data: &mut VecDeque<u8>) -> io::Result<Option<usize>> {
        let mut buf = [0u8; 256];
        let rc = unsafe {
            serial_read_input(self.handle, buf.as_mut_ptr() as u32, buf.len() as u32)
        };
        if rc == ERR_EOF {
            return Ok(None);
        }
        let n = check_io(rc)? as usize;
        data.extend(&buf[..n]);
        Ok(Some(n))
    }

    fn shutdown(&self) -> io::Result<()> {
        check_io_unit(unsafe { serial_shutdown(self.handle) })
    }
}

#[derive(Debug, Default)]
pub struct WasmIoHost;

impl WasmIoHost {
    pub fn new() -> Self {
        Self
    }
}

impl GuestMemAccess for WasmIoHost {
    fn read_bytes(&self, gpa: u64, dst: &mut [u8]) -> io::Result<()> {
        check_io_unit(unsafe {
            io_guest_mem_read(gpa, dst.as_mut_ptr() as u32, dst.len() as u32)
        })
    }

    fn write_bytes(&self, gpa: u64, src: &[u8]) -> io::Result<()> {
        check_io_unit(unsafe {
            io_guest_mem_write(gpa, src.as_ptr() as u32, src.len() as u32)
        })
    }
}

impl IoHost for WasmIoHost {
    fn create_tap(&self, if_name: Option<&str>) -> io::Result<Box<dyn Tap>> {
        let (has_name, ptr, len) = match if_name {
            Some(name) => (1u32, name.as_ptr() as u32, name.len() as u32),
            None => (0u32, 0u32, 0u32),
        };
        let handle = check_io_handle(unsafe { tap_open(has_name, ptr, len) })?;
        Ok(Box::new(WasmTap { handle }))
    }

    fn open_block(&self, path: &Path, read_only: bool) -> io::Result<Box<dyn BlockBackend>> {
        let path_str = path.to_string_lossy();
        let mut size = 0u64;
        let handle = check_io_handle(unsafe {
            blk_open(
                path_str.as_ptr() as u32,
                path_str.len() as u32,
                u32::from(read_only),
                &mut size as *mut u64 as u32,
            )
        })?;
        Ok(Box::new(WasmBlock { handle, size }))
    }

    fn create_serial_console(&self) -> io::Result<Box<dyn SerialConsole>> {
        let handle = check_io_handle(unsafe { serial_open() })?;
        Ok(Box::new(WasmSerialConsole { handle }))
    }

    fn io_register_vm_config(
        &self,
        boot_cfg: &IoBootConfig,
        virtio_devs: &[VirtioDeviceSpec],
    ) -> io::Result<()> {
        let mut raw_boot = RawIoBootConfig {
            num_cpus: boot_cfg.num_cpus,
            exec_type: match boot_cfg.exec_kind {
                Some(ExecKind::Linux) => EXEC_TYPE_LINUX,
                Some(ExecKind::Pvh) => EXEC_TYPE_PVH,
                None => EXEC_TYPE_NONE,
            },
            mem_size: boot_cfg.mem_size as u64,
            ..Default::default()
        };
        if let Some(ref kp) = boot_cfg.kernel_path {
            let s = kp.to_string_lossy();
            let b = s.as_bytes();
            let len = b.len().min(raw_boot.kernel_path.len());
            raw_boot.kernel_path[..len].copy_from_slice(&b[..len]);
            raw_boot.kernel_path_len = len as u32;
        }
        if let Some(ref ip) = boot_cfg.initramfs_path {
            let s = ip.to_string_lossy();
            let b = s.as_bytes();
            let len = b.len().min(raw_boot.initramfs_path.len());
            raw_boot.initramfs_path[..len].copy_from_slice(&b[..len]);
            raw_boot.initramfs_path_len = len as u32;
        }
        if let Some(ref cmd) = boot_cfg.cmd_line {
            let b = cmd.as_bytes();
            let len = b.len().min(raw_boot.cmd_line.len());
            raw_boot.cmd_line[..len].copy_from_slice(&b[..len]);
            raw_boot.cmd_line_len = len as u32;
        }

        let mut raw_devs = Vec::with_capacity(virtio_devs.len());
        for spec in virtio_devs {
            let mut raw = ShmVirtioDeviceSpec {
                dev: spec.dev,
                device_features: spec.device_features,
                device_id: spec.device_id,
                num_queues: spec.num_queues,
                ..Default::default()
            };
            let nb = spec.name.as_bytes();
            let nlen = nb.len().min(raw.name.len());
            raw.name[..nlen].copy_from_slice(&nb[..nlen]);
            raw.name_len = nlen as u16;

            let clen = spec.config_bytes.len().min(raw.config_bytes.len());
            raw.config_bytes[..clen].copy_from_slice(&spec.config_bytes[..clen]);
            raw.config_len = clen as u16;
            raw_devs.push(raw);
        }

        check_io_unit(unsafe {
            io_register_vm_config(
                &raw_boot as *const RawIoBootConfig as u32,
                raw_devs.as_ptr() as u32,
                raw_devs.len() as u32,
            )
        })
    }

    fn io_next_event(&self) -> io::Result<IoBridgeEvent> {
        let mut raw = RawIoBridgeEvent::default();
        check_io_unit(unsafe { io_next_event(&mut raw as *mut RawIoBridgeEvent as u32) })?;
        match raw.kind {
            IO_BRIDGE_EVENT_VIRTIO_START => {
                let nq = (raw.num_queues as usize).min(raw.queues.len());
                let queues = raw.queues[..nq]
                    .iter()
                    .copied()
                    .map(VirtioQueueConfig::from)
                    .collect();
                Ok(IoBridgeEvent::VirtioStart {
                    dev: raw.dev,
                    driver_features: raw.driver_features,
                    queues,
                })
            }
            IO_BRIDGE_EVENT_VIRTIO_NOTIFY => Ok(IoBridgeEvent::VirtioNotify {
                dev: raw.dev,
                queue_index: raw.queue_index,
            }),
            IO_BRIDGE_EVENT_VIRTIO_RESET => Ok(IoBridgeEvent::VirtioReset { dev: raw.dev }),
            IO_BRIDGE_EVENT_POLL => Ok(IoBridgeEvent::Poll(PollEvent {
                token: Token(raw.token),
                is_readable: raw.is_readable != 0,
                is_writable: raw.is_writable != 0,
            })),
            IO_BRIDGE_EVENT_SERIAL_INPUT => Ok(IoBridgeEvent::SerialInput),
            IO_BRIDGE_EVENT_SERIAL_TX => {
                let len = (raw.tx_len as usize).min(raw.tx_bytes.len());
                Ok(IoBridgeEvent::SerialTx(raw.tx_bytes[..len].to_vec()))
            }
            IO_BRIDGE_EVENT_SHUTDOWN => Ok(IoBridgeEvent::Shutdown),
            other => Err(io::Error::other(format!("unknown IoBridgeEvent kind {other}"))),
        }
    }

    fn io_request_shutdown(&self) -> io::Result<()> {
        check_io_unit(unsafe { io_request_shutdown() })
    }

    fn io_virtio_irq(&self, dev: Handle, kind: VirtioIrqKind) -> io::Result<()> {
        let (irq_kind, q_idx) = match kind {
            VirtioIrqKind::Config => (IRQ_KIND_CONFIG, 0),
            VirtioIrqKind::Queue(idx) => (IRQ_KIND_QUEUE, idx as u32),
        };
        check_io_unit(unsafe { io_virtio_irq(dev, irq_kind, q_idx) })
    }

    fn io_serial_push_rx(&self, data: &[u8]) -> io::Result<()> {
        check_io_unit(unsafe { io_serial_push_rx(data.as_ptr() as u32, data.len() as u32) })
    }
}

#[used]
static mut DATA_PAD: [u64; 16] = [1; 16];

thread_local! {
    static TLS_PAD: std::cell::Cell<[u64; 16]> = const { std::cell::Cell::new([1; 16]) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vmm_memcpy(mut dst: *mut u8, mut src: *const u8, mut n: usize) {
    if n == usize::MAX {
        TLS_PAD.with(|c| c.set(unsafe { DATA_PAD }));
    }
    if dst as usize == src as usize || n == 0 {
        return;
    }
    if (dst as usize) < (src as usize) || (dst as usize) >= (src as usize).wrapping_add(n) {
        while core::hint::black_box(n) >= 8 {
            unsafe {
                let v = core::ptr::read_unaligned(src as *const u64);
                core::ptr::write_unaligned(dst as *mut u64, v);
                src = src.add(8);
                dst = dst.add(8);
            }
            n -= 8;
        }
        while core::hint::black_box(n) > 0 {
            unsafe {
                *dst = *src;
                src = src.add(1);
                dst = dst.add(1);
            }
            n -= 1;
        }
    } else {
        unsafe {
            src = src.add(n);
            dst = dst.add(n);
        }
        while core::hint::black_box(n) >= 8 {
            n -= 8;
            unsafe {
                src = src.sub(8);
                dst = dst.sub(8);
                let v = core::ptr::read_unaligned(src as *const u64);
                core::ptr::write_unaligned(dst as *mut u64, v);
            }
        }
        while core::hint::black_box(n) > 0 {
            n -= 1;
            unsafe {
                src = src.sub(1);
                dst = dst.sub(1);
                *dst = *src;
            }
        }
    }
}
